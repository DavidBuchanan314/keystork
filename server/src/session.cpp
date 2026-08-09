#include "session.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <grp.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

// From vendor/binder_ndk/include_platform: the NDK ships neither of these.
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <aidl/android/hardware/security/keymint/TagType.h>
#include <aidl/android/system/keystore2/CreateOperationResponse.h>
#include <aidl/android/system/keystore2/Domain.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/KeyDescriptor.h>
#include <aidl/android/system/keystore2/KeyEntryResponse.h>

#include "framing.h"
#include "keystork.pb.h"
#include "log.h"
#include "status.h"

namespace keystork {
namespace {

namespace pb = ::keystork::v1;

using ::aidl::android::hardware::security::keymint::KeyParameter;
using ::aidl::android::hardware::security::keymint::KeyParameterValue;
using ::aidl::android::hardware::security::keymint::SecurityLevel;
using ::aidl::android::hardware::security::keymint::Tag;
using ::aidl::android::hardware::security::keymint::TagType;
using ::aidl::android::system::keystore2::CreateOperationResponse;
using ::aidl::android::system::keystore2::Domain;
using ::aidl::android::system::keystore2::IKeystoreOperation;
using ::aidl::android::system::keystore2::IKeystoreSecurityLevel;
using ::aidl::android::system::keystore2::IKeystoreService;
using ::aidl::android::system::keystore2::KeyDescriptor;
using ::aidl::android::system::keystore2::KeyEntryResponse;

constexpr char kKeystoreServiceName[] = "android.system.keystore2.IKeystoreService/default";

// The package manager's own record of which UID each package runs as. 0640
// system:package_info, so it must be read before the privilege drop -- an app
// UID cannot open it.
constexpr char kPackagesList[] = "/data/system/packages.list";

// Android offsets each secondary user's UIDs by this much (AID_USER_OFFSET).
constexpr long kUserOffset = 100000;
constexpr uint32_t kProtocolVersion = pb::PROTOCOL_VERSION_1;

// Resolves a package name to the UID it runs as. Every line of packages.list is
// space-separated with the name first and its user-0 UID second; nothing after
// that matters here. Parsed with stdio rather than iostreams to keep the
// binary's static libc++ from growing a locale machinery it uses nowhere else.
bool ResolvePackage(const std::string& name, uint32_t user, uid_t* uid, std::string* error,
                    int* error_errno) {
  FILE* file = ::fopen(kPackagesList, "re");
  if (file == nullptr) {
    *error_errno = errno;
    *error = std::string("could not read ") + kPackagesList + ": " + ::strerror(errno);
    return false;
  }

  char* line = nullptr;
  size_t capacity = 0;
  bool found = false;
  while (::getline(&line, &capacity, file) > 0) {
    const char* separator = ::strchr(line, ' ');
    if (separator == nullptr) continue;
    if (static_cast<size_t>(separator - line) != name.size()) continue;
    if (::memcmp(line, name.data(), name.size()) != 0) continue;

    const long app_uid = ::strtol(separator + 1, nullptr, 10);
    if (app_uid <= 0) continue;
    // packages.list records the user-0 UID; strip any user already in it before
    // applying the requested one.
    *uid = static_cast<uid_t>(app_uid % kUserOffset + static_cast<long>(user) * kUserOffset);
    found = true;
    break;
  }
  ::free(line);
  ::fclose(file);

  if (!found) {
    *error_errno = 0;
    *error = "no package named '" + name + "' in " + kPackagesList;
  }
  return found;
}

// Permanently drops to `uid`, used as both UID and primary GID -- real,
// effective and saved all at once, so there is no way back to root. Must run
// before any Binder call: the kernel captures the caller's credentials per
// transaction, and keystore2 partitions keys by exactly those credentials.
bool DropPrivileges(uid_t uid, std::string* error, int* error_errno) {
  const auto gid = static_cast<gid_t>(uid);

  auto fail = [&](const char* what) {
    *error_errno = errno;
    *error = std::string(what) + " failed: " + ::strerror(errno);
    return false;
  };

  // Supplementary groups are inherited from root and would otherwise survive
  // the drop, leaving the session with more access than the UID it claims.
  if (::setgroups(1, &gid) != 0) return fail("setgroups");
  if (::setresgid(gid, gid, gid) != 0) return fail("setresgid");
  if (::setresuid(uid, uid, uid) != 0) return fail("setresuid");

  // setresuid reports success if it changed *some* of the three IDs, so the
  // drop is verified rather than assumed.
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  if (::getresuid(&ruid, &euid, &suid) != 0) return fail("getresuid");
  if (::getresgid(&rgid, &egid, &sgid) != 0) return fail("getresgid");
  if (ruid != uid || euid != uid || suid != uid || rgid != gid || egid != gid || sgid != gid) {
    *error_errno = 0;
    *error = "privilege drop did not take effect";
    return false;
  }
  return true;
}

// Opens this child's own Binder connection. Everything here happens after the
// UID drop: fork() clones only the calling thread, so any threadpool started in
// the supervisor would not exist here anyway.
std::shared_ptr<IKeystoreService> ConnectKeystore(std::string* error) {
  ABinderProcess_startThreadPool();

  // checkService returns immediately with null if keystore2 is not registered;
  // waitForService blocks until it is. Trying the cheap one first means the
  // normal case (a booted device) never waits, while a device still bringing
  // keystore2 up still works.
  ::ndk::SpAIBinder binder(AServiceManager_checkService(kKeystoreServiceName));
  if (binder.get() == nullptr) {
    KS_LOGI("keystore2 not registered yet, waiting for it");
    binder = ::ndk::SpAIBinder(AServiceManager_waitForService(kKeystoreServiceName));
  }
  if (binder.get() == nullptr) {
    *error = std::string("could not reach ") + kKeystoreServiceName;
    return nullptr;
  }

  auto service = IKeystoreService::fromBinder(binder);
  if (service == nullptr) {
    *error = std::string(kKeystoreServiceName) + " is not an IKeystoreService";
    return nullptr;
  }
  return service;
}

void ToWire(const KeyDescriptor& in, pb::KeyDescriptor* out) {
  out->set_domain(static_cast<int32_t>(in.domain));
  out->set_nspace(in.nspace);
  if (in.alias.has_value()) out->set_alias(*in.alias);
  if (in.blob.has_value()) out->set_blob(in.blob->data(), in.blob->size());
}

KeyDescriptor FromWire(const pb::KeyDescriptor& in) {
  KeyDescriptor out;
  out.domain = static_cast<Domain>(in.domain());
  out.nspace = in.nspace();
  if (in.has_alias()) out.alias = in.alias();
  if (in.has_blob()) {
    out.blob = std::vector<uint8_t>(in.blob().begin(), in.blob().end());
  }
  return out;
}

// A KeyMint Tag carries its TagType in its top four bits, which is what selects
// the arm of the KeyParameterValue union.
int32_t TagTypeOf(int32_t tag) {
  return static_cast<int32_t>(static_cast<uint32_t>(tag) & 0xf0000000u);
}

// The one place this daemon knows what a tag *means*, and only because it has
// to: KeyParameterValue gives every KeyMint enum its own arm, so a tag of type
// ENUM or ENUM_REP cannot be built from the tag type alone. Everything else is
// derived structurally in FromWire below. A tag missing from this table still
// reaches keystore2 -- as the generic `integer` arm, which keystore2 will
// refuse if it was wrong -- rather than being rejected here.
bool SetEnumValue(int32_t tag, int32_t value, KeyParameterValue* out) {
  namespace km = ::aidl::android::hardware::security::keymint;
  switch (static_cast<Tag>(tag)) {
    case Tag::ALGORITHM:
      out->set<KeyParameterValue::algorithm>(static_cast<km::Algorithm>(value));
      return true;
    case Tag::BLOCK_MODE:
      out->set<KeyParameterValue::blockMode>(static_cast<km::BlockMode>(value));
      return true;
    case Tag::PADDING:
      out->set<KeyParameterValue::paddingMode>(static_cast<km::PaddingMode>(value));
      return true;
    case Tag::DIGEST:
    case Tag::RSA_OAEP_MGF_DIGEST:
      out->set<KeyParameterValue::digest>(static_cast<km::Digest>(value));
      return true;
    case Tag::EC_CURVE:
      out->set<KeyParameterValue::ecCurve>(static_cast<km::EcCurve>(value));
      return true;
    case Tag::ORIGIN:
      out->set<KeyParameterValue::origin>(static_cast<km::KeyOrigin>(value));
      return true;
    case Tag::PURPOSE:
      out->set<KeyParameterValue::keyPurpose>(static_cast<km::KeyPurpose>(value));
      return true;
    case Tag::USER_AUTH_TYPE:
      out->set<KeyParameterValue::hardwareAuthenticatorType>(
          static_cast<km::HardwareAuthenticatorType>(value));
      return true;
    case Tag::HARDWARE_TYPE:
      out->set<KeyParameterValue::securityLevel>(static_cast<km::SecurityLevel>(value));
      return true;
    case Tag::ML_DSA_VARIANT:
      out->set<KeyParameterValue::mlDsaVariant>(static_cast<km::MlDsaVariant>(value));
      return true;
    default:
      return false;
  }
}

KeyParameter FromWire(const pb::KeyParameter& in) {
  KeyParameter out;
  out.tag = static_cast<Tag>(in.tag());

  switch (static_cast<TagType>(TagTypeOf(in.tag()))) {
    case TagType::BOOL:
      // KeyMint reads a BOOL tag's presence, not its value.
      out.value.set<KeyParameterValue::boolValue>(in.bool_value());
      break;
    case TagType::ENUM:
    case TagType::ENUM_REP:
      if (!SetEnumValue(in.tag(), static_cast<int32_t>(in.integer()), &out.value)) {
        out.value.set<KeyParameterValue::integer>(static_cast<int32_t>(in.integer()));
      }
      break;
    case TagType::UINT:
    case TagType::UINT_REP:
      out.value.set<KeyParameterValue::integer>(static_cast<int32_t>(in.integer()));
      break;
    case TagType::ULONG:
    case TagType::ULONG_REP:
      out.value.set<KeyParameterValue::longInteger>(static_cast<int64_t>(in.long_integer()));
      break;
    case TagType::DATE:
      out.value.set<KeyParameterValue::dateTime>(static_cast<int64_t>(in.long_integer()));
      break;
    case TagType::BYTES:
    case TagType::BIGNUM:
      out.value.set<KeyParameterValue::blob>(
          std::vector<uint8_t>(in.blob().begin(), in.blob().end()));
      break;
    case TagType::INVALID:
      break;
  }
  return out;
}

void ToWire(const KeyParameter& in, pb::KeyParameter* out) {
  out->set_tag(static_cast<int32_t>(in.tag));

  switch (in.value.getTag()) {
    case KeyParameterValue::boolValue:
      out->set_bool_value(in.value.get<KeyParameterValue::boolValue>());
      break;
    case KeyParameterValue::integer:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::integer>()));
      break;
    case KeyParameterValue::algorithm:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::algorithm>()));
      break;
    case KeyParameterValue::blockMode:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::blockMode>()));
      break;
    case KeyParameterValue::paddingMode:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::paddingMode>()));
      break;
    case KeyParameterValue::digest:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::digest>()));
      break;
    case KeyParameterValue::ecCurve:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::ecCurve>()));
      break;
    case KeyParameterValue::origin:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::origin>()));
      break;
    case KeyParameterValue::keyPurpose:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::keyPurpose>()));
      break;
    case KeyParameterValue::hardwareAuthenticatorType:
      out->set_integer(
          static_cast<uint32_t>(in.value.get<KeyParameterValue::hardwareAuthenticatorType>()));
      break;
    case KeyParameterValue::securityLevel:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::securityLevel>()));
      break;
    case KeyParameterValue::mlDsaVariant:
      out->set_integer(static_cast<uint32_t>(in.value.get<KeyParameterValue::mlDsaVariant>()));
      break;
    case KeyParameterValue::longInteger:
      out->set_long_integer(
          static_cast<uint64_t>(in.value.get<KeyParameterValue::longInteger>()));
      break;
    case KeyParameterValue::dateTime:
      out->set_long_integer(static_cast<uint64_t>(in.value.get<KeyParameterValue::dateTime>()));
      break;
    case KeyParameterValue::blob: {
      const auto& blob = in.value.get<KeyParameterValue::blob>();
      out->set_blob(blob.data(), blob.size());
      break;
    }
    case KeyParameterValue::invalid:
      // No arm set: the tag travels alone, which is what KeyMint sent.
      break;
  }
}

// One ListRequest is exactly one keystore2 call. The client owns the capability
// table that decides between the two, and owns the pagination loop for the
// batched form; the server just relays.
void HandleList(IKeystoreService* service, const pb::ListRequest& request, pb::Response* response) {
  // The domain is passed through unvalidated, on purpose: this is a research
  // tool, and rejecting values keystore2 might accept would defeat the point.
  const auto domain = static_cast<Domain>(request.domain());

  std::vector<KeyDescriptor> entries;
  ::ndk::ScopedAStatus status;

  if (request.batched()) {
    std::optional<std::string> starting_past_alias;
    if (request.has_starting_past_alias()) starting_past_alias = request.starting_past_alias();
    status = service->listEntriesBatched(domain, request.nspace(), starting_past_alias, &entries);
  } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    // Deprecated in favour of listEntriesBatched, but it is the only listing
    // call on interface V1 and V2, so the client can still ask for it.
    status = service->listEntries(domain, request.nspace(), &entries);
#pragma clang diagnostic pop
  }

  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }

  auto* list = response->mutable_list();
  for (const auto& entry : entries) ToWire(entry, list->add_entries());
}

// getKeyEntry also hands back an IKeystoreSecurityLevel; that handle stays here
// (§3.6) and only the metadata goes on the wire.
void HandleGetKeyEntry(IKeystoreService* service, const pb::GetKeyEntryRequest& request,
                       pb::Response* response) {
  KeyEntryResponse entry;
  const auto status = service->getKeyEntry(FromWire(request.key()), &entry);
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }

  auto* metadata = response->mutable_get_key_entry()->mutable_metadata();
  ToWire(entry.metadata.key, metadata->mutable_key());
  metadata->set_key_security_level(static_cast<int32_t>(entry.metadata.keySecurityLevel));
  metadata->set_modification_time_ms(entry.metadata.modificationTimeMs);

  for (const auto& authorization : entry.metadata.authorizations) {
    auto* out = metadata->add_authorizations();
    out->set_security_level(static_cast<int32_t>(authorization.securityLevel));
    ToWire(authorization.keyParameter, out->mutable_parameter());
  }

  if (entry.metadata.certificate.has_value()) {
    metadata->set_certificate(entry.metadata.certificate->data(),
                              entry.metadata.certificate->size());
  }
  if (entry.metadata.certificateChain.has_value()) {
    metadata->set_certificate_chain(entry.metadata.certificateChain->data(),
                                    entry.metadata.certificateChain->size());
  }
}

// Everything a session carries between round-trips. The operation handle is the
// only real state: keystore2 owns the operation, this is the live Binder proxy
// to it, and there is at most one because requests are synchronous. If the
// client vanishes the child dies with it, keystore2 sees the Binder death, and
// the operation is reclaimed -- there is nothing to clean up here.
struct SessionState {
  std::shared_ptr<IKeystoreService> service;
  std::shared_ptr<IKeystoreOperation> operation;
  std::map<int32_t, std::shared_ptr<IKeystoreSecurityLevel>> security_levels;
};

std::vector<uint8_t> Bytes(const std::string& in) {
  return std::vector<uint8_t>(in.begin(), in.end());
}

// getSecurityLevel is a round-trip returning a sub-interface. The handle is
// never exposed on the wire (§3.6), and a session uses one or two levels at
// most, so it is fetched once and kept.
std::shared_ptr<IKeystoreSecurityLevel> SecurityLevelFor(SessionState* session, int32_t level,
                                                         ::ndk::ScopedAStatus* status) {
  const auto cached = session->security_levels.find(level);
  if (cached != session->security_levels.end()) return cached->second;

  std::shared_ptr<IKeystoreSecurityLevel> handle;
  *status = session->service->getSecurityLevel(static_cast<SecurityLevel>(level), &handle);
  if (!status->isOk() || handle == nullptr) return nullptr;

  session->security_levels[level] = handle;
  return handle;
}

// createOperation, shared by run_operation and op_begin. On failure it fills
// `response` with the error and returns null; `begun` is a local the caller
// copies into the response only once the whole call has succeeded, so a later
// failure can replace the response body wholesale.
std::shared_ptr<IKeystoreOperation> BeginOperation(SessionState* session,
                                                   const pb::OperationStart& start,
                                                   pb::OperationBegun* begun,
                                                   pb::Response* response) {
  ::ndk::ScopedAStatus status;
  auto level = SecurityLevelFor(session, start.security_level(), &status);
  if (level == nullptr) {
    if (!status.isOk()) {
      FillError(status, response->mutable_error());
    } else {
      FillProtocolError("keystore2 returned no security level for " +
                            std::to_string(start.security_level()),
                        response->mutable_error());
    }
    return nullptr;
  }

  std::vector<KeyParameter> parameters;
  parameters.reserve(static_cast<size_t>(start.parameters_size()));
  for (const auto& parameter : start.parameters()) parameters.push_back(FromWire(parameter));

  CreateOperationResponse created;
  status = level->createOperation(FromWire(start.key()), parameters, start.forced(), &created);
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return nullptr;
  }
  if (created.iOperation == nullptr) {
    FillProtocolError("keystore2 accepted the request but returned no operation",
                      response->mutable_error());
    return nullptr;
  }

  if (created.parameters.has_value()) {
    for (const auto& parameter : created.parameters->keyParameter) {
      ToWire(parameter, begun->add_parameters());
    }
  }
  if (created.operationChallenge.has_value()) {
    begun->set_operation_challenge(created.operationChallenge->challenge);
  }
  if (created.upgradedBlob.has_value()) {
    begun->set_upgraded_blob(created.upgradedBlob->data(), created.upgradedBlob->size());
  }
  return created.iOperation;
}

// createOperation + updateAad + update + finish, in one round-trip. The whole
// input is fed through update() and finish() takes only the signature, which is
// the conventional shape and keeps one huge parcel off the Binder transaction
// even when the client sends everything at once.
void HandleRunOperation(SessionState* session, const pb::RunOperationRequest& request,
                        pb::Response* response) {
  pb::OperationBegun begun;
  auto operation = BeginOperation(session, request.start(), &begun, response);
  if (operation == nullptr) return;

  // Anything that fails before finish() leaves a live operation behind, and
  // keystore2 has a limited number of slots, so it is given back immediately
  // rather than at session teardown.
  const auto fail = [&](const ::ndk::ScopedAStatus& status) {
    (void)operation->abort();
    FillError(status, response->mutable_error());
  };

  std::string output;
  ::ndk::ScopedAStatus status;

  if (request.has_aad()) {
    status = operation->updateAad(Bytes(request.aad()));
    if (!status.isOk()) return fail(status);
  }

  if (request.has_input()) {
    std::optional<std::vector<uint8_t>> chunk;
    status = operation->update(Bytes(request.input()), &chunk);
    if (!status.isOk()) return fail(status);
    if (chunk.has_value()) output.append(chunk->begin(), chunk->end());
  }

  std::optional<std::vector<uint8_t>> signature;
  if (request.has_signature()) signature = Bytes(request.signature());

  std::optional<std::vector<uint8_t>> final_output;
  status = operation->finish(std::nullopt, signature, &final_output);
  if (!status.isOk()) {
    // finish() consumes the operation whether or not it succeeded; aborting now
    // would just produce a second, more confusing error.
    FillError(status, response->mutable_error());
    return;
  }
  if (final_output.has_value()) output.append(final_output->begin(), final_output->end());

  auto* result = response->mutable_run_operation();
  *result->mutable_begun() = begun;
  result->set_output(output);
}

void HandleOpBegin(SessionState* session, const pb::OpBeginRequest& request,
                   pb::Response* response) {
  if (session->operation != nullptr) {
    FillProtocolError("an operation is already open on this session; finish or abort it first",
                      response->mutable_error());
    return;
  }

  pb::OperationBegun begun;
  auto operation = BeginOperation(session, request.start(), &begun, response);
  if (operation == nullptr) return;

  session->operation = operation;
  *response->mutable_op_begin()->mutable_begun() = begun;
}

// The session's operation is implicit, so every op_* call but begin has to say
// so when there is nothing open.
IKeystoreOperation* LiveOperation(SessionState* session, pb::Response* response) {
  if (session->operation == nullptr) {
    FillProtocolError("no operation is open on this session", response->mutable_error());
    return nullptr;
  }
  return session->operation.get();
}

void HandleOpUpdateAad(SessionState* session, const pb::OpUpdateAadRequest& request,
                       pb::Response* response) {
  auto* operation = LiveOperation(session, response);
  if (operation == nullptr) return;

  const auto status = operation->updateAad(Bytes(request.aad()));
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }
  response->mutable_op_update_aad();
}

void HandleOpUpdate(SessionState* session, const pb::OpUpdateRequest& request,
                    pb::Response* response) {
  auto* operation = LiveOperation(session, response);
  if (operation == nullptr) return;

  std::optional<std::vector<uint8_t>> chunk;
  const auto status = operation->update(Bytes(request.input()), &chunk);
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }

  auto* result = response->mutable_op_update();
  // KeyMint is free to buffer, so no output on an update is ordinary.
  if (chunk.has_value()) result->set_output(chunk->data(), chunk->size());
}

void HandleOpFinish(SessionState* session, const pb::OpFinishRequest& request,
                    pb::Response* response) {
  auto* operation = LiveOperation(session, response);
  if (operation == nullptr) return;

  std::optional<std::vector<uint8_t>> input;
  if (request.has_input()) input = Bytes(request.input());
  std::optional<std::vector<uint8_t>> signature;
  if (request.has_signature()) signature = Bytes(request.signature());

  std::optional<std::vector<uint8_t>> output;
  const auto status = operation->finish(input, signature, &output);

  // finish() ends the operation either way, so the session lets go of it before
  // reporting anything.
  session->operation.reset();

  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }
  auto* result = response->mutable_op_finish();
  if (output.has_value()) result->set_output(output->data(), output->size());
}

void HandleOpAbort(SessionState* session, pb::Response* response) {
  auto* operation = LiveOperation(session, response);
  if (operation == nullptr) return;

  const auto status = operation->abort();
  session->operation.reset();

  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }
  response->mutable_op_abort();
}

bool SendFrame(int fd, const google::protobuf::MessageLite& message) {
  std::string encoded;
  if (!message.SerializeToString(&encoded)) {
    KS_LOGE("failed to serialize response");
    return false;
  }
  return WriteFrame(fd, encoded);
}

// Establishes a keystore session: drops privileges and connects to keystore2.
// Every failure is reported in the ack rather than by dropping the connection,
// so the client always learns why a session did not start.
std::shared_ptr<IKeystoreService> StartKeystoreSession(int fd, const pb::StartKeystoreSession& start,
                                                       pb::OpenAck* ack) {
  std::string error;
  int error_errno = 0;

  uid_t uid = 0;
  switch (start.identity_case()) {
    case pb::StartKeystoreSession::kUid:
      uid = static_cast<uid_t>(start.uid());
      break;
    case pb::StartKeystoreSession::kPackage:
      // Must happen here, while still root: packages.list is unreadable to the
      // UID this session is about to become.
      if (!ResolvePackage(start.package().name(), start.package().user(), &uid, &error,
                          &error_errno)) {
        KS_LOGE("%s", error.c_str());
        FillIdentityError(error, error_errno, ack->mutable_error());
        SendFrame(fd, *ack);
        return nullptr;
      }
      KS_LOGI("package '%s' user %u is uid=%u", start.package().name().c_str(),
              start.package().user(), uid);
      break;
    case pb::StartKeystoreSession::IDENTITY_NOT_SET:
      FillProtocolError("keystore session names neither a uid nor a package",
                        ack->mutable_error());
      SendFrame(fd, *ack);
      return nullptr;
  }
  if (!DropPrivileges(uid, &error, &error_errno)) {
    KS_LOGE("could not become uid=%u: %s", uid, error.c_str());
    FillIdentityError(error, error_errno, ack->mutable_error());
    SendFrame(fd, *ack);
    return nullptr;
  }
  KS_LOGI("session running as uid=%u", uid);

  auto service = ConnectKeystore(&error);
  if (service == nullptr) {
    KS_LOGE("%s", error.c_str());
    FillIdentityError(error, 0, ack->mutable_error());
    SendFrame(fd, *ack);
    return nullptr;
  }

  // The client drives its capability table off this number, so an interface
  // version we cannot read is a failed session rather than a guess.
  int32_t interface_version = 0;
  const auto status = service->getInterfaceVersion(&interface_version);
  if (!status.isOk()) {
    const char* message = status.getMessage();
    FillIdentityError(std::string("getInterfaceVersion failed: ") + (message ? message : ""), 0,
                      ack->mutable_error());
    SendFrame(fd, *ack);
    return nullptr;
  }

  ack->mutable_keystore()->set_keystore_interface_version(interface_version);
  ack->mutable_keystore()->set_uid(uid);
  KS_LOGI("keystore2 interface version %d", interface_version);
  if (!SendFrame(fd, *ack)) return nullptr;
  return service;
}

// Acknowledges first, then signals: the client has to learn the kill was
// accepted, and the supervisor's SIGTERM comes straight back to this child.
// Still root here -- the UID drop only happens for a keystore session.
bool KillServer(int fd, pid_t supervisor_pid, pb::OpenAck* ack) {
  ack->mutable_kill_server();
  if (!SendFrame(fd, *ack)) return false;

  KS_LOGI("kill_server requested, signalling supervisor %d", supervisor_pid);
  if (::kill(supervisor_pid, SIGTERM) != 0) {
    KS_LOGE("could not signal supervisor %d: %s", supervisor_pid, ::strerror(errno));
    return false;
  }
  return true;
}

}  // namespace

int RunConnection(int fd, pid_t supervisor_pid) {
  std::string encoded;
  if (ReadFrame(fd, &encoded) != FrameStatus::kOk) {
    // Nothing useful to say to a peer that never sent a readable Open.
    KS_LOGE("open read failed");
    return 1;
  }

  pb::OpenAck ack;
  ack.set_protocol_version(kProtocolVersion);

  pb::Open open;
  if (!open.ParseFromString(encoded)) {
    FillProtocolError("malformed open", ack.mutable_error());
    SendFrame(fd, ack);
    return 1;
  }
  if (open.protocol_version() != kProtocolVersion) {
    FillProtocolError("unsupported protocol version " +
                          std::to_string(open.protocol_version()) + ", this server speaks " +
                          std::to_string(kProtocolVersion),
                      ack.mutable_error());
    SendFrame(fd, ack);
    return 1;
  }

  if (open.command_case() == pb::Open::kKillServer) {
    return KillServer(fd, supervisor_pid, &ack) ? 0 : 1;
  }
  if (open.command_case() != pb::Open::kKeystore) {
    // Also what a newer client's unimplemented command looks like here: its
    // field number is unknown to this build, so no oneof arm is set.
    FillProtocolError("open names no command this server implements", ack.mutable_error());
    SendFrame(fd, ack);
    return 1;
  }

  SessionState session;
  session.service = StartKeystoreSession(fd, open.keystore(), &ack);
  if (session.service == nullptr) return 1;

  for (;;) {
    const FrameStatus frame_status = ReadFrame(fd, &encoded);
    if (frame_status == FrameStatus::kEof) return 0;
    if (frame_status != FrameStatus::kOk) {
      KS_LOGE("request read failed: %s", ToString(frame_status));
      return 1;
    }

    pb::Response response;
    pb::Request request;
    if (!request.ParseFromString(encoded)) {
      FillProtocolError("malformed request", response.mutable_error());
    } else {
      switch (request.body_case()) {
        case pb::Request::kList:
          HandleList(session.service.get(), request.list(), &response);
          break;
        case pb::Request::kGetKeyEntry:
          HandleGetKeyEntry(session.service.get(), request.get_key_entry(), &response);
          break;
        case pb::Request::kRunOperation:
          HandleRunOperation(&session, request.run_operation(), &response);
          break;
        case pb::Request::kOpBegin:
          HandleOpBegin(&session, request.op_begin(), &response);
          break;
        case pb::Request::kOpUpdateAad:
          HandleOpUpdateAad(&session, request.op_update_aad(), &response);
          break;
        case pb::Request::kOpUpdate:
          HandleOpUpdate(&session, request.op_update(), &response);
          break;
        case pb::Request::kOpFinish:
          HandleOpFinish(&session, request.op_finish(), &response);
          break;
        case pb::Request::kOpAbort:
          HandleOpAbort(&session, &response);
          break;
        case pb::Request::BODY_NOT_SET:
          // Also what a newer client's unimplemented RPC looks like here: its
          // field number is unknown to this build, so no oneof arm is set.
          FillProtocolError("request has no body this server implements", response.mutable_error());
          break;
      }
    }

    if (!SendFrame(fd, response)) {
      KS_LOGE("response write failed: %s", ::strerror(errno));
      return 1;
    }
  }
}

}  // namespace keystork
