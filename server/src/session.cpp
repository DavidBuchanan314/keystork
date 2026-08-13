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

#include <fcntl.h>
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
#include <aidl/android/system/keystore2/KeyMetadata.h>

#include "exec.h"
#include "framing.h"
#include "inject.h"
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
using ::aidl::android::system::keystore2::KeyMetadata;

constexpr char kKeystoreServiceName[] = "android.system.keystore2.IKeystoreService/default";

constexpr uint32_t kProtocolVersion = pb::PROTOCOL_VERSION_1;

// Largest read_file chunk. Comfortably inside the frame limit both sides agree
// on, with room for the rest of the message.
constexpr size_t kReadChunkBytes = 1024 * 1024;

// What root looked like before a session dropped, so it can be put back.
struct SavedIdentity {
  std::vector<gid_t> groups;
  bool held = false;
};

// Drops to `uid`, used as both UID and primary GID, keeping **0 as the saved
// ID** so the session can be ended and the connection returned to the top
// level. Must run before any Binder call: the kernel captures the caller's
// credentials per transaction, and keystore2 partitions keys by exactly those.
//
// A saved 0 does mean a bug inside a session could climb back to root rather
// than being confined to an app's UID. That is not a threat here: this daemon
// is unauthenticated and hands out `exec` as root to anyone who connects, so
// the escalation it would buy is one the protocol offers outright.
//
// What is still structural is the part that matters -- keys are UID
// partitioned, and the only way to act as a UID is to *be* it at transaction
// time. A session is one UID for its whole life; ending it is the only way
// back, and the next one starts from root again.
bool DropPrivileges(uid_t uid, SavedIdentity* saved, std::string* error, int* error_errno) {
  const auto gid = static_cast<gid_t>(uid);

  auto fail = [&](const char* what) {
    *error_errno = errno;
    *error = std::string(what) + " failed: " + ::strerror(errno);
    return false;
  };

  // Recorded before the drop, since setgroups is what throws them away and
  // there is no reading them back afterwards.
  const int count = ::getgroups(0, nullptr);
  if (count < 0) return fail("getgroups");
  saved->groups.assign(static_cast<size_t>(count), 0);
  if (count > 0 && ::getgroups(count, saved->groups.data()) < 0) return fail("getgroups");
  saved->held = true;

  // Supplementary groups are inherited from root and would otherwise survive
  // the drop, leaving the session with more access than the UID it claims.
  if (::setgroups(1, &gid) != 0) return fail("setgroups");
  if (::setresgid(gid, gid, 0) != 0) return fail("setresgid");
  if (::setresuid(uid, uid, 0) != 0) return fail("setresuid");

  // setresuid reports success if it changed *some* of the three IDs, so the
  // drop is verified rather than assumed.
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  if (::getresuid(&ruid, &euid, &suid) != 0) return fail("getresuid");
  if (::getresgid(&rgid, &egid, &sgid) != 0) return fail("getresgid");
  if (ruid != uid || euid != uid || suid != 0 || rgid != gid || egid != gid || sgid != 0) {
    *error_errno = 0;
    *error = "privilege drop did not take effect";
    return false;
  }
  return true;
}

// Climbs back through the saved 0, in the reverse order of the drop: the UID
// first, because everything below it needs root, and the groups last, because
// only root may set them.
bool RaisePrivileges(const SavedIdentity& saved, std::string* error) {
  auto fail = [&](const char* what) {
    *error = std::string(what) + " failed: " + ::strerror(errno);
    return false;
  };

  if (::setresuid(0, 0, 0) != 0) return fail("setresuid(0)");
  if (::setresgid(0, 0, 0) != 0) return fail("setresgid(0)");
  if (saved.held && ::setgroups(saved.groups.size(), saved.groups.data()) != 0) {
    return fail("setgroups");
  }

  uid_t ruid, euid, suid;
  if (::getresuid(&ruid, &euid, &suid) != 0) return fail("getresuid");
  if (ruid != 0 || euid != 0 || suid != 0) {
    *error = "could not get back to root";
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
void HandleList(IKeystoreService* service, const pb::ListRequest& request, pb::KeystoreResponse* response) {
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

// Shared by getKeyEntry and generateKey, which answer with the same thing: one
// says how a key was generated, the other says it while generating it. For an
// attested generation the certificate chain below is the attestation.
void ToWire(const KeyMetadata& in, pb::KeyMetadata* out) {
  ToWire(in.key, out->mutable_key());
  out->set_key_security_level(static_cast<int32_t>(in.keySecurityLevel));
  out->set_modification_time_ms(in.modificationTimeMs);

  for (const auto& authorization : in.authorizations) {
    auto* entry = out->add_authorizations();
    entry->set_security_level(static_cast<int32_t>(authorization.securityLevel));
    ToWire(authorization.keyParameter, entry->mutable_parameter());
  }

  if (in.certificate.has_value()) {
    out->set_certificate(in.certificate->data(), in.certificate->size());
  }
  if (in.certificateChain.has_value()) {
    out->set_certificate_chain(in.certificateChain->data(), in.certificateChain->size());
  }
}

// getKeyEntry also hands back an IKeystoreSecurityLevel; that handle stays here
// (§3.6) and only the metadata goes on the wire.
void HandleGetKeyEntry(IKeystoreService* service, const pb::GetKeyEntryRequest& request,
                       pb::KeystoreResponse* response) {
  KeyEntryResponse entry;
  const auto status = service->getKeyEntry(FromWire(request.key()), &entry);
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }
  ToWire(entry.metadata, response->mutable_get_key_entry()->mutable_metadata());
}

// deleteKey. On IKeystoreService rather than a security level: keystore2 finds
// the entry by descriptor and knows which backend holds it. The KeyMint blob
// goes with the entry, so there is nothing left afterwards and nothing to undo.
void HandleDeleteKey(IKeystoreService* service, const pb::DeleteKeyRequest& request,
                     pb::KeystoreResponse* response) {
  const auto status = service->deleteKey(FromWire(request.key()));
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }
  response->mutable_delete_key();
}

// updateSubcomponent. Replaces a key's certificates without touching the key.
// Both arguments are nullable and independent, and an absent one clears rather
// than keeps -- so the two optionals are passed straight through as they came,
// and a request that sets neither is a request to hold no certificate at all.
void HandleUpdateSubcomponent(IKeystoreService* service,
                              const pb::UpdateSubcomponentRequest& request,
                              pb::KeystoreResponse* response) {
  std::optional<std::vector<uint8_t>> certificate;
  if (request.has_certificate()) {
    certificate.emplace(request.certificate().begin(), request.certificate().end());
  }
  std::optional<std::vector<uint8_t>> chain;
  if (request.has_certificate_chain()) {
    chain.emplace(request.certificate_chain().begin(), request.certificate_chain().end());
  }

  const auto status =
      service->updateSubcomponent(FromWire(request.key()), certificate, chain);
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }
  response->mutable_update_subcomponent();
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

  // Root as it was before the drop, for end_session to climb back to.
  SavedIdentity saved;

  // Everything the dropped UID reached goes when the session does. Binder
  // itself does not: the driver captures credentials per transaction, so the
  // process's one connection serves whatever UID it currently is, and the next
  // session's proxies are fetched fresh anyway.
  void Forget() {
    operation.reset();
    security_levels.clear();
    service.reset();
  }
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

// Fills `response` with whatever went wrong reaching a security level, for the
// two calls that need one. A null handle with an ok status is keystore2
// answering a level it does not have, which is not an error it reports.
void FillSecurityLevelError(const ::ndk::ScopedAStatus& status, int32_t level,
                            pb::KeystoreResponse* response) {
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }
  FillProtocolError("keystore2 returned no security level for " + std::to_string(level),
                    response->mutable_error());
}

// generateKey. Attestation is not a separate call: a parameter list carrying
// ATTESTATION_CHALLENGE comes back with a certificate chain, and one without
// comes back with a self-signed leaf and no chain. Either way the daemon does
// not read the parameters -- what a key needs is KeyMint's business.
//
// keystore2 adds ATTESTATION_APPLICATION_ID itself, from the calling UID's
// package and signing certificate. That is why this has to run inside the
// session's dropped child rather than as root, and why attesting as a UID with
// no package installed fails in keystore2 rather than here.
void HandleGenerateKey(SessionState* session, const pb::GenerateKeyRequest& request,
                       pb::KeystoreResponse* response) {
  ::ndk::ScopedAStatus status;
  auto level = SecurityLevelFor(session, request.security_level(), &status);
  if (level == nullptr) {
    FillSecurityLevelError(status, request.security_level(), response);
    return;
  }

  std::vector<KeyParameter> parameters;
  parameters.reserve(static_cast<size_t>(request.parameters_size()));
  for (const auto& parameter : request.parameters()) parameters.push_back(FromWire(parameter));

  std::optional<KeyDescriptor> attestation_key;
  if (request.has_attestation_key()) attestation_key = FromWire(request.attestation_key());

  KeyMetadata metadata;
  status = level->generateKey(FromWire(request.key()), attestation_key, parameters,
                              request.flags(), Bytes(request.entropy()), &metadata);
  if (!status.isOk()) {
    FillError(status, response->mutable_error());
    return;
  }

  ToWire(metadata, response->mutable_generate_key()->mutable_metadata());
}

// createOperation, shared by run_operation and op_begin. On failure it fills
// `response` with the error and returns null; `begun` is a local the caller
// copies into the response only once the whole call has succeeded, so a later
// failure can replace the response body wholesale.
std::shared_ptr<IKeystoreOperation> BeginOperation(SessionState* session,
                                                   const pb::OperationStart& start,
                                                   pb::OperationBegun* begun,
                                                   pb::KeystoreResponse* response) {
  ::ndk::ScopedAStatus status;
  auto level = SecurityLevelFor(session, start.security_level(), &status);
  if (level == nullptr) {
    FillSecurityLevelError(status, start.security_level(), response);
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
                        pb::KeystoreResponse* response) {
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
                   pb::KeystoreResponse* response) {
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
IKeystoreOperation* LiveOperation(SessionState* session, pb::KeystoreResponse* response) {
  if (session->operation == nullptr) {
    FillProtocolError("no operation is open on this session", response->mutable_error());
    return nullptr;
  }
  return session->operation.get();
}

void HandleOpUpdateAad(SessionState* session, const pb::OpUpdateAadRequest& request,
                       pb::KeystoreResponse* response) {
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
                    pb::KeystoreResponse* response) {
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
                    pb::KeystoreResponse* response) {
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

void HandleOpAbort(SessionState* session, pb::KeystoreResponse* response) {
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

// Drops privileges and connects to keystore2. Failures are reported in the
// command response like any other, so the client always learns why.
std::shared_ptr<IKeystoreService> OpenKeystoreSession(const pb::OpenKeystoreSessionRequest& request,
                                                      SavedIdentity* saved,
                                                      pb::CommandResponse* response) {
  const auto uid = static_cast<uid_t>(request.uid());

  std::string error;
  int error_errno = 0;
  if (!DropPrivileges(uid, saved, &error, &error_errno)) {
    KS_LOGE("could not become uid=%u: %s", uid, error.c_str());
    FillIdentityError(error, error_errno, response->mutable_error());
    return nullptr;
  }
  KS_LOGI("session running as uid=%u", uid);

  auto service = ConnectKeystore(&error);
  if (service == nullptr) {
    KS_LOGE("%s", error.c_str());
    FillIdentityError(error, 0, response->mutable_error());
    return nullptr;
  }

  // The client drives its capability table off this number, so an interface
  // version we cannot read is a failed session rather than a guess.
  int32_t interface_version = 0;
  const auto status = service->getInterfaceVersion(&interface_version);
  if (!status.isOk()) {
    const char* message = status.getMessage();
    FillIdentityError(std::string("getInterfaceVersion failed: ") + (message ? message : ""), 0,
                      response->mutable_error());
    return nullptr;
  }

  response->mutable_open_keystore_session()->set_keystore_interface_version(interface_version);
  KS_LOGI("keystore2 interface version %d", interface_version);
  return service;
}

// Always runs as root: this is a top-level command, and the only way to reach
// it is before any session has dropped privileges.
void HandleReadFile(const pb::ReadFileRequest& request, pb::CommandResponse* response) {
  const int fd = ::open(request.path().c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    FillIdentityError("could not open '" + request.path() + "': " + ::strerror(errno), errno,
                      response->mutable_error());
    return;
  }

  // Clamped so a huge max_length cannot ask for a frame the peer would reject.
  size_t length = request.max_length() == 0 ? kReadChunkBytes : request.max_length();
  if (length > kReadChunkBytes) length = kReadChunkBytes;

  std::string buffer(length, '\0');
  const ssize_t got = ::pread(fd, buffer.data(), length, static_cast<off_t>(request.offset()));
  const int read_errno = errno;
  ::close(fd);

  if (got < 0) {
    FillIdentityError("could not read '" + request.path() + "': " + ::strerror(read_errno),
                      read_errno, response->mutable_error());
    return;
  }

  buffer.resize(static_cast<size_t>(got));
  auto* result = response->mutable_read_file();
  result->set_data(buffer);
  // A short read is only the end of the file if it was short of what was asked
  // for; pread stops at EOF and nowhere else for a regular file.
  result->set_eof(static_cast<size_t>(got) < length);
}

// Answered first, then signalled: the client has to learn the kill was
// accepted, and the supervisor's SIGTERM comes straight back to this child.
// Still root here -- privileges only drop when a keystore session opens.
void HandleKillServer(pid_t supervisor_pid, pb::CommandResponse* response) {
  response->mutable_kill_server();
  KS_LOGI("kill_server requested, signalling supervisor %d", supervisor_pid);
}

// One frame, taking anything an exec pump read past its own last frame first.
// Those bytes are already off the socket, so reading the socket again would
// skip them; and a frame that arrived in pieces has to be reassembled from the
// half that is here and the half still in flight.
FrameStatus NextFrame(int fd, std::string* pending, std::string* out) {
  if (pending->empty()) return ReadFrame(fd, out);

  FrameBuffer buffered;
  buffered.Append(pending->data(), pending->size());
  for (;;) {
    if (buffered.over_limit()) return FrameStatus::kTooLarge;
    if (buffered.Next(out)) {
      *pending = buffered.Rest();
      return FrameStatus::kOk;
    }

    char chunk[4096];
    const ssize_t got = ::read(fd, chunk, sizeof(chunk));
    if (got > 0) {
      buffered.Append(chunk, static_cast<size_t>(got));
      continue;
    }
    if (got == 0) {
      // Mid-frame, so this is a truncation rather than a clean hang-up.
      pending->clear();
      return FrameStatus::kTruncated;
    }
    if (errno == EINTR) continue;
    return FrameStatus::kIoError;
  }
}

}  // namespace

int RunConnection(int fd, pid_t supervisor_pid) {
  // The server speaks first, so version validation happens once and the
  // client's command stream needs no special first message.
  pb::Greeting greeting;
  greeting.set_protocol_version(kProtocolVersion);
  if (!SendFrame(fd, greeting)) return 1;

  SessionState session;
  ExecProcess process;
  IntegritySession integrity;
  std::string encoded;

  // Bytes an exec pump read past the last frame it consumed. Already off the
  // socket, so the command loop has to take them from here.
  std::string pending;

  // Two levels, and the connection moves between them: the top level hands
  // over to a subprotocol, and a keystore session hands back. exec and
  // integrity do not come back, so those return out of here entirely.
  for (;;) {
  // Top level: root, one Command at a time, until one hands the connection to
  // a subprotocol.
  while (session.service == nullptr) {
    const FrameStatus frame_status = NextFrame(fd, &pending, &encoded);
    if (frame_status == FrameStatus::kEof) return 0;
    if (frame_status != FrameStatus::kOk) {
      KS_LOGE("command read failed: %s", ToString(frame_status));
      return 1;
    }

    pb::CommandResponse response;
    pb::Command command;
    bool kill_requested = false;
    bool exec_started = false;
    bool integrity_opened = false;
    bool straggler = false;

    if (!command.ParseFromString(encoded)) {
      FillProtocolError("malformed command", response.mutable_error());
    } else {
      switch (command.body_case()) {
        case pb::Command::kReadFile:
          HandleReadFile(command.read_file(), &response);
          break;
        case pb::Command::kKillServer:
          HandleKillServer(supervisor_pid, &response);
          kill_requested = true;
          break;
        case pb::Command::kOpenKeystoreSession:
          // From here the connection is a keystore session until it says
          // otherwise: the drop keeps 0 as the saved UID, so end_session can
          // climb back and the top level resumes.
          session.service =
              OpenKeystoreSession(command.open_keystore_session(), &session.saved, &response);
          break;
        case pb::Command::kExec: {
          // Also irreversible, for a different reason: on success the
          // connection becomes the child's stdio, so there is nowhere left to
          // put a command. A failed exec is an ordinary error and changes
          // nothing -- the error is built to one side so that the response
          // carries it only if there is one.
          pb::Error error;
          if (StartExec(command.exec(), &process, &error)) {
            auto* started = response.mutable_exec();
            started->set_pid(process.pid);
            started->set_pty(process.pty);
            exec_started = true;
          } else {
            *response.mutable_error() = error;
          }
          break;
        }
        case pb::Command::kOpenIntegritySession:
          // Irreversible like the two above, and slower than anything else at
          // this level: it has to catch a zygote fork, so it takes seconds
          // rather than a round trip. On success the connection is a
          // conversation with the app for the rest of its life.
          integrity_opened = OpenIntegritySession(command.open_integrity_session(), &response,
                                                  &integrity);
          break;
        case pb::Command::kExecInput:
          // Input for a child that has already exited: the client sent it
          // before it saw the exit, and it arrived after. Harmless, and
          // recognizable as itself -- which is the whole reason exec_input
          // lives in Command rather than in a message of its own.
          straggler = true;
          break;
        case pb::Command::BODY_NOT_SET:
          // Also what a newer client's unimplemented command looks like here:
          // its field number is unknown to this build, so no arm is set.
          FillProtocolError("command names nothing this server implements",
                            response.mutable_error());
          break;
      }
    }

    // A straggling exec input is answered with nothing at all: the client is
    // not waiting on it, and a response it never asked for would be read as
    // the answer to whatever it asks next.
    if (straggler) continue;

    if (!SendFrame(fd, response)) {
      KS_LOGE("command response write failed: %s", ::strerror(errno));
      return 1;
    }

    if (kill_requested) {
      if (::kill(supervisor_pid, SIGTERM) != 0) {
        KS_LOGE("could not signal supervisor %d: %s", supervisor_pid, ::strerror(errno));
        return 1;
      }
      return 0;
    }

    // The client has been told the child's pid; everything after this is its
    // stdio, in both directions and unprompted -- until the child exits, at
    // which point the connection is a connection again.
    if (exec_started) {
      std::string leftover;
      switch (RunExecSession(fd, &process, &leftover)) {
        case ExecOutcome::kChildExited:
          pending.append(leftover);
          process = ExecProcess();
          continue;
        case ExecOutcome::kClientGone:
          return 0;
        case ExecOutcome::kFailed:
          return 1;
      }
    }

    // Likewise: the client has been told the app is up, and everything after
    // this belongs to it.
    if (integrity_opened) return RunIntegritySession(fd, &integrity);
  }

  // Keystore subprotocol: only these messages, until end_session or EOF.
  bool ended = false;
  while (!ended) {
    const FrameStatus frame_status = ReadFrame(fd, &encoded);
    if (frame_status == FrameStatus::kEof) return 0;
    if (frame_status != FrameStatus::kOk) {
      KS_LOGE("request read failed: %s", ToString(frame_status));
      return 1;
    }

    pb::KeystoreResponse response;
    pb::KeystoreRequest request;
    if (!request.ParseFromString(encoded)) {
      FillProtocolError("malformed request", response.mutable_error());
    } else {
      switch (request.body_case()) {
        case pb::KeystoreRequest::kEndSession: {
          // Everything the dropped UID reached is released before the climb,
          // so nothing outlives the identity it was obtained under.
          session.Forget();
          std::string error;
          if (!RaisePrivileges(session.saved, &error)) {
            // Nothing here can be trusted afterwards: the connection is stuck
            // at a UID it was meant to have left, and pretending otherwise
            // would let the next command run as the wrong one.
            KS_LOGE("could not end the keystore session: %s", error.c_str());
            FillIdentityError(error, errno, response.mutable_error());
            SendFrame(fd, response);
            return 1;
          }
          KS_LOGI("keystore session ended; back to root");
          response.mutable_end_session();
          ended = true;
          break;
        }
        case pb::KeystoreRequest::kList:
          HandleList(session.service.get(), request.list(), &response);
          break;
        case pb::KeystoreRequest::kGetKeyEntry:
          HandleGetKeyEntry(session.service.get(), request.get_key_entry(), &response);
          break;
        case pb::KeystoreRequest::kGenerateKey:
          HandleGenerateKey(&session, request.generate_key(), &response);
          break;
        case pb::KeystoreRequest::kDeleteKey:
          HandleDeleteKey(session.service.get(), request.delete_key(), &response);
          break;
        case pb::KeystoreRequest::kUpdateSubcomponent:
          HandleUpdateSubcomponent(session.service.get(), request.update_subcomponent(),
                                   &response);
          break;
        case pb::KeystoreRequest::kRunOperation:
          HandleRunOperation(&session, request.run_operation(), &response);
          break;
        case pb::KeystoreRequest::kOpBegin:
          HandleOpBegin(&session, request.op_begin(), &response);
          break;
        case pb::KeystoreRequest::kOpUpdateAad:
          HandleOpUpdateAad(&session, request.op_update_aad(), &response);
          break;
        case pb::KeystoreRequest::kOpUpdate:
          HandleOpUpdate(&session, request.op_update(), &response);
          break;
        case pb::KeystoreRequest::kOpFinish:
          HandleOpFinish(&session, request.op_finish(), &response);
          break;
        case pb::KeystoreRequest::kOpAbort:
          HandleOpAbort(&session, &response);
          break;
        case pb::KeystoreRequest::BODY_NOT_SET:
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
  }  // and round to the top level again, as root
}

}  // namespace keystork
