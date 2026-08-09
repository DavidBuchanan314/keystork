#include "session.h"

#include <cerrno>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

// From vendor/binder_ndk/include_platform: the NDK ships neither of these.
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <aidl/android/system/keystore2/Domain.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/KeyDescriptor.h>

#include "framing.h"
#include "keystork.pb.h"
#include "log.h"
#include "status.h"

namespace keystork {
namespace {

namespace pb = ::keystork::v1;

using ::aidl::android::system::keystore2::Domain;
using ::aidl::android::system::keystore2::IKeystoreService;
using ::aidl::android::system::keystore2::KeyDescriptor;

constexpr char kKeystoreServiceName[] = "android.system.keystore2.IKeystoreService/default";
constexpr uint32_t kProtocolVersion = pb::PROTOCOL_VERSION_1;

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

bool SendFrame(int fd, const google::protobuf::MessageLite& message) {
  std::string encoded;
  if (!message.SerializeToString(&encoded)) {
    KS_LOGE("failed to serialize response");
    return false;
  }
  return WriteFrame(fd, encoded);
}

// Reads the mandatory handshake, drops privileges, and connects to keystore2.
// Every failure is reported in the ack rather than by dropping the connection,
// so the client always learns why a session did not start.
std::shared_ptr<IKeystoreService> Establish(int fd) {
  std::string encoded;
  const FrameStatus frame_status = ReadFrame(fd, &encoded);
  if (frame_status != FrameStatus::kOk) {
    // Nothing useful to say to a peer that never sent a readable handshake.
    KS_LOGE("handshake read failed: %s", ToString(frame_status));
    return nullptr;
  }

  pb::HandshakeAck ack;
  ack.set_protocol_version(kProtocolVersion);

  pb::Handshake handshake;
  if (!handshake.ParseFromString(encoded)) {
    FillProtocolError("malformed handshake", ack.mutable_error());
    SendFrame(fd, ack);
    return nullptr;
  }
  if (handshake.protocol_version() != kProtocolVersion) {
    FillProtocolError("unsupported protocol version " +
                          std::to_string(handshake.protocol_version()) + ", this server speaks " +
                          std::to_string(kProtocolVersion),
                      ack.mutable_error());
    SendFrame(fd, ack);
    return nullptr;
  }

  const auto uid = static_cast<uid_t>(handshake.uid());

  std::string error;
  int error_errno = 0;
  if (!DropPrivileges(uid, &error, &error_errno)) {
    KS_LOGE("could not become uid=%u: %s", uid, error.c_str());
    FillIdentityError(error, error_errno, ack.mutable_error());
    SendFrame(fd, ack);
    return nullptr;
  }
  KS_LOGI("session running as uid=%u", uid);

  auto service = ConnectKeystore(&error);
  if (service == nullptr) {
    KS_LOGE("%s", error.c_str());
    FillIdentityError(error, 0, ack.mutable_error());
    SendFrame(fd, ack);
    return nullptr;
  }

  // The client drives its capability table off this number, so an interface
  // version we cannot read is a failed session rather than a guess.
  int32_t interface_version = 0;
  auto status = service->getInterfaceVersion(&interface_version);
  if (!status.isOk()) {
    const char* message = status.getMessage();
    FillIdentityError(std::string("getInterfaceVersion failed: ") + (message ? message : ""),
                      0, ack.mutable_error());
    SendFrame(fd, ack);
    return nullptr;
  }

  ack.set_keystore_interface_version(interface_version);
  KS_LOGI("keystore2 interface version %d", interface_version);
  if (!SendFrame(fd, ack)) return nullptr;
  return service;
}

}  // namespace

int RunSession(int fd) {
  auto service = Establish(fd);
  if (service == nullptr) return 1;

  for (;;) {
    std::string encoded;
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
          HandleList(service.get(), request.list(), &response);
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
