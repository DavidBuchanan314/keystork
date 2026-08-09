#include "status.h"

namespace keystork {

namespace pb = ::keystork::v1;

void FillError(const ::ndk::ScopedAStatus& status, pb::Error* out) {
  const char* message = status.getMessage();
  out->set_message(message != nullptr ? message : "");

  if (status.getExceptionCode() == EX_SERVICE_SPECIFIC) {
    out->set_kind(pb::Error::SERVICE_SPECIFIC);
    out->set_code(status.getServiceSpecificError());
    return;
  }

  // Everything else is a transaction-level failure: a dead node, an unknown
  // transaction code because the device's keystore2 is older than the stubs we
  // built against, a security exception, and so on. Both numbers are kept
  // because the two spaces overlap (EX_SECURITY == -1 and
  // STATUS_PERMISSION_DENIED == -1 mean entirely different things).
  out->set_kind(pb::Error::TRANSACTION);
  out->set_code(status.getStatus());
  out->set_exception_code(status.getExceptionCode());
}

void FillProtocolError(const std::string& message, pb::Error* out) {
  out->set_kind(pb::Error::PROTOCOL);
  out->set_code(0);
  out->set_message(message);
}

void FillIdentityError(const std::string& message, int err, pb::Error* out) {
  out->set_kind(pb::Error::IDENTITY);
  out->set_code(err);
  out->set_message(message);
}

}  // namespace keystork
