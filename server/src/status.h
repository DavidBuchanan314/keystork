#pragma once

#include <string>

#include <android/binder_auto_utils.h>

#include "keystork.pb.h"

namespace keystork {

// Translates a Binder Status into the wire Error. The server does not
// interpret the numbers: it records which error space they came from and
// hands them over verbatim, and the Python client owns every name table.
//
//   service-specific -> kind=SERVICE_SPECIFIC, code = the int keystore2 threw
//                       (positive: keystore2 ResponseCode;
//                        negative: embedded KeyMint ErrorCode)
//   anything else    -> kind=TRANSACTION, code = binder_status_t,
//                       exception_code = binder_exception_t
void FillError(const ::ndk::ScopedAStatus& status, ::keystork::v1::Error* out);

// The client sent something this daemon cannot act on.
void FillProtocolError(const std::string& message, ::keystork::v1::Error* out);

// Session setup failed before any keystore2 call. `err` is an errno, or 0.
void FillIdentityError(const std::string& message, int err, ::keystork::v1::Error* out);

}  // namespace keystork
