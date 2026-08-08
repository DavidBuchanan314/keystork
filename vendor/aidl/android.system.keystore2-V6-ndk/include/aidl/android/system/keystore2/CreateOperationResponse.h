/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 6 --hash b115fcb5d111eb616a65f0f32e0c2cef131575ec -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint_interface/5/preprocessed.aidl --ninja -d out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging/android/system/keystore2/CreateOperationResponse.cpp.d -h out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/include/staging -o out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging -Nsystem/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6 system/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6/android/system/keystore2/CreateOperationResponse.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/KeyParameters.h>
#include <aidl/android/system/keystore2/OperationChallenge.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::system::keystore2 {
class IKeystoreOperation;
class KeyParameters;
class OperationChallenge;
}  // namespace aidl::android::system::keystore2
namespace aidl {
namespace android {
namespace system {
namespace keystore2 {
class CreateOperationResponse {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  std::shared_ptr<::aidl::android::system::keystore2::IKeystoreOperation> iOperation;
  std::optional<::aidl::android::system::keystore2::OperationChallenge> operationChallenge;
  std::optional<::aidl::android::system::keystore2::KeyParameters> parameters;
  std::optional<std::vector<uint8_t>> upgradedBlob;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator==(const CreateOperationResponse& _rhs) const {
    return std::tie(iOperation, operationChallenge, parameters, upgradedBlob) == std::tie(_rhs.iOperation, _rhs.operationChallenge, _rhs.parameters, _rhs.upgradedBlob);
  }
  inline bool operator<(const CreateOperationResponse& _rhs) const {
    return std::tie(iOperation, operationChallenge, parameters, upgradedBlob) < std::tie(_rhs.iOperation, _rhs.operationChallenge, _rhs.parameters, _rhs.upgradedBlob);
  }
  inline bool operator!=(const CreateOperationResponse& _rhs) const {
    return !(*this == _rhs);
  }
  inline bool operator>(const CreateOperationResponse& _rhs) const {
    return _rhs < *this;
  }
  inline bool operator>=(const CreateOperationResponse& _rhs) const {
    return !(*this < _rhs);
  }
  inline bool operator<=(const CreateOperationResponse& _rhs) const {
    return !(_rhs < *this);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream _aidl_os;
    _aidl_os << "CreateOperationResponse{";
    _aidl_os << "iOperation: " << ::android::internal::ToString(iOperation);
    _aidl_os << ", operationChallenge: " << ::android::internal::ToString(operationChallenge);
    _aidl_os << ", parameters: " << ::android::internal::ToString(parameters);
    _aidl_os << ", upgradedBlob: " << ::android::internal::ToString(upgradedBlob);
    _aidl_os << "}";
    return _aidl_os.str();
  }
};
}  // namespace keystore2
}  // namespace system
}  // namespace android
}  // namespace aidl
