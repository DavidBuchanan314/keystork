/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/HardwareAuthToken.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/HardwareAuthToken.aidl
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
#include <aidl/android/hardware/security/keymint/HardwareAuthenticatorType.h>
#include <aidl/android/hardware/security/secureclock/Timestamp.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::hardware::security::secureclock {
class Timestamp;
}  // namespace aidl::android::hardware::security::secureclock
namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
class HardwareAuthToken {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int64_t challenge = 0L;
  int64_t userId = 0L;
  int64_t authenticatorId = 0L;
  ::aidl::android::hardware::security::keymint::HardwareAuthenticatorType authenticatorType = ::aidl::android::hardware::security::keymint::HardwareAuthenticatorType::NONE;
  ::aidl::android::hardware::security::secureclock::Timestamp timestamp;
  std::vector<uint8_t> mac;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator==(const HardwareAuthToken& _rhs) const {
    return std::tie(challenge, userId, authenticatorId, authenticatorType, timestamp, mac) == std::tie(_rhs.challenge, _rhs.userId, _rhs.authenticatorId, _rhs.authenticatorType, _rhs.timestamp, _rhs.mac);
  }
  inline bool operator<(const HardwareAuthToken& _rhs) const {
    return std::tie(challenge, userId, authenticatorId, authenticatorType, timestamp, mac) < std::tie(_rhs.challenge, _rhs.userId, _rhs.authenticatorId, _rhs.authenticatorType, _rhs.timestamp, _rhs.mac);
  }
  inline bool operator!=(const HardwareAuthToken& _rhs) const {
    return !(*this == _rhs);
  }
  inline bool operator>(const HardwareAuthToken& _rhs) const {
    return _rhs < *this;
  }
  inline bool operator>=(const HardwareAuthToken& _rhs) const {
    return !(*this < _rhs);
  }
  inline bool operator<=(const HardwareAuthToken& _rhs) const {
    return !(_rhs < *this);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream _aidl_os;
    _aidl_os << "HardwareAuthToken{";
    _aidl_os << "challenge: " << ::android::internal::ToString(challenge);
    _aidl_os << ", userId: " << ::android::internal::ToString(userId);
    _aidl_os << ", authenticatorId: " << ::android::internal::ToString(authenticatorId);
    _aidl_os << ", authenticatorType: " << ::android::internal::ToString(authenticatorType);
    _aidl_os << ", timestamp: " << ::android::internal::ToString(timestamp);
    _aidl_os << ", mac: " << ::android::internal::ToString(mac);
    _aidl_os << "}";
    return _aidl_os.str();
  }
};
}  // namespace keymint
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
