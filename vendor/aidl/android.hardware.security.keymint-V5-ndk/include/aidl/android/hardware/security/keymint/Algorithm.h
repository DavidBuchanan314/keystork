/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/Algorithm.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/Algorithm.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_enums.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
enum class Algorithm : int32_t {
  RSA = 1,
  EC = 3,
  ML_DSA = 4,
  AES = 32,
  TRIPLE_DES = 33,
  HMAC = 128,
};

}  // namespace keymint
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
[[nodiscard]] static inline std::string toString(Algorithm val) {
  switch(val) {
  case Algorithm::RSA:
    return "RSA";
  case Algorithm::EC:
    return "EC";
  case Algorithm::ML_DSA:
    return "ML_DSA";
  case Algorithm::AES:
    return "AES";
  case Algorithm::TRIPLE_DES:
    return "TRIPLE_DES";
  case Algorithm::HMAC:
    return "HMAC";
  default:
    return std::to_string(static_cast<int32_t>(val));
  }
}
}  // namespace keymint
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace ndk {
namespace internal {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template <>
constexpr inline std::array<aidl::android::hardware::security::keymint::Algorithm, 6> enum_values<aidl::android::hardware::security::keymint::Algorithm> = {
  aidl::android::hardware::security::keymint::Algorithm::RSA,
  aidl::android::hardware::security::keymint::Algorithm::EC,
  aidl::android::hardware::security::keymint::Algorithm::ML_DSA,
  aidl::android::hardware::security::keymint::Algorithm::AES,
  aidl::android::hardware::security::keymint::Algorithm::TRIPLE_DES,
  aidl::android::hardware::security::keymint::Algorithm::HMAC,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
