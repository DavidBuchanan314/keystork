/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/PaddingMode.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/PaddingMode.aidl
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
enum class PaddingMode : int32_t {
  NONE = 1,
  RSA_OAEP = 2,
  RSA_PSS = 3,
  RSA_PKCS1_1_5_ENCRYPT = 4,
  RSA_PKCS1_1_5_SIGN = 5,
  PKCS7 = 64,
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
[[nodiscard]] static inline std::string toString(PaddingMode val) {
  switch(val) {
  case PaddingMode::NONE:
    return "NONE";
  case PaddingMode::RSA_OAEP:
    return "RSA_OAEP";
  case PaddingMode::RSA_PSS:
    return "RSA_PSS";
  case PaddingMode::RSA_PKCS1_1_5_ENCRYPT:
    return "RSA_PKCS1_1_5_ENCRYPT";
  case PaddingMode::RSA_PKCS1_1_5_SIGN:
    return "RSA_PKCS1_1_5_SIGN";
  case PaddingMode::PKCS7:
    return "PKCS7";
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
constexpr inline std::array<aidl::android::hardware::security::keymint::PaddingMode, 6> enum_values<aidl::android::hardware::security::keymint::PaddingMode> = {
  aidl::android::hardware::security::keymint::PaddingMode::NONE,
  aidl::android::hardware::security::keymint::PaddingMode::RSA_OAEP,
  aidl::android::hardware::security::keymint::PaddingMode::RSA_PSS,
  aidl::android::hardware::security::keymint::PaddingMode::RSA_PKCS1_1_5_ENCRYPT,
  aidl::android::hardware::security::keymint::PaddingMode::RSA_PKCS1_1_5_SIGN,
  aidl::android::hardware::security::keymint::PaddingMode::PKCS7,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
