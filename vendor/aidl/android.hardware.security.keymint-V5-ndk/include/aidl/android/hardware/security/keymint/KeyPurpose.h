/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/KeyPurpose.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/KeyPurpose.aidl
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
enum class KeyPurpose : int32_t {
  ENCRYPT = 0,
  DECRYPT = 1,
  SIGN = 2,
  VERIFY = 3,
  WRAP_KEY = 5,
  AGREE_KEY = 6,
  ATTEST_KEY = 7,
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
[[nodiscard]] static inline std::string toString(KeyPurpose val) {
  switch(val) {
  case KeyPurpose::ENCRYPT:
    return "ENCRYPT";
  case KeyPurpose::DECRYPT:
    return "DECRYPT";
  case KeyPurpose::SIGN:
    return "SIGN";
  case KeyPurpose::VERIFY:
    return "VERIFY";
  case KeyPurpose::WRAP_KEY:
    return "WRAP_KEY";
  case KeyPurpose::AGREE_KEY:
    return "AGREE_KEY";
  case KeyPurpose::ATTEST_KEY:
    return "ATTEST_KEY";
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
constexpr inline std::array<aidl::android::hardware::security::keymint::KeyPurpose, 7> enum_values<aidl::android::hardware::security::keymint::KeyPurpose> = {
  aidl::android::hardware::security::keymint::KeyPurpose::ENCRYPT,
  aidl::android::hardware::security::keymint::KeyPurpose::DECRYPT,
  aidl::android::hardware::security::keymint::KeyPurpose::SIGN,
  aidl::android::hardware::security::keymint::KeyPurpose::VERIFY,
  aidl::android::hardware::security::keymint::KeyPurpose::WRAP_KEY,
  aidl::android::hardware::security::keymint::KeyPurpose::AGREE_KEY,
  aidl::android::hardware::security::keymint::KeyPurpose::ATTEST_KEY,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
