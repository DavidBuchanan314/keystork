/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/Digest.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/Digest.aidl
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
enum class Digest : int32_t {
  NONE = 0,
  MD5 = 1,
  SHA1 = 2,
  SHA_2_224 = 3,
  SHA_2_256 = 4,
  SHA_2_384 = 5,
  SHA_2_512 = 6,
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
[[nodiscard]] static inline std::string toString(Digest val) {
  switch(val) {
  case Digest::NONE:
    return "NONE";
  case Digest::MD5:
    return "MD5";
  case Digest::SHA1:
    return "SHA1";
  case Digest::SHA_2_224:
    return "SHA_2_224";
  case Digest::SHA_2_256:
    return "SHA_2_256";
  case Digest::SHA_2_384:
    return "SHA_2_384";
  case Digest::SHA_2_512:
    return "SHA_2_512";
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
constexpr inline std::array<aidl::android::hardware::security::keymint::Digest, 7> enum_values<aidl::android::hardware::security::keymint::Digest> = {
  aidl::android::hardware::security::keymint::Digest::NONE,
  aidl::android::hardware::security::keymint::Digest::MD5,
  aidl::android::hardware::security::keymint::Digest::SHA1,
  aidl::android::hardware::security::keymint::Digest::SHA_2_224,
  aidl::android::hardware::security::keymint::Digest::SHA_2_256,
  aidl::android::hardware::security::keymint::Digest::SHA_2_384,
  aidl::android::hardware::security::keymint::Digest::SHA_2_512,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
