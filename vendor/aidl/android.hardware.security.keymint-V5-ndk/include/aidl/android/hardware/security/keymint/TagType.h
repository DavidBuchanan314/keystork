/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/TagType.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/TagType.aidl
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
enum class TagType : int32_t {
  INVALID = 0,
  ENUM = 268435456,
  ENUM_REP = 536870912,
  UINT = 805306368,
  UINT_REP = 1073741824,
  ULONG = 1342177280,
  DATE = 1610612736,
  BOOL = 1879048192,
  BIGNUM = -2147483648,
  BYTES = -1879048192,
  ULONG_REP = -1610612736,
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
[[nodiscard]] static inline std::string toString(TagType val) {
  switch(val) {
  case TagType::INVALID:
    return "INVALID";
  case TagType::ENUM:
    return "ENUM";
  case TagType::ENUM_REP:
    return "ENUM_REP";
  case TagType::UINT:
    return "UINT";
  case TagType::UINT_REP:
    return "UINT_REP";
  case TagType::ULONG:
    return "ULONG";
  case TagType::DATE:
    return "DATE";
  case TagType::BOOL:
    return "BOOL";
  case TagType::BIGNUM:
    return "BIGNUM";
  case TagType::BYTES:
    return "BYTES";
  case TagType::ULONG_REP:
    return "ULONG_REP";
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
constexpr inline std::array<aidl::android::hardware::security::keymint::TagType, 11> enum_values<aidl::android::hardware::security::keymint::TagType> = {
  aidl::android::hardware::security::keymint::TagType::INVALID,
  aidl::android::hardware::security::keymint::TagType::ENUM,
  aidl::android::hardware::security::keymint::TagType::ENUM_REP,
  aidl::android::hardware::security::keymint::TagType::UINT,
  aidl::android::hardware::security::keymint::TagType::UINT_REP,
  aidl::android::hardware::security::keymint::TagType::ULONG,
  aidl::android::hardware::security::keymint::TagType::DATE,
  aidl::android::hardware::security::keymint::TagType::BOOL,
  aidl::android::hardware::security::keymint::TagType::BIGNUM,
  aidl::android::hardware::security::keymint::TagType::BYTES,
  aidl::android::hardware::security::keymint::TagType::ULONG_REP,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
