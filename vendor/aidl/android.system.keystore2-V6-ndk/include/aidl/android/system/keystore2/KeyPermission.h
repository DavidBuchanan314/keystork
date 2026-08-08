/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 6 --hash b115fcb5d111eb616a65f0f32e0c2cef131575ec -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint_interface/5/preprocessed.aidl --ninja -d out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging/android/system/keystore2/KeyPermission.cpp.d -h out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/include/staging -o out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging -Nsystem/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6 system/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6/android/system/keystore2/KeyPermission.aidl
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
namespace system {
namespace keystore2 {
enum class KeyPermission : int32_t {
  NONE = 0,
  DELETE = 1,
  GEN_UNIQUE_ID = 2,
  GET_INFO = 4,
  GRANT = 8,
  MANAGE_BLOB = 16,
  REBIND = 32,
  REQ_FORCED_OP = 64,
  UPDATE = 128,
  USE = 256,
  USE_DEV_ID = 512,
  USE_NO_LSKF_BINDING = 1024,
  CONVERT_STORAGE_KEY_TO_EPHEMERAL = 2048,
};

}  // namespace keystore2
}  // namespace system
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace system {
namespace keystore2 {
[[nodiscard]] static inline std::string toString(KeyPermission val) {
  switch(val) {
  case KeyPermission::NONE:
    return "NONE";
  case KeyPermission::DELETE:
    return "DELETE";
  case KeyPermission::GEN_UNIQUE_ID:
    return "GEN_UNIQUE_ID";
  case KeyPermission::GET_INFO:
    return "GET_INFO";
  case KeyPermission::GRANT:
    return "GRANT";
  case KeyPermission::MANAGE_BLOB:
    return "MANAGE_BLOB";
  case KeyPermission::REBIND:
    return "REBIND";
  case KeyPermission::REQ_FORCED_OP:
    return "REQ_FORCED_OP";
  case KeyPermission::UPDATE:
    return "UPDATE";
  case KeyPermission::USE:
    return "USE";
  case KeyPermission::USE_DEV_ID:
    return "USE_DEV_ID";
  case KeyPermission::USE_NO_LSKF_BINDING:
    return "USE_NO_LSKF_BINDING";
  case KeyPermission::CONVERT_STORAGE_KEY_TO_EPHEMERAL:
    return "CONVERT_STORAGE_KEY_TO_EPHEMERAL";
  default:
    return std::to_string(static_cast<int32_t>(val));
  }
}
}  // namespace keystore2
}  // namespace system
}  // namespace android
}  // namespace aidl
namespace ndk {
namespace internal {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template <>
constexpr inline std::array<aidl::android::system::keystore2::KeyPermission, 13> enum_values<aidl::android::system::keystore2::KeyPermission> = {
  aidl::android::system::keystore2::KeyPermission::NONE,
  aidl::android::system::keystore2::KeyPermission::DELETE,
  aidl::android::system::keystore2::KeyPermission::GEN_UNIQUE_ID,
  aidl::android::system::keystore2::KeyPermission::GET_INFO,
  aidl::android::system::keystore2::KeyPermission::GRANT,
  aidl::android::system::keystore2::KeyPermission::MANAGE_BLOB,
  aidl::android::system::keystore2::KeyPermission::REBIND,
  aidl::android::system::keystore2::KeyPermission::REQ_FORCED_OP,
  aidl::android::system::keystore2::KeyPermission::UPDATE,
  aidl::android::system::keystore2::KeyPermission::USE,
  aidl::android::system::keystore2::KeyPermission::USE_DEV_ID,
  aidl::android::system::keystore2::KeyPermission::USE_NO_LSKF_BINDING,
  aidl::android::system::keystore2::KeyPermission::CONVERT_STORAGE_KEY_TO_EPHEMERAL,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
