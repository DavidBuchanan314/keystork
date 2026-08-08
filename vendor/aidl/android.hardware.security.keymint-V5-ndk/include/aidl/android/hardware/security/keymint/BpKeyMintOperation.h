/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/IKeyMintOperation.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/IKeyMintOperation.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include "aidl/android/hardware/security/keymint/IKeyMintOperation.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
class BpKeyMintOperation : public ::ndk::BpCInterface<IKeyMintOperation> {
public:
  explicit BpKeyMintOperation(const ::ndk::SpAIBinder& binder);
  virtual ~BpKeyMintOperation();

  ::ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& in_input, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timeStampToken) override;
  ::ndk::ScopedAStatus update(const std::vector<uint8_t>& in_input, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timeStampToken, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& in_input, const std::optional<std::vector<uint8_t>>& in_signature, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timestampToken, const std::optional<std::vector<uint8_t>>& in_confirmationToken, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus abort() override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  int32_t _aidl_cached_version = -1;
  std::string _aidl_cached_hash = "-1";
  std::mutex _aidl_cached_hash_mutex;
};
}  // namespace keymint
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
