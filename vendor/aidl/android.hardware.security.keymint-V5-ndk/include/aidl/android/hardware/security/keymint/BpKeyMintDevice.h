/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/IKeyMintDevice.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/IKeyMintDevice.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include "aidl/android/hardware/security/keymint/IKeyMintDevice.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
class BpKeyMintDevice : public ::ndk::BpCInterface<IKeyMintDevice> {
public:
  explicit BpKeyMintDevice(const ::ndk::SpAIBinder& binder);
  virtual ~BpKeyMintDevice();

  ::ndk::ScopedAStatus getHardwareInfo(::aidl::android::hardware::security::keymint::KeyMintHardwareInfo* _aidl_return) override;
  ::ndk::ScopedAStatus addRngEntropy(const std::vector<uint8_t>& in_data) override;
  ::ndk::ScopedAStatus generateKey(const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_keyParams, const std::optional<::aidl::android::hardware::security::keymint::AttestationKey>& in_attestationKey, ::aidl::android::hardware::security::keymint::KeyCreationResult* _aidl_return) override;
  ::ndk::ScopedAStatus importKey(const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_keyParams, ::aidl::android::hardware::security::keymint::KeyFormat in_keyFormat, const std::vector<uint8_t>& in_keyData, const std::optional<::aidl::android::hardware::security::keymint::AttestationKey>& in_attestationKey, ::aidl::android::hardware::security::keymint::KeyCreationResult* _aidl_return) override;
  ::ndk::ScopedAStatus importWrappedKey(const std::vector<uint8_t>& in_wrappedKeyData, const std::vector<uint8_t>& in_wrappingKeyBlob, const std::vector<uint8_t>& in_maskingKey, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_unwrappingParams, int64_t in_passwordSid, int64_t in_biometricSid, ::aidl::android::hardware::security::keymint::KeyCreationResult* _aidl_return) override;
  ::ndk::ScopedAStatus upgradeKey(const std::vector<uint8_t>& in_keyBlobToUpgrade, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_upgradeParams, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus deleteKey(const std::vector<uint8_t>& in_keyBlob) override;
  ::ndk::ScopedAStatus deleteAllKeys() override;
  ::ndk::ScopedAStatus destroyAttestationIds() override;
  ::ndk::ScopedAStatus begin(::aidl::android::hardware::security::keymint::KeyPurpose in_purpose, const std::vector<uint8_t>& in_keyBlob, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_params, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, ::aidl::android::hardware::security::keymint::BeginResult* _aidl_return) override;
  ::ndk::ScopedAStatus deviceLocked(bool in_passwordOnly, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timestampToken) override __attribute__((deprecated("Method has never been used due to design limitations")));
  ::ndk::ScopedAStatus earlyBootEnded() override;
  ::ndk::ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& in_storageKeyBlob, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& in_keyBlob, const std::vector<uint8_t>& in_appId, const std::vector<uint8_t>& in_appData, std::vector<::aidl::android::hardware::security::keymint::KeyCharacteristics>* _aidl_return) override;
  ::ndk::ScopedAStatus getRootOfTrustChallenge(std::array<uint8_t, 16>* _aidl_return) override;
  ::ndk::ScopedAStatus getRootOfTrust(const std::array<uint8_t, 16>& in_challenge, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus sendRootOfTrust(const std::vector<uint8_t>& in_rootOfTrust) override;
  ::ndk::ScopedAStatus setAdditionalAttestationInfo(const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_info) override;
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
