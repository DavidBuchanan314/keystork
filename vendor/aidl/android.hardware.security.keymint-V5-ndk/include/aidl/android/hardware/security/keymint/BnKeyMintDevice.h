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
#include <cassert>

#ifndef __BIONIC__
#ifndef __assert2
#define __assert2(a,b,c,d) ((void)0)
#endif
#endif

namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
class BnKeyMintDevice : public ::ndk::BnCInterface<IKeyMintDevice> {
public:
  BnKeyMintDevice();
  virtual ~BnKeyMintDevice();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IKeyMintDeviceDelegator : public BnKeyMintDevice {
public:
  explicit IKeyMintDeviceDelegator(const std::shared_ptr<IKeyMintDevice> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IKeyMintDevice::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus getHardwareInfo(::aidl::android::hardware::security::keymint::KeyMintHardwareInfo* _aidl_return) override {
    return _impl->getHardwareInfo(_aidl_return);
  }
  ::ndk::ScopedAStatus addRngEntropy(const std::vector<uint8_t>& in_data) override {
    return _impl->addRngEntropy(in_data);
  }
  ::ndk::ScopedAStatus generateKey(const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_keyParams, const std::optional<::aidl::android::hardware::security::keymint::AttestationKey>& in_attestationKey, ::aidl::android::hardware::security::keymint::KeyCreationResult* _aidl_return) override {
    return _impl->generateKey(in_keyParams, in_attestationKey, _aidl_return);
  }
  ::ndk::ScopedAStatus importKey(const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_keyParams, ::aidl::android::hardware::security::keymint::KeyFormat in_keyFormat, const std::vector<uint8_t>& in_keyData, const std::optional<::aidl::android::hardware::security::keymint::AttestationKey>& in_attestationKey, ::aidl::android::hardware::security::keymint::KeyCreationResult* _aidl_return) override {
    return _impl->importKey(in_keyParams, in_keyFormat, in_keyData, in_attestationKey, _aidl_return);
  }
  ::ndk::ScopedAStatus importWrappedKey(const std::vector<uint8_t>& in_wrappedKeyData, const std::vector<uint8_t>& in_wrappingKeyBlob, const std::vector<uint8_t>& in_maskingKey, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_unwrappingParams, int64_t in_passwordSid, int64_t in_biometricSid, ::aidl::android::hardware::security::keymint::KeyCreationResult* _aidl_return) override {
    return _impl->importWrappedKey(in_wrappedKeyData, in_wrappingKeyBlob, in_maskingKey, in_unwrappingParams, in_passwordSid, in_biometricSid, _aidl_return);
  }
  ::ndk::ScopedAStatus upgradeKey(const std::vector<uint8_t>& in_keyBlobToUpgrade, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_upgradeParams, std::vector<uint8_t>* _aidl_return) override {
    return _impl->upgradeKey(in_keyBlobToUpgrade, in_upgradeParams, _aidl_return);
  }
  ::ndk::ScopedAStatus deleteKey(const std::vector<uint8_t>& in_keyBlob) override {
    return _impl->deleteKey(in_keyBlob);
  }
  ::ndk::ScopedAStatus deleteAllKeys() override {
    return _impl->deleteAllKeys();
  }
  ::ndk::ScopedAStatus destroyAttestationIds() override {
    return _impl->destroyAttestationIds();
  }
  ::ndk::ScopedAStatus begin(::aidl::android::hardware::security::keymint::KeyPurpose in_purpose, const std::vector<uint8_t>& in_keyBlob, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_params, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, ::aidl::android::hardware::security::keymint::BeginResult* _aidl_return) override {
    return _impl->begin(in_purpose, in_keyBlob, in_params, in_authToken, _aidl_return);
  }
  ::ndk::ScopedAStatus deviceLocked(bool in_passwordOnly, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timestampToken) override __attribute__((deprecated("Method has never been used due to design limitations"))) {
    return _impl->deviceLocked(in_passwordOnly, in_timestampToken);
  }
  ::ndk::ScopedAStatus earlyBootEnded() override {
    return _impl->earlyBootEnded();
  }
  ::ndk::ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& in_storageKeyBlob, std::vector<uint8_t>* _aidl_return) override {
    return _impl->convertStorageKeyToEphemeral(in_storageKeyBlob, _aidl_return);
  }
  ::ndk::ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& in_keyBlob, const std::vector<uint8_t>& in_appId, const std::vector<uint8_t>& in_appData, std::vector<::aidl::android::hardware::security::keymint::KeyCharacteristics>* _aidl_return) override {
    return _impl->getKeyCharacteristics(in_keyBlob, in_appId, in_appData, _aidl_return);
  }
  ::ndk::ScopedAStatus getRootOfTrustChallenge(std::array<uint8_t, 16>* _aidl_return) override {
    return _impl->getRootOfTrustChallenge(_aidl_return);
  }
  ::ndk::ScopedAStatus getRootOfTrust(const std::array<uint8_t, 16>& in_challenge, std::vector<uint8_t>* _aidl_return) override {
    return _impl->getRootOfTrust(in_challenge, _aidl_return);
  }
  ::ndk::ScopedAStatus sendRootOfTrust(const std::vector<uint8_t>& in_rootOfTrust) override {
    return _impl->sendRootOfTrust(in_rootOfTrust);
  }
  ::ndk::ScopedAStatus setAdditionalAttestationInfo(const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_info) override {
    return _impl->setAdditionalAttestationInfo(in_info);
  }
protected:
private:
  std::shared_ptr<IKeyMintDevice> _impl;
};

}  // namespace keymint
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
