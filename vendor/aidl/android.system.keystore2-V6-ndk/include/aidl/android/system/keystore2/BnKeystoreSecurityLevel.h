/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 6 --hash b115fcb5d111eb616a65f0f32e0c2cef131575ec -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint_interface/5/preprocessed.aidl --ninja -d out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging/android/system/keystore2/IKeystoreSecurityLevel.cpp.d -h out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/include/staging -o out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging -Nsystem/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6 system/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6/android/system/keystore2/IKeystoreSecurityLevel.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include "aidl/android/system/keystore2/IKeystoreSecurityLevel.h"

#include <android/binder_ibinder.h>
#include <cassert>

#ifndef __BIONIC__
#ifndef __assert2
#define __assert2(a,b,c,d) ((void)0)
#endif
#endif

namespace aidl {
namespace android {
namespace system {
namespace keystore2 {
class BnKeystoreSecurityLevel : public ::ndk::BnCInterface<IKeystoreSecurityLevel> {
public:
  BnKeystoreSecurityLevel();
  virtual ~BnKeystoreSecurityLevel();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IKeystoreSecurityLevelDelegator : public BnKeystoreSecurityLevel {
public:
  explicit IKeystoreSecurityLevelDelegator(const std::shared_ptr<IKeystoreSecurityLevel> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IKeystoreSecurityLevel::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus createOperation(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_operationParameters, bool in_forced, ::aidl::android::system::keystore2::CreateOperationResponse* _aidl_return) override {
    return _impl->createOperation(in_key, in_operationParameters, in_forced, _aidl_return);
  }
  ::ndk::ScopedAStatus generateKey(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, const std::optional<::aidl::android::system::keystore2::KeyDescriptor>& in_attestationKey, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_params, int32_t in_flags, const std::vector<uint8_t>& in_entropy, ::aidl::android::system::keystore2::KeyMetadata* _aidl_return) override {
    return _impl->generateKey(in_key, in_attestationKey, in_params, in_flags, in_entropy, _aidl_return);
  }
  ::ndk::ScopedAStatus importKey(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, const std::optional<::aidl::android::system::keystore2::KeyDescriptor>& in_attestationKey, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_params, int32_t in_flags, const std::vector<uint8_t>& in_keyData, ::aidl::android::system::keystore2::KeyMetadata* _aidl_return) override {
    return _impl->importKey(in_key, in_attestationKey, in_params, in_flags, in_keyData, _aidl_return);
  }
  ::ndk::ScopedAStatus importWrappedKey(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, const ::aidl::android::system::keystore2::KeyDescriptor& in_wrappingKey, const std::optional<std::vector<uint8_t>>& in_maskingKey, const std::vector<::aidl::android::hardware::security::keymint::KeyParameter>& in_params, const std::vector<::aidl::android::system::keystore2::AuthenticatorSpec>& in_authenticators, ::aidl::android::system::keystore2::KeyMetadata* _aidl_return) override {
    return _impl->importWrappedKey(in_key, in_wrappingKey, in_maskingKey, in_params, in_authenticators, _aidl_return);
  }
  ::ndk::ScopedAStatus convertStorageKeyToEphemeral(const ::aidl::android::system::keystore2::KeyDescriptor& in_storageKey, ::aidl::android::system::keystore2::EphemeralStorageKeyResponse* _aidl_return) override {
    return _impl->convertStorageKeyToEphemeral(in_storageKey, _aidl_return);
  }
  ::ndk::ScopedAStatus deleteKey(const ::aidl::android::system::keystore2::KeyDescriptor& in_key) override {
    return _impl->deleteKey(in_key);
  }
protected:
private:
  std::shared_ptr<IKeystoreSecurityLevel> _impl;
};

}  // namespace keystore2
}  // namespace system
}  // namespace android
}  // namespace aidl
