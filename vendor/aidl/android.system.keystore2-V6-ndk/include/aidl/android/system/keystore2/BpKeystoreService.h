/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 6 --hash b115fcb5d111eb616a65f0f32e0c2cef131575ec -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint_interface/5/preprocessed.aidl --ninja -d out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging/android/system/keystore2/IKeystoreService.cpp.d -h out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/include/staging -o out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen/staging -Nsystem/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6 system/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6/android/system/keystore2/IKeystoreService.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include "aidl/android/system/keystore2/IKeystoreService.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace system {
namespace keystore2 {
class BpKeystoreService : public ::ndk::BpCInterface<IKeystoreService> {
public:
  explicit BpKeystoreService(const ::ndk::SpAIBinder& binder);
  virtual ~BpKeystoreService();

  ::ndk::ScopedAStatus getSecurityLevel(::aidl::android::hardware::security::keymint::SecurityLevel in_securityLevel, std::shared_ptr<::aidl::android::system::keystore2::IKeystoreSecurityLevel>* _aidl_return) override;
  ::ndk::ScopedAStatus getKeyEntry(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, ::aidl::android::system::keystore2::KeyEntryResponse* _aidl_return) override;
  ::ndk::ScopedAStatus updateSubcomponent(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, const std::optional<std::vector<uint8_t>>& in_publicCert, const std::optional<std::vector<uint8_t>>& in_certificateChain) override;
  ::ndk::ScopedAStatus listEntries(::aidl::android::system::keystore2::Domain in_domain, int64_t in_nspace, std::vector<::aidl::android::system::keystore2::KeyDescriptor>* _aidl_return) override __attribute__((deprecated("use listEntriesBatched instead.")));
  ::ndk::ScopedAStatus deleteKey(const ::aidl::android::system::keystore2::KeyDescriptor& in_key) override;
  ::ndk::ScopedAStatus grant(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, int32_t in_granteeUid, int32_t in_accessVector, ::aidl::android::system::keystore2::KeyDescriptor* _aidl_return) override;
  ::ndk::ScopedAStatus ungrant(const ::aidl::android::system::keystore2::KeyDescriptor& in_key, int32_t in_granteeUid) override;
  ::ndk::ScopedAStatus getNumberOfEntries(::aidl::android::system::keystore2::Domain in_domain, int64_t in_nspace, int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus listEntriesBatched(::aidl::android::system::keystore2::Domain in_domain, int64_t in_nspace, const std::optional<std::string>& in_startingPastAlias, std::vector<::aidl::android::system::keystore2::KeyDescriptor>* _aidl_return) override;
  ::ndk::ScopedAStatus getSupplementaryAttestationInfo(::aidl::android::hardware::security::keymint::Tag in_tag, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  int32_t _aidl_cached_version = -1;
  std::string _aidl_cached_hash = "-1";
  std::mutex _aidl_cached_hash_mutex;
};
}  // namespace keystore2
}  // namespace system
}  // namespace android
}  // namespace aidl
