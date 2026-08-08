/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 1 --hash cd55ca9963c6a57fa5f2f120a45c6e0c4fafb423 -t --stability vintf --min_sdk_version 30 --ninja -d out/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock-V1-ndk-source/gen/staging/android/hardware/security/secureclock/ISecureClock.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock-V1-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock-V1-ndk-source/gen/staging -Nhardware/interfaces/security/secureclock/aidl/aidl_api/android.hardware.security.secureclock/1 hardware/interfaces/security/secureclock/aidl/aidl_api/android.hardware.security.secureclock/1/android/hardware/security/secureclock/ISecureClock.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include "aidl/android/hardware/security/secureclock/ISecureClock.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace secureclock {
class BpSecureClock : public ::ndk::BpCInterface<ISecureClock> {
public:
  explicit BpSecureClock(const ::ndk::SpAIBinder& binder);
  virtual ~BpSecureClock();

  ::ndk::ScopedAStatus generateTimeStamp(int64_t in_challenge, ::aidl::android::hardware::security::secureclock::TimeStampToken* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  int32_t _aidl_cached_version = -1;
  std::string _aidl_cached_hash = "-1";
  std::mutex _aidl_cached_hash_mutex;
};
}  // namespace secureclock
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
