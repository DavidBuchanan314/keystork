/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 1 --hash cd55ca9963c6a57fa5f2f120a45c6e0c4fafb423 -t --stability vintf --min_sdk_version 30 --ninja -d out/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock-V1-ndk-source/gen/staging/android/hardware/security/secureclock/ISecureClock.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock-V1-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock-V1-ndk-source/gen/staging -Nhardware/interfaces/security/secureclock/aidl/aidl_api/android.hardware.security.secureclock/1 hardware/interfaces/security/secureclock/aidl/aidl_api/android.hardware.security.secureclock/1/android/hardware/security/secureclock/ISecureClock.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/security/secureclock/TimeStampToken.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::hardware::security::secureclock {
class TimeStampToken;
}  // namespace aidl::android::hardware::security::secureclock
namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace secureclock {
class ISecureClockDelegator;

class ISecureClock : public ::ndk::ICInterface {
public:
  typedef ISecureClockDelegator DefaultDelegator;
  static const char* descriptor;
  ISecureClock();
  virtual ~ISecureClock();

  static const char* TIME_STAMP_MAC_LABEL;
  static inline const int32_t version = 1;
  static inline const std::string hash = "cd55ca9963c6a57fa5f2f120a45c6e0c4fafb423";
  static constexpr uint32_t TRANSACTION_generateTimeStamp = FIRST_CALL_TRANSACTION + 0;

  static std::shared_ptr<ISecureClock> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<ISecureClock>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<ISecureClock>* instance);
  virtual ::ndk::ScopedAStatus generateTimeStamp(int64_t in_challenge, ::aidl::android::hardware::security::secureclock::TimeStampToken* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
};
class ISecureClockDefault : public ISecureClock {
public:
  ::ndk::ScopedAStatus generateTimeStamp(int64_t in_challenge, ::aidl::android::hardware::security::secureclock::TimeStampToken* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace secureclock
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
