/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/IKeyMintOperation.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/IKeyMintOperation.aidl
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
#include <android/binder_ibinder_platform.h>
#include <android/binder_interface_utils.h>
#include <android/binder_parcel_platform.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/secureclock/TimeStampToken.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::hardware::security::keymint {
class HardwareAuthToken;
}  // namespace aidl::android::hardware::security::keymint
namespace aidl::android::hardware::security::secureclock {
class TimeStampToken;
}  // namespace aidl::android::hardware::security::secureclock
namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
class IKeyMintOperationDelegator;

class IKeyMintOperation : public ::ndk::ICInterface {
public:
  typedef IKeyMintOperationDelegator DefaultDelegator;
  static const char* descriptor;
  IKeyMintOperation();
  virtual ~IKeyMintOperation();

  static inline const int32_t version = 5;
  static inline const std::string hash = "177877c3782ff5543c231b8616f1ee6a300f810d";
  static constexpr uint32_t TRANSACTION_updateAad = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_update = FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_finish = FIRST_CALL_TRANSACTION + 2;
  static constexpr uint32_t TRANSACTION_abort = FIRST_CALL_TRANSACTION + 3;

  static std::shared_ptr<IKeyMintOperation> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IKeyMintOperation>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IKeyMintOperation>* instance);
  virtual ::ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& in_input, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timeStampToken) = 0;
  virtual ::ndk::ScopedAStatus update(const std::vector<uint8_t>& in_input, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timeStampToken, std::vector<uint8_t>* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& in_input, const std::optional<std::vector<uint8_t>>& in_signature, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timestampToken, const std::optional<std::vector<uint8_t>>& in_confirmationToken, std::vector<uint8_t>* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus abort() = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
};
class IKeyMintOperationDefault : public IKeyMintOperation {
public:
  ::ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& in_input, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timeStampToken) override;
  ::ndk::ScopedAStatus update(const std::vector<uint8_t>& in_input, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timeStampToken, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& in_input, const std::optional<std::vector<uint8_t>>& in_signature, const std::optional<::aidl::android::hardware::security::keymint::HardwareAuthToken>& in_authToken, const std::optional<::aidl::android::hardware::security::secureclock::TimeStampToken>& in_timestampToken, const std::optional<std::vector<uint8_t>>& in_confirmationToken, std::vector<uint8_t>* _aidl_return) override;
  ::ndk::ScopedAStatus abort() override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace keymint
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
