/*
 * This file is auto-generated.  DO NOT MODIFY.
 * Using: out/host/linux-x86/bin/aidl --lang=ndk --structured --version 5 --hash 177877c3782ff5543c231b8616f1ee6a300f810d -t --stability vintf --min_sdk_version 30 -pout/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock_interface/1/preprocessed.aidl --ninja -d out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging/android/hardware/security/keymint/KeyParameterValue.cpp.d -h out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/include/staging -o out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen/staging -Nhardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5 hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/5/android/hardware/security/keymint/KeyParameterValue.aidl
 *
 * DO NOT CHECK THIS FILE INTO A CODE TREE (e.g. git, etc..).
 * ALWAYS GENERATE THIS FILE FROM UPDATED AIDL COMPILER
 * AS A BUILD INTERMEDIATE ONLY. THIS IS NOT SOURCE CODE.
 */
#include "aidl/android/hardware/security/keymint/KeyParameterValue.h"

#include <cstdint>
#include <android/binder_parcel.h>
#include <android/binder_parcel_utils.h>
#include <android/binder_status.h>
#include <aidl/android/hardware/security/secureclock/BnSecureClock.h>
#include <aidl/android/hardware/security/secureclock/BpSecureClock.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>

namespace aidl {
namespace android {
namespace hardware {
namespace security {
namespace keymint {
const char* KeyParameterValue::descriptor = "android.hardware.security.keymint.KeyParameterValue";

binder_status_t KeyParameterValue::readFromParcel(const AParcel* _parcel) {
  binder_status_t _aidl_ret_status;
  int32_t _aidl_tag;
  if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_tag)) != STATUS_OK) return _aidl_ret_status;
  switch (static_cast<Tag>(_aidl_tag)) {
  case invalid: {
    int32_t _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<int32_t>) {
      set<invalid>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<invalid>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case algorithm: {
    ::aidl::android::hardware::security::keymint::Algorithm _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::Algorithm>) {
      set<algorithm>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<algorithm>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case blockMode: {
    ::aidl::android::hardware::security::keymint::BlockMode _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::BlockMode>) {
      set<blockMode>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<blockMode>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case paddingMode: {
    ::aidl::android::hardware::security::keymint::PaddingMode _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::PaddingMode>) {
      set<paddingMode>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<paddingMode>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case digest: {
    ::aidl::android::hardware::security::keymint::Digest _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::Digest>) {
      set<digest>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<digest>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case ecCurve: {
    ::aidl::android::hardware::security::keymint::EcCurve _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::EcCurve>) {
      set<ecCurve>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<ecCurve>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case origin: {
    ::aidl::android::hardware::security::keymint::KeyOrigin _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::KeyOrigin>) {
      set<origin>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<origin>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case keyPurpose: {
    ::aidl::android::hardware::security::keymint::KeyPurpose _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::KeyPurpose>) {
      set<keyPurpose>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<keyPurpose>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case hardwareAuthenticatorType: {
    ::aidl::android::hardware::security::keymint::HardwareAuthenticatorType _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::HardwareAuthenticatorType>) {
      set<hardwareAuthenticatorType>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<hardwareAuthenticatorType>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case securityLevel: {
    ::aidl::android::hardware::security::keymint::SecurityLevel _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::SecurityLevel>) {
      set<securityLevel>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<securityLevel>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case boolValue: {
    bool _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<bool>) {
      set<boolValue>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<boolValue>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case integer: {
    int32_t _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<int32_t>) {
      set<integer>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<integer>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case longInteger: {
    int64_t _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<int64_t>) {
      set<longInteger>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<longInteger>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case dateTime: {
    int64_t _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<int64_t>) {
      set<dateTime>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<dateTime>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case blob: {
    std::vector<uint8_t> _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<std::vector<uint8_t>>) {
      set<blob>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<blob>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case mlDsaVariant: {
    ::aidl::android::hardware::security::keymint::MlDsaVariant _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::security::keymint::MlDsaVariant>) {
      set<mlDsaVariant>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<mlDsaVariant>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  }
  return STATUS_BAD_VALUE;
}
binder_status_t KeyParameterValue::writeToParcel(AParcel* _parcel) const {
  binder_status_t _aidl_ret_status = ::ndk::AParcel_writeData(_parcel, static_cast<int32_t>(getTag()));
  if (_aidl_ret_status != STATUS_OK) return _aidl_ret_status;
  switch (getTag()) {
  case invalid: return ::ndk::AParcel_writeData(_parcel, get<invalid>());
  case algorithm: return ::ndk::AParcel_writeData(_parcel, get<algorithm>());
  case blockMode: return ::ndk::AParcel_writeData(_parcel, get<blockMode>());
  case paddingMode: return ::ndk::AParcel_writeData(_parcel, get<paddingMode>());
  case digest: return ::ndk::AParcel_writeData(_parcel, get<digest>());
  case ecCurve: return ::ndk::AParcel_writeData(_parcel, get<ecCurve>());
  case origin: return ::ndk::AParcel_writeData(_parcel, get<origin>());
  case keyPurpose: return ::ndk::AParcel_writeData(_parcel, get<keyPurpose>());
  case hardwareAuthenticatorType: return ::ndk::AParcel_writeData(_parcel, get<hardwareAuthenticatorType>());
  case securityLevel: return ::ndk::AParcel_writeData(_parcel, get<securityLevel>());
  case boolValue: return ::ndk::AParcel_writeData(_parcel, get<boolValue>());
  case integer: return ::ndk::AParcel_writeData(_parcel, get<integer>());
  case longInteger: return ::ndk::AParcel_writeData(_parcel, get<longInteger>());
  case dateTime: return ::ndk::AParcel_writeData(_parcel, get<dateTime>());
  case blob: return ::ndk::AParcel_writeData(_parcel, get<blob>());
  case mlDsaVariant: return ::ndk::AParcel_writeData(_parcel, get<mlDsaVariant>());
  }
  __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "can't reach here");
}

}  // namespace keymint
}  // namespace security
}  // namespace hardware
}  // namespace android
}  // namespace aidl
