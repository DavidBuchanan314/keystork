"""Name tables for every enum the wire carries as a bare integer.

The wire speaks KeyMint's raw integers and the server never names anything, so
these tables are the single place a value becomes a word. They are transcribed
from the vendored AIDL stubs (keystore2 V6 / KeyMint V5) and from the NDK's
`binder_status.h`.

Every lookup goes through `name_of`, which never raises: a device running
a newer KeyMint than these tables know about must produce a readable
`UNKNOWN(-1234)` rather than an exception.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Type


def name_of(table: Type[IntEnum], value: int) -> str:
    """Name `value` in `table`, tolerating values the table has never heard of."""
    try:
        return table(value).name
    except ValueError:
        return f"UNKNOWN({value})"


class Domain(IntEnum):
    """`android.system.keystore2.Domain`.

    `APP` scopes to the calling UID and ignores `nspace`; `SELINUX` uses
    `nspace` as the SELinux namespace; `GRANT` and `KEY_ID` address a key
    by number; `BLOB` carries the key material inline.
    """

    APP = 0
    GRANT = 1
    SELINUX = 2
    BLOB = 3
    KEY_ID = 4


class ResponseCode(IntEnum):
    """`android.system.keystore2.ResponseCode`, as of interface V6.

    These arrive as *positive* service-specific error codes.
    """

    LOCKED = 2
    UNINITIALIZED = 3
    SYSTEM_ERROR = 4
    PERMISSION_DENIED = 6
    KEY_NOT_FOUND = 7
    VALUE_CORRUPTED = 8
    KEY_PERMANENTLY_INVALIDATED = 17
    BACKEND_BUSY = 18
    OPERATION_BUSY = 19
    INVALID_ARGUMENT = 20
    TOO_MUCH_DATA = 21
    OUT_OF_KEYS = 22  # deprecated in favour of the OUT_OF_KEYS_* codes below
    OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE = 23
    OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY = 24
    OUT_OF_KEYS_TRANSIENT_ERROR = 25
    OUT_OF_KEYS_PERMANENT_ERROR = 26
    GET_ATTESTATION_APPLICATION_ID_FAILED = 27
    INFO_NOT_AVAILABLE = 28
    TOO_MANY_APP_KEYS = 29
    TOO_MANY_APP_KEYS_SDK37 = 30


class ErrorCode(IntEnum):
    """`android.hardware.security.keymint.ErrorCode`, as of KeyMint V5.

    These arrive as *negative* service-specific error codes: keystore2 embeds a
    KeyMint failure by passing its code through unchanged, and the sign is what
    separates the two error spaces.
    """

    OK = 0
    ROOT_OF_TRUST_ALREADY_SET = -1
    UNSUPPORTED_PURPOSE = -2
    INCOMPATIBLE_PURPOSE = -3
    UNSUPPORTED_ALGORITHM = -4
    INCOMPATIBLE_ALGORITHM = -5
    UNSUPPORTED_KEY_SIZE = -6
    UNSUPPORTED_BLOCK_MODE = -7
    INCOMPATIBLE_BLOCK_MODE = -8
    UNSUPPORTED_MAC_LENGTH = -9
    UNSUPPORTED_PADDING_MODE = -10
    INCOMPATIBLE_PADDING_MODE = -11
    UNSUPPORTED_DIGEST = -12
    INCOMPATIBLE_DIGEST = -13
    INVALID_EXPIRATION_TIME = -14
    INVALID_USER_ID = -15
    INVALID_AUTHORIZATION_TIMEOUT = -16
    UNSUPPORTED_KEY_FORMAT = -17
    INCOMPATIBLE_KEY_FORMAT = -18
    UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19
    UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20
    INVALID_INPUT_LENGTH = -21
    KEY_EXPORT_OPTIONS_INVALID = -22
    DELEGATION_NOT_ALLOWED = -23
    KEY_NOT_YET_VALID = -24
    KEY_EXPIRED = -25
    KEY_USER_NOT_AUTHENTICATED = -26
    OUTPUT_PARAMETER_NULL = -27
    INVALID_OPERATION_HANDLE = -28
    INSUFFICIENT_BUFFER_SPACE = -29
    VERIFICATION_FAILED = -30
    TOO_MANY_OPERATIONS = -31
    UNEXPECTED_NULL_POINTER = -32
    INVALID_KEY_BLOB = -33
    IMPORTED_KEY_NOT_ENCRYPTED = -34
    IMPORTED_KEY_DECRYPTION_FAILED = -35
    IMPORTED_KEY_NOT_SIGNED = -36
    IMPORTED_KEY_VERIFICATION_FAILED = -37
    INVALID_ARGUMENT = -38
    UNSUPPORTED_TAG = -39
    INVALID_TAG = -40
    MEMORY_ALLOCATION_FAILED = -41
    IMPORT_PARAMETER_MISMATCH = -44
    SECURE_HW_ACCESS_DENIED = -45
    OPERATION_CANCELLED = -46
    CONCURRENT_ACCESS_CONFLICT = -47
    SECURE_HW_BUSY = -48
    SECURE_HW_COMMUNICATION_FAILED = -49
    UNSUPPORTED_EC_FIELD = -50
    MISSING_NONCE = -51
    INVALID_NONCE = -52
    MISSING_MAC_LENGTH = -53
    KEY_RATE_LIMIT_EXCEEDED = -54
    CALLER_NONCE_PROHIBITED = -55
    KEY_MAX_OPS_EXCEEDED = -56
    INVALID_MAC_LENGTH = -57
    MISSING_MIN_MAC_LENGTH = -58
    UNSUPPORTED_MIN_MAC_LENGTH = -59
    UNSUPPORTED_KDF = -60
    UNSUPPORTED_EC_CURVE = -61
    KEY_REQUIRES_UPGRADE = -62
    ATTESTATION_CHALLENGE_MISSING = -63
    KEYMINT_NOT_CONFIGURED = -64
    ATTESTATION_APPLICATION_ID_MISSING = -65
    CANNOT_ATTEST_IDS = -66
    ROLLBACK_RESISTANCE_UNAVAILABLE = -67
    HARDWARE_TYPE_UNAVAILABLE = -68
    PROOF_OF_PRESENCE_REQUIRED = -69
    CONCURRENT_PROOF_OF_PRESENCE_REQUESTED = -70
    NO_USER_CONFIRMATION = -71
    DEVICE_LOCKED = -72
    EARLY_BOOT_ENDED = -73
    ATTESTATION_KEYS_NOT_PROVISIONED = -74
    ATTESTATION_IDS_NOT_PROVISIONED = -75
    INVALID_OPERATION = -76
    STORAGE_KEY_UNSUPPORTED = -77
    INCOMPATIBLE_MGF_DIGEST = -78
    UNSUPPORTED_MGF_DIGEST = -79
    MISSING_NOT_BEFORE = -80
    MISSING_NOT_AFTER = -81
    MISSING_ISSUER_SUBJECT = -82
    INVALID_ISSUER_SUBJECT = -83
    BOOT_LEVEL_EXCEEDED = -84
    HARDWARE_NOT_YET_AVAILABLE = -85
    MODULE_HASH_ALREADY_SET = -86
    UNSUPPORTED_ML_DSA_VARIANT = -87
    UNIMPLEMENTED = -100
    VERSION_MISMATCH = -101
    UNKNOWN_ERROR = -1000


class BinderStatus(IntEnum):
    """`binder_status_t` from the NDK's `android/binder_status.h`.

    Mostly negative errnos, so the values are Linux's.
    """

    STATUS_OK = 0
    STATUS_UNKNOWN_ERROR = -2147483648  # INT32_MIN
    STATUS_NO_MEMORY = -12  # -ENOMEM
    STATUS_INVALID_OPERATION = -38  # -ENOSYS
    STATUS_BAD_VALUE = -22  # -EINVAL
    STATUS_BAD_TYPE = -2147483647
    STATUS_NAME_NOT_FOUND = -2  # -ENOENT
    STATUS_PERMISSION_DENIED = -1  # -EPERM
    STATUS_NO_INIT = -19  # -ENODEV
    STATUS_ALREADY_EXISTS = -17  # -EEXIST
    STATUS_DEAD_OBJECT = -32  # -EPIPE
    STATUS_FAILED_TRANSACTION = -2147483646
    STATUS_BAD_INDEX = -75  # -EOVERFLOW
    STATUS_NOT_ENOUGH_DATA = -61  # -ENODATA
    STATUS_WOULD_BLOCK = -11  # -EWOULDBLOCK
    STATUS_TIMED_OUT = -110  # -ETIMEDOUT
    STATUS_UNKNOWN_TRANSACTION = -74  # -EBADMSG
    STATUS_FDS_NOT_ALLOWED = -2147483641
    STATUS_UNEXPECTED_NULL = -2147483640


class BinderException(IntEnum):
    """`binder_exception_t` from the NDK's `android/binder_status.h`."""

    EX_NONE = 0
    EX_SECURITY = -1
    EX_BAD_PARCELABLE = -2
    EX_ILLEGAL_ARGUMENT = -3
    EX_NULL_POINTER = -4
    EX_ILLEGAL_STATE = -5
    EX_NETWORK_MAIN_THREAD = -6
    EX_UNSUPPORTED_OPERATION = -7
    EX_SERVICE_SPECIFIC = -8
    EX_PARCELABLE = -9
    EX_TRANSACTION_FAILED = -129


class IntegrityErrorCode(IntEnum):
    """The Play Integrity SDK's own IntegrityErrorCode.

    Not a keystore2 or KeyMint enum at all -- it is raised inside the app and
    passed through the daemon untouched -- but it is a wire integer that wants
    a name, which is what this module is for. Documented at
    developer.android.com/google/play/integrity/reference, under
    IntegrityErrorCode.
    """

    API_NOT_AVAILABLE = -1
    PLAY_STORE_NOT_FOUND = -2
    NETWORK_ERROR = -3
    PLAY_STORE_ACCOUNT_NOT_FOUND = -4
    APP_NOT_INSTALLED = -5
    PLAY_SERVICES_NOT_FOUND = -6
    APP_UID_MISMATCH = -7
    TOO_MANY_REQUESTS = -8
    CANNOT_BIND_TO_SERVICE = -9
    NONCE_TOO_SHORT = -10
    NONCE_TOO_LONG = -11
    GOOGLE_SERVER_UNAVAILABLE = -12
    NONCE_IS_NOT_BASE64 = -13
    PLAY_STORE_VERSION_OUTDATED = -14
    PLAY_SERVICES_VERSION_OUTDATED = -15
    CLOUD_PROJECT_NUMBER_IS_INVALID = -16
    REQUEST_HASH_TOO_LONG = -17
    CLIENT_TRANSIENT_ERROR = -18
    INTEGRITY_TOKEN_PROVIDER_INVALID = -19
    INTERNAL_ERROR = -100


class Algorithm(IntEnum):
    """`android.hardware.security.keymint.Algorithm`."""

    RSA = 1
    EC = 3
    ML_DSA = 4
    AES = 32
    TRIPLE_DES = 33
    HMAC = 128


class BlockMode(IntEnum):
    """`android.hardware.security.keymint.BlockMode`."""

    ECB = 1
    CBC = 2
    CTR = 3
    GCM = 32


class PaddingMode(IntEnum):
    """`android.hardware.security.keymint.PaddingMode`."""

    NONE = 1
    RSA_OAEP = 2
    RSA_PSS = 3
    RSA_PKCS1_1_5_ENCRYPT = 4
    RSA_PKCS1_1_5_SIGN = 5
    PKCS7 = 64


class Digest(IntEnum):
    """`android.hardware.security.keymint.Digest`."""

    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA_2_224 = 3
    SHA_2_256 = 4
    SHA_2_384 = 5
    SHA_2_512 = 6


class KeyPurpose(IntEnum):
    """`android.hardware.security.keymint.KeyPurpose`.

    An operation names exactly one of these in `Tag.PURPOSE`; the key must
    have been generated allowing it.
    """

    ENCRYPT = 0
    DECRYPT = 1
    SIGN = 2
    VERIFY = 3
    WRAP_KEY = 5
    AGREE_KEY = 6
    ATTEST_KEY = 7


class EcCurve(IntEnum):
    """`android.hardware.security.keymint.EcCurve`."""

    P_224 = 0
    P_256 = 1
    P_384 = 2
    P_521 = 3
    CURVE_25519 = 4


class KeyOrigin(IntEnum):
    """`android.hardware.security.keymint.KeyOrigin`."""

    GENERATED = 0
    DERIVED = 1
    IMPORTED = 2
    RESERVED = 3
    SECURELY_IMPORTED = 4


class HardwareAuthenticatorType(IntEnum):
    """`android.hardware.security.keymint.HardwareAuthenticatorType`."""

    NONE = 0
    PASSWORD = 1
    FINGERPRINT = 2
    ANY = -1


class MlDsaVariant(IntEnum):
    """`android.hardware.security.keymint.MlDsaVariant`."""

    ML_DSA_65 = 1
    ML_DSA_87 = 2


class SecurityLevel(IntEnum):
    """`android.hardware.security.keymint.SecurityLevel`.

    Which backend to ask keystore2 for. `TRUSTED_ENVIRONMENT` is the ordinary
    hardware-backed choice; `STRONGBOX` needs a device that has one.
    """

    SOFTWARE = 0
    TRUSTED_ENVIRONMENT = 1
    STRONGBOX = 2
    KEYSTORE = 100


class TagType(IntEnum):
    """`android.hardware.security.keymint.TagType`.

    A KeyMint `Tag` carries its type in its top four bits, so
    `type_of_tag` recovers this from any tag -- including one these tables
    have never seen -- and that is what decides how a parameter is put on the
    wire.
    """

    INVALID = 0
    ENUM = 0x10000000
    ENUM_REP = 0x20000000
    UINT = 0x30000000
    UINT_REP = 0x40000000
    ULONG = 0x50000000
    DATE = 0x60000000
    BOOL = 0x70000000
    BIGNUM = -0x80000000
    BYTES = -0x70000000
    ULONG_REP = -0x60000000


class Tag(IntEnum):
    """`android.hardware.security.keymint.Tag`, as of KeyMint V5."""

    INVALID = 0
    PURPOSE = 536870913
    ALGORITHM = 268435458
    KEY_SIZE = 805306371
    BLOCK_MODE = 536870916
    DIGEST = 536870917
    PADDING = 536870918
    CALLER_NONCE = 1879048199
    MIN_MAC_LENGTH = 805306376
    EC_CURVE = 268435466
    ML_DSA_VARIANT = 268435467
    RSA_PUBLIC_EXPONENT = 1342177480
    INCLUDE_UNIQUE_ID = 1879048394
    RSA_OAEP_MGF_DIGEST = 536871115
    BOOTLOADER_ONLY = 1879048494
    ROLLBACK_RESISTANCE = 1879048495
    HARDWARE_TYPE = 268435760
    EARLY_BOOT_ONLY = 1879048497
    ACTIVE_DATETIME = 1610613136
    ORIGINATION_EXPIRE_DATETIME = 1610613137
    USAGE_EXPIRE_DATETIME = 1610613138
    MIN_SECONDS_BETWEEN_OPS = 805306771
    MAX_USES_PER_BOOT = 805306772
    USAGE_COUNT_LIMIT = 805306773
    USER_ID = 805306869
    USER_SECURE_ID = -1610612234
    NO_AUTH_REQUIRED = 1879048695
    USER_AUTH_TYPE = 268435960
    AUTH_TIMEOUT = 805306873
    ALLOW_WHILE_ON_BODY = 1879048698
    TRUSTED_USER_PRESENCE_REQUIRED = 1879048699
    TRUSTED_CONFIRMATION_REQUIRED = 1879048700
    UNLOCKED_DEVICE_REQUIRED = 1879048701
    APPLICATION_ID = -1879047591
    APPLICATION_DATA = -1879047492
    CREATION_DATETIME = 1610613437
    ORIGIN = 268436158
    ROOT_OF_TRUST = -1879047488
    OS_VERSION = 805307073
    OS_PATCHLEVEL = 805307074
    UNIQUE_ID = -1879047485
    ATTESTATION_CHALLENGE = -1879047484
    ATTESTATION_APPLICATION_ID = -1879047483
    ATTESTATION_ID_BRAND = -1879047482
    ATTESTATION_ID_DEVICE = -1879047481
    ATTESTATION_ID_PRODUCT = -1879047480
    ATTESTATION_ID_SERIAL = -1879047479
    ATTESTATION_ID_IMEI = -1879047478
    ATTESTATION_ID_MEID = -1879047477
    ATTESTATION_ID_MANUFACTURER = -1879047476
    ATTESTATION_ID_MODEL = -1879047475
    VENDOR_PATCHLEVEL = 805307086
    BOOT_PATCHLEVEL = 805307087
    DEVICE_UNIQUE_ATTESTATION = 1879048912
    IDENTITY_CREDENTIAL_KEY = 1879048913
    STORAGE_KEY = 1879048914
    ATTESTATION_ID_SECOND_IMEI = -1879047469
    MODULE_HASH = -1879047468
    ASSOCIATED_DATA = -1879047192
    NONCE = -1879047191
    MAC_LENGTH = 805307371
    RESET_SINCE_ID_ROTATION = 1879049196
    CONFIRMATION_TOKEN = -1879047187
    CERTIFICATE_SERIAL = -2147482642
    CERTIFICATE_SUBJECT = -1879047185
    CERTIFICATE_NOT_BEFORE = 1610613744
    CERTIFICATE_NOT_AFTER = 1610613745
    MAX_BOOT_LEVEL = 805307378


# The KeyMint enum each ENUM/ENUM_REP tag draws its values from. Only these
# tags need it: every other tag's type is recoverable from the tag itself.
TAG_ENUMS = {
    Tag.ALGORITHM: Algorithm,
    Tag.BLOCK_MODE: BlockMode,
    Tag.PADDING: PaddingMode,
    Tag.DIGEST: Digest,
    Tag.RSA_OAEP_MGF_DIGEST: Digest,
    Tag.EC_CURVE: EcCurve,
    Tag.ORIGIN: KeyOrigin,
    Tag.PURPOSE: KeyPurpose,
    Tag.USER_AUTH_TYPE: HardwareAuthenticatorType,
    Tag.HARDWARE_TYPE: SecurityLevel,
    Tag.ML_DSA_VARIANT: MlDsaVariant,
}


def type_of_tag(tag: int) -> TagType:
    """The `TagType` encoded in `tag`'s top four bits.

    Works for tags these tables have never seen, which is the point: a new
    KeyMint tag still round-trips without a client update.
    """
    masked = tag & 0xF0000000
    if masked >= 0x80000000:
        masked -= 0x100000000
    return TagType(masked)
