"""Name tables for every enum the wire carries as a bare integer.

The wire speaks KeyMint's raw integers and the server never names anything, so
these tables are the single place a value becomes a word. They are transcribed
from the vendored AIDL stubs (keystore2 V6 / KeyMint V5) and from the NDK's
``binder_status.h``.

Every lookup goes through :func:`name_of`, which never raises: a device running
a newer KeyMint than these tables know about must produce a readable
``UNKNOWN(-1234)`` rather than an exception.
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
    """``android.system.keystore2.Domain``.

    ``APP`` scopes to the calling UID and ignores ``nspace``; ``SELINUX`` uses
    ``nspace`` as the SELinux namespace; ``GRANT`` and ``KEY_ID`` address a key
    by number; ``BLOB`` carries the key material inline.
    """

    APP = 0
    GRANT = 1
    SELINUX = 2
    BLOB = 3
    KEY_ID = 4


class ResponseCode(IntEnum):
    """``android.system.keystore2.ResponseCode``, as of interface V6.

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
    """``android.hardware.security.keymint.ErrorCode``, as of KeyMint V5.

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
    """``binder_status_t`` from the NDK's ``android/binder_status.h``.

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
    """``binder_exception_t`` from the NDK's ``android/binder_status.h``."""

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
