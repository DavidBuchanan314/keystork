"""keystork -- drive a remote Android device's keystore2 over IP.

    >>> import keystork
    >>> with keystork.Session(uid=10123) as ks:
    ...     for key in ks.list():
    ...         print(key)

The daemon on the device is deliberately dumb: it makes one keystore2 Binder
call as the session's UID and hands the raw bytes back. Everything that is
interpretation -- naming enum values, pagination, typed errors -- lives here.
"""

from .enums import (
    TAG_ENUMS,
    Algorithm,
    BinderException,
    BinderStatus,
    BlockMode,
    Digest,
    Domain,
    EcCurve,
    ErrorCode,
    HardwareAuthenticatorType,
    KeyOrigin,
    KeyPurpose,
    MlDsaVariant,
    PaddingMode,
    ResponseCode,
    SecurityLevel,
    Tag,
    TagType,
    name_of,
    type_of_tag,
)
from .errors import (
    ConnectionClosed,
    IdentityError,
    KeyMintError,
    KeystoreError,
    KeystorkError,
    ProtocolError,
    ServiceError,
    TransactionError,
    UnsupportedByDevice,
)
from .session import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    MIN_INTERFACE_VERSION,
    PROTOCOL_VERSION,
    Authorization,
    KeyDescriptor,
    KeyMetadata,
    KeyParameter,
    Operation,
    OperationBegun,
    OperationResult,
    NONCE_LENGTHS,
    Session,
    nonce_length,
    operation_parameters,
)

__version__ = "0.1.0"

__all__ = [
    "Algorithm",
    "Authorization",
    "BinderException",
    "BinderStatus",
    "BlockMode",
    "ConnectionClosed",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "Digest",
    "Domain",
    "EcCurve",
    "ErrorCode",
    "HardwareAuthenticatorType",
    "IdentityError",
    "KeyDescriptor",
    "KeyMetadata",
    "KeyMintError",
    "KeyOrigin",
    "KeyParameter",
    "KeyPurpose",
    "KeystoreError",
    "KeystorkError",
    "MIN_INTERFACE_VERSION",
    "MlDsaVariant",
    "NONCE_LENGTHS",
    "Operation",
    "OperationBegun",
    "OperationResult",
    "PROTOCOL_VERSION",
    "PaddingMode",
    "ProtocolError",
    "ResponseCode",
    "SecurityLevel",
    "ServiceError",
    "Session",
    "TAG_ENUMS",
    "Tag",
    "TagType",
    "TransactionError",
    "UnsupportedByDevice",
    "name_of",
    "nonce_length",
    "operation_parameters",
    "type_of_tag",
]
