"""keystork -- drive a remote Android device's keystore2 over IP.

    >>> import keystork
    >>> device = keystork.Device()
    >>> with device.connect() as conn:
    ...     with conn.open_keystore_session(uid=10123) as ks:
    ...         for key in ks.list():
    ...             print(key)

A device is an address, a connection is a conversation with the daemon, and a
session is a connection that has been handed over. Each is reached by a verb on
the one before it, and :class:`Device` is the only one you construct.

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
    CommandFailed,
    IdentityError,
    IntegrityError,
    KeyMintError,
    KeystoreError,
    KeystorkError,
    ProtocolError,
    ServiceError,
    TransactionError,
    UnsupportedByDevice,
)
from .process import (
    CHUNK_BYTES,
    DEFAULT_WINDOW,
    ESCAPE,
    STDERR,
    STDOUT,
    ExitStatus,
    Process,
)
from .session import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEVICE_SHELL,
    MIN_INTERFACE_VERSION,
    PROTOCOL_VERSION,
    Authorization,
    Connection,
    Device,
    IntegritySession,
    KeystoreSession,
    KeyDescriptor,
    KeyMetadata,
    KeyParameter,
    Operation,
    OperationBegun,
    OperationResult,
    NONCE_LENGTHS,
    PACKAGES_LIST,
    READ_CHUNK_BYTES,
    USER_OFFSET,
    parse_packages_list,
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
    "CHUNK_BYTES",
    "CommandFailed",
    "Connection",
    "ConnectionClosed",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "DEFAULT_WINDOW",
    "DEVICE_SHELL",
    "Device",
    "Digest",
    "Domain",
    "ESCAPE",
    "EcCurve",
    "ErrorCode",
    "ExitStatus",
    "HardwareAuthenticatorType",
    "IdentityError",
    "IntegrityError",
    "IntegritySession",
    "KeyDescriptor",
    "KeyMetadata",
    "KeyMintError",
    "KeyOrigin",
    "KeyParameter",
    "KeyPurpose",
    "KeystoreError",
    "KeystoreSession",
    "KeystorkError",
    "MIN_INTERFACE_VERSION",
    "MlDsaVariant",
    "NONCE_LENGTHS",
    "Operation",
    "OperationBegun",
    "OperationResult",
    "PACKAGES_LIST",
    "PROTOCOL_VERSION",
    "PaddingMode",
    "Process",
    "ProtocolError",
    "READ_CHUNK_BYTES",
    "ResponseCode",
    "STDERR",
    "STDOUT",
    "SecurityLevel",
    "ServiceError",
    "TAG_ENUMS",
    "Tag",
    "TagType",
    "TransactionError",
    "USER_OFFSET",
    "UnsupportedByDevice",
    "name_of",
    "nonce_length",
    "operation_parameters",
    "parse_packages_list",
    "type_of_tag",
]
