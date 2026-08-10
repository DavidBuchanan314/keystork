"""keystork -- drive a remote Android device's keystore2 over IP.

    >>> import keystork
    >>> device = keystork.Device()
    >>> with device.connect() as conn:
    ...     with conn.open_keystore_session(10123) as ks:
    ...         for key in ks.list():
    ...             print(key)

A device is an address, a connection is a conversation with the daemon, and a
session is a connection that has been handed over. Each is reached by a verb on
the one before it, and `Device` is the only one you construct.

Identity is a UID throughout. Nothing here knows what a package is; that lives
in `keystork.util.packages`, whose `resolve_uid` turns a name into a number
over a connection that is still at the top level.

The daemon on the device is deliberately dumb: it makes one keystore2 Binder
call as the session's UID and hands the raw bytes back. Everything that is
interpretation -- naming enum values, pagination, typed errors -- lives here.
"""

from . import attestation
from .attestation import (
    ATTESTATION_OID,
    Attestation,
    AttestationApplicationId,
    AttestationError,
    PackageInfo,
    RootOfTrust,
)
from .connection import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEVICE_SHELL,
    PROTOCOL_VERSION,
    READ_CHUNK_BYTES,
    Connection,
    Device,
)
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
    IntegrityErrorCode,
    KeyOrigin,
    KeyPurpose,
    MlDsaVariant,
    PaddingMode,
    ResponseCode,
    SecurityLevel,
    Tag,
    TagType,
    VerifiedBootState,
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
from .integrity import INTEGRITY_TIMEOUT, IntegritySession
from .keystore import (
    DEFAULT_KEY_SIZES,
    MIN_INTERFACE_VERSION,
    NONCE_LENGTHS,
    RSA_PUBLIC_EXPONENT,
    Authorization,
    KeyDescriptor,
    KeyMetadata,
    KeyParameter,
    KeyRef,
    KeystoreSession,
    Operation,
    OperationBegun,
    OperationResult,
    generation_parameters,
    nonce_length,
    operation_parameters,
)
from .process import (
    CHUNK_BYTES,
    DEFAULT_WINDOW,
    ESCAPE,
    STDERR,
    STDOUT,
    ExitStatus,
    Process,
    local_window,
    stdin_is_tty,
)
from . import util
from .util.packages import (
    PACKAGES_LIST,
    PACKAGES_XML,
    USER_OFFSET,
    cert_hash,
    package_cert_hash,
    package_uids,
    parse_packages_list,
    parse_signing_certs,
    resolve_uid,
    signing_cert,
)

__version__ = "0.1.0"

__all__ = [
    "ATTESTATION_OID",
    "Algorithm",
    "Attestation",
    "AttestationApplicationId",
    "AttestationError",
    "Authorization",
    "BinderException",
    "BinderStatus",
    "BlockMode",
    "CHUNK_BYTES",
    "CommandFailed",
    "Connection",
    "ConnectionClosed",
    "DEFAULT_HOST",
    "DEFAULT_KEY_SIZES",
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
    "INTEGRITY_TIMEOUT",
    "IdentityError",
    "IntegrityError",
    "IntegrityErrorCode",
    "IntegritySession",
    "KeyDescriptor",
    "KeyMetadata",
    "KeyMintError",
    "KeyOrigin",
    "KeyParameter",
    "KeyPurpose",
    "KeyRef",
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
    "PACKAGES_XML",
    "PackageInfo",
    "PROTOCOL_VERSION",
    "PaddingMode",
    "Process",
    "ProtocolError",
    "READ_CHUNK_BYTES",
    "RSA_PUBLIC_EXPONENT",
    "ResponseCode",
    "RootOfTrust",
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
    "VerifiedBootState",
    "attestation",
    "cert_hash",
    "generation_parameters",
    "local_window",
    "name_of",
    "nonce_length",
    "operation_parameters",
    "package_cert_hash",
    "package_uids",
    "parse_packages_list",
    "parse_signing_certs",
    "resolve_uid",
    "signing_cert",
    "stdin_is_tty",
    "type_of_tag",
    "util",
]
