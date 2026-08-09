"""keystork -- drive a remote Android device's keystore2 over IP.

    >>> import keystork
    >>> with keystork.Session(uid=10123) as ks:
    ...     for key in ks.list():
    ...         print(key)

The daemon on the device is deliberately dumb: it makes one keystore2 Binder
call as the session's UID and hands the raw bytes back. Everything that is
interpretation -- naming enum values, pagination, typed errors -- lives here.
"""

from .enums import BinderException, BinderStatus, Domain, ErrorCode, ResponseCode, name_of
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
    KeyDescriptor,
    Session,
)

__version__ = "0.1.0"

__all__ = [
    "BinderException",
    "BinderStatus",
    "ConnectionClosed",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "Domain",
    "ErrorCode",
    "IdentityError",
    "KeyDescriptor",
    "KeyMintError",
    "KeystoreError",
    "KeystorkError",
    "MIN_INTERFACE_VERSION",
    "PROTOCOL_VERSION",
    "ProtocolError",
    "ResponseCode",
    "ServiceError",
    "Session",
    "TransactionError",
    "UnsupportedByDevice",
    "name_of",
]
