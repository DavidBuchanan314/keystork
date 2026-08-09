"""Typed exceptions.

The server hands back ``{kind, code, message}`` and never interprets it. This
module is where a wire error becomes something with a name and a type you can
catch, per the sign-of-the-code rule: a positive service-specific code is a
keystore2 ``ResponseCode``, a negative one is an embedded KeyMint ``ErrorCode``.
"""

from __future__ import annotations

from .enums import BinderException, BinderStatus, ErrorCode, ResponseCode, name_of
from ._proto import keystork_pb2 as pb


class KeystorkError(Exception):
    """Base class for everything this library raises."""


class ConnectionClosed(KeystorkError):
    """The daemon hung up, or the connection was already closed locally."""


class ProtocolError(KeystorkError):
    """The exchange broke down: bad framing, a malformed or unexpected message.

    Also raised for the server's ``PROTOCOL`` errors, which mean the daemon
    could not act on what it was sent.
    """


class IdentityError(KeystorkError):
    """A command failed before it could do the thing it was for.

    The daemon could not become the requested UID, could not reach keystore2
    once it had, could not read a file, or could not exec a program. Carries
    the errno where one applies.
    """

    def __init__(self, message: str, errno: int = 0) -> None:
        super().__init__(message)
        self.errno = errno


class UnsupportedByDevice(KeystorkError):
    """This device's keystore2 is too old for the call you asked for.

    Raised from the client's capability table, before anything goes on the
    wire, so you get the version arithmetic instead of ``UNKNOWN_TRANSACTION``.
    """

    def __init__(self, call: str, required: int, actual: int) -> None:
        super().__init__(
            f"{call} requires keystore2 interface version {required}, "
            f"but this device reports V{actual}"
        )
        self.call = call
        self.required = required
        self.actual = actual


class TransactionError(KeystorkError):
    """The Binder transaction failed, so keystore2 never gave a verdict."""

    def __init__(self, status: int, exception_code: int, message: str) -> None:
        detail = (
            f"{name_of(BinderStatus, status)} ({status}) / "
            f"{name_of(BinderException, exception_code)} ({exception_code})"
        )
        if message:
            detail = f"{detail}: {message}"
        if status == BinderStatus.STATUS_UNKNOWN_TRANSACTION:
            # The capability table should have caught this first; reaching here
            # means its version data is behind the device.
            detail += (
                " -- the device's keystore2 does not implement this call; "
                "the client's capability table may be out of date"
            )
        super().__init__(detail)
        self.status = status
        self.exception_code = exception_code


class ServiceError(KeystorkError):
    """Base for the two service-specific error spaces."""

    def __init__(self, code: int, name: str, message: str) -> None:
        detail = f"{name} ({code})"
        if message:
            detail = f"{detail}: {message}"
        super().__init__(detail)
        self.code = code
        self.name = name


class KeystoreError(ServiceError):
    """keystore2 rejected the call. ``code`` is a positive ``ResponseCode``."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(code, name_of(ResponseCode, code), message)


class KeyMintError(ServiceError):
    """KeyMint rejected the call. ``code`` is a negative ``ErrorCode``."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(code, name_of(ErrorCode, code), message)


def from_wire(error: pb.Error) -> KeystorkError:
    """Build the exception a wire ``Error`` describes. Does not raise it."""
    kind = error.kind
    message = error.message

    if kind == pb.Error.SERVICE_SPECIFIC:
        # The sign is the discriminator: keystore2 embeds KeyMint failures by
        # passing their negative codes straight through.
        if error.code < 0:
            return KeyMintError(error.code, message)
        return KeystoreError(error.code, message)

    if kind == pb.Error.TRANSACTION:
        return TransactionError(error.code, error.exception_code, message)

    if kind == pb.Error.IDENTITY:
        return IdentityError(message or "session setup failed", error.code)

    if kind == pb.Error.PROTOCOL:
        return ProtocolError(message or "protocol error")

    return ProtocolError(f"server returned an unrecognized error kind {kind}: {message}")
