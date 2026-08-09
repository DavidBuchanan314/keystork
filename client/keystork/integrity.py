"""Talking to our own code running inside an app's process.

`Connection.open_integrity_session` launches the app with its own code taken
off every classpath in the process before a line of it ran, so what answers
here is ours -- but the process is the app's, at the app's UID and with its
package and signing certificate, which is what Play Integrity identifies the
caller by.

The daemon relays these messages without reading them; they are a contract
between this module and the Java in the app.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Tuple

from . import errors
from ._proto import keystork_pb2 as pb

if TYPE_CHECKING:
    from .connection import Connection

# A token request is the app talking to Play over the network, so it is bounded
# by that rather than by anything local. Preparing a Standard provider is the
# slowest of them.
INTEGRITY_TIMEOUT = 120.0


class IntegritySession:
    """A conversation with our own code, running inside an app's process.

    >>> from keystork.util.packages import resolve_uid
    >>> with device.connect() as conn:
    ...     uid = resolve_uid(conn, "com.example.app")
    ...     with conn.open_integrity_session("com.example.app", uid) as integrity:
    ...         nonce = base64.urlsafe_b64encode(os.urandom(32)).decode()
    ...         token = integrity.classic(nonce)

    The app lives exactly as long as this session. Closing it -- or dropping
    the connection -- ends the process, which is deliberate: nothing else on
    the device knows the process is there, so a survivor would be a process
    with no owner holding an app's identity.

    `Connection.open_integrity_session` is the only way in.
    """

    def __init__(self) -> None:
        raise TypeError("open a session with Connection.open_integrity_session()")

    @classmethod
    def _attach(
        cls, connection: "Connection", package: str, opened: pb.IntegritySessionOpened
    ) -> "IntegritySession":
        """Wrap a connection that has already transitioned, without dialing."""
        session = cls.__new__(cls)
        session._connection = connection
        session._transport = connection._transport
        session._package = package
        session._opened = opened
        return session

    # -- properties ---------------------------------------------------------

    @property
    def package(self) -> str:
        """The app whose process this session is talking to."""
        return self._package

    @property
    def pid(self) -> int:
        """That process, on the device."""
        return self._opened.pid

    @property
    def uid(self) -> int:
        """The UID it runs as, which is the app's."""
        return self._opened.uid

    @property
    def steps(self) -> Tuple[int, int]:
        """What the injection cost in stepped syscalls: to the runtime, then to the bind."""
        return (self._opened.arm_steps, self._opened.bind_steps)

    # -- calls --------------------------------------------------------------

    def classic(
        self,
        nonce: str,
        *,
        cloud_project_number: Optional[int] = None,
    ) -> str:
        """Request a classic integrity token. Returns it as the API gave it.

        `nonce` reaches the API exactly as given, and is yours to build: it
        must be URL-safe base64, unwrapped, decoding to 16..500 bytes. Nothing
        here encodes, pads or trims it, because it is the value the token is
        bound to and the one you will check the verdict against -- a client
        that rewrote it would be handing you back something you never sent.

        (Play echoes the nonce in requestDetails.nonce re-encoded from the
        bytes it decoded, so compare decoded bytes rather than strings if you
        did not pad it the same way.)

        A nonce the API will not take comes back as an `IntegrityError` naming
        its own code -- NONCE_TOO_SHORT, NONCE_IS_NOT_BASE64 -- rather than
        being second-guessed here.

        `cloud_project_number` is only needed for an app Google Play does not
        know; the ordinary case is the app's own linked project, which the API
        finds for itself.

        The token is a JWE. Its verdicts are readable only by Play, or by
        whoever holds the app's decryption keys -- nothing here looks inside.
        """
        request = pb.ClassicTokenRequest(nonce=nonce)
        if cloud_project_number is not None:
            request.cloud_project_number = cloud_project_number
        return self._exchange(pb.IntegrityRequest(classic=request)).token.token

    def prepare_standard(self, cloud_project_number: int) -> None:
        """Prepare the Standard-mode token provider. Slow, and done once.

        The provider it builds stays warm in the app for the rest of the
        session, which is the reason this is a session at all.
        """
        self._exchange(
            pb.IntegrityRequest(
                prepare_standard=pb.PrepareStandardRequest(
                    cloud_project_number=cloud_project_number
                )
            )
        )

    def standard(self, request_hash: str) -> str:
        """Issue a Standard-mode token from the prepared provider.

        `request_hash` is bound into the token and is yours to choose --
        typically a digest of whatever the token is vouching for. Call
        `prepare_standard` first; the app has nothing to issue from otherwise.
        """
        return self._exchange(
            pb.IntegrityRequest(standard=pb.StandardTokenRequest(request_hash=request_hash))
        ).token.token

    # -- plumbing -----------------------------------------------------------

    def _exchange(self, request: pb.IntegrityRequest) -> pb.IntegrityResponse:
        """One request, one response. The session allows nothing in between."""
        self._transport.send(request)
        # A token request talks to Play over the network, which is slower than
        # anything else in this protocol and is the app waiting, not us.
        with self._transport.deadline(INTEGRITY_TIMEOUT):
            response = self._transport.recv(pb.IntegrityResponse())
        if response.WhichOneof("body") == "error":
            raise errors.from_wire(response.error)
        return response

    def close(self) -> None:
        """End the session, the connection it took over, and the app."""
        self._connection.close()

    @property
    def closed(self) -> bool:
        return self._transport.closed

    def __enter__(self) -> "IntegritySession":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else f"pid {self.pid}"
        return f"<keystork.IntegritySession {self._package} {state}>"
