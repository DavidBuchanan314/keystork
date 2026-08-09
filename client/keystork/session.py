"""Sessions and the calls you make on them.

A connection *is* a session: constructing a `Session` opens the socket, and the
daemon forks a child that permanently drops to the session's UID, so the UID is
fixed at handshake time and can never change. Acting as a second UID means
opening a second session.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterator, List, Optional

from . import errors
from ._proto import keystork_pb2 as pb
from .enums import Domain, name_of
from .transport import Transport

PROTOCOL_VERSION = pb.PROTOCOL_VERSION_1

#: Where ``adb forward tcp:9432 localabstract:keystork`` puts the daemon.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9432

#: Socket timeout, in seconds. Applies to the connect and to every read, so it
#: bounds a single round-trip rather than the session as a whole.
DEFAULT_TIMEOUT = 30.0

#: Minimum ``keystore2`` interface version each call needs. The daemon is built
#: against the newest frozen interface and reports what the device actually
#: implements, so this table is what turns "too new for this device" into a
#: sentence instead of a bare ``UNKNOWN_TRANSACTION``.
MIN_INTERFACE_VERSION = {
    "listEntries": 1,
    "listEntriesBatched": 3,
    "getNumberOfEntries": 3,
    "getSupplementaryAttestationInfo": 5,
}


@dataclass(frozen=True)
class KeyDescriptor:
    """``android.system.keystore2.KeyDescriptor``.

    Which fields carry meaning depends on ``domain``: ``APP`` and ``SELINUX``
    keys are named by ``alias``, ``GRANT`` and ``KEY_ID`` keys are numbered by
    ``nspace``, and a ``BLOB`` key carries its material in ``blob``.
    """

    domain: Domain
    nspace: int
    alias: Optional[str] = None
    blob: Optional[bytes] = None

    @classmethod
    def _from_wire(cls, wire: pb.KeyDescriptor) -> "KeyDescriptor":
        try:
            domain = Domain(wire.domain)
        except ValueError:
            # A domain this client does not know is worth surfacing verbatim
            # rather than rejecting; the raw int is still usable.
            domain = wire.domain  # type: ignore[assignment]
        return cls(
            domain=domain,
            nspace=wire.nspace,
            alias=wire.alias if wire.HasField("alias") else None,
            blob=wire.blob if wire.HasField("blob") else None,
        )

    def __str__(self) -> str:
        domain = name_of(Domain, int(self.domain))
        if self.alias is not None:
            return f"{domain}:{self.nspace}:{self.alias}"
        if self.blob is not None:
            return f"{domain}:{self.nspace}:<{len(self.blob)}-byte blob>"
        return f"{domain}:{self.nspace}"


class Session:
    """One UID-scoped session. Use it as a context manager.

    Constructing one opens the connection and completes the handshake, so the
    session is live -- or has raised -- by the time you have the object.

    >>> with Session(uid=10123) as ks:
    ...     for key in ks.list():
    ...         print(key)
    """

    def __init__(
        self,
        uid: int,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        timeout: Optional[float] = DEFAULT_TIMEOUT,
    ) -> None:
        if uid < 0:
            raise ValueError(f"uid must be non-negative, got {uid}")

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise errors.ConnectionClosed(
                f"could not reach keystorkd at {host}:{port}: {exc} "
                f"(is `adb forward tcp:{port} localabstract:keystork` running?)"
            ) from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        self._transport = Transport(sock)
        self._uid = uid
        self._interface_version = 0
        self._handshake()

    # -- properties ---------------------------------------------------------

    @property
    def uid(self) -> int:
        """The UID every call in this session runs as."""
        return self._uid

    @property
    def interface_version(self) -> int:
        """What the device's keystore2 reports from ``getInterfaceVersion()``."""
        return self._interface_version

    def supports(self, call: str) -> bool:
        """Whether this device's keystore2 implements `call`."""
        return self._interface_version >= MIN_INTERFACE_VERSION[call]

    def require(self, call: str) -> None:
        """Raise :class:`~keystork.errors.UnsupportedByDevice` unless `call` exists."""
        required = MIN_INTERFACE_VERSION[call]
        if self._interface_version < required:
            raise errors.UnsupportedByDevice(call, required, self._interface_version)

    # -- calls --------------------------------------------------------------

    def list(
        self,
        domain: int = Domain.APP,
        nspace: int = 0,
        *,
        batched: Optional[bool] = None,
        starting_past_alias: Optional[str] = None,
    ) -> List[KeyDescriptor]:
        """List the keys visible to this session's UID.

        ``domain=APP`` scopes to the UID itself and ignores ``nspace``; a
        ``SELINUX`` listing uses ``nspace`` as the namespace.

        By default this uses ``listEntriesBatched`` where the device has it and
        walks every page, falling back to the deprecated one-shot
        ``listEntries`` on older devices. Pass ``batched`` to force either.
        """
        if batched is None:
            batched = self.supports("listEntriesBatched")

        if not batched:
            if starting_past_alias is not None:
                raise ValueError("starting_past_alias only applies to a batched listing")
            self.require("listEntries")
            return self._list_page(domain, nspace, batched=False, cursor=None)

        self.require("listEntriesBatched")
        return list(self.iter_list(domain, nspace, starting_past_alias=starting_past_alias))

    def iter_list(
        self,
        domain: int = Domain.APP,
        nspace: int = 0,
        *,
        starting_past_alias: Optional[str] = None,
    ) -> Iterator[KeyDescriptor]:
        """Stream a batched listing page by page, rather than buffering it all.

        Always uses ``listEntriesBatched``; the pagination loop lives here in
        the client, so each page is exactly one round-trip and one keystore2
        call.
        """
        self.require("listEntriesBatched")
        cursor = starting_past_alias

        while True:
            page = self._list_page(domain, nspace, batched=True, cursor=cursor)
            if not page:
                return
            yield from page

            # keystore2 resumes strictly *after* an alias, so the cursor is the
            # last alias of the page. Without one there is nothing to resume
            # from and the page has to be the last.
            last_alias = page[-1].alias
            if last_alias is None or last_alias == cursor:
                return
            cursor = last_alias

    # -- plumbing -----------------------------------------------------------

    def _list_page(
        self, domain: int, nspace: int, *, batched: bool, cursor: Optional[str]
    ) -> List[KeyDescriptor]:
        request = pb.ListRequest(domain=int(domain), nspace=nspace, batched=batched)
        if cursor is not None:
            request.starting_past_alias = cursor

        response = self._exchange(pb.Request(list=request))
        if response.WhichOneof("body") != "list":
            raise errors.ProtocolError(
                f"expected a list response, got {response.WhichOneof('body')!r}"
            )
        return [KeyDescriptor._from_wire(entry) for entry in response.list.entries]

    def _handshake(self) -> None:
        handshake = pb.Handshake(protocol_version=PROTOCOL_VERSION, uid=self._uid)
        self._transport.send(handshake)

        ack = self._transport.recv(pb.HandshakeAck())
        if ack.HasField("error"):
            self.close()
            raise errors.from_wire(ack.error)
        if ack.protocol_version != PROTOCOL_VERSION:
            self.close()
            raise errors.ProtocolError(
                f"daemon speaks protocol version {ack.protocol_version}, "
                f"this client speaks {PROTOCOL_VERSION}"
            )
        self._interface_version = ack.keystore_interface_version

    def _exchange(self, request: pb.Request) -> pb.Response:
        """One request, one response. The session allows nothing in between."""
        self._transport.send(request)
        response = self._transport.recv(pb.Response())
        if response.WhichOneof("body") == "error":
            raise errors.from_wire(response.error)
        return response

    def close(self) -> None:
        """End the session. The daemon's child exits when the socket closes."""
        self._transport.close()

    @property
    def closed(self) -> bool:
        return self._transport.closed

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else f"keystore2 V{self._interface_version}"
        return f"<keystork.Session uid={self._uid} {state}>"
