"""Sessions and the calls you make on them.

A connection *is* a session: constructing a `Session` opens the socket, and the
daemon forks a child that permanently drops to the session's UID, so the UID is
fixed at handshake time and can never change. Acting as a second UID means
opening a second session.
"""

from __future__ import annotations

import base64
import contextlib
import socket
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

from . import errors
from ._proto import keystork_pb2 as pb
from .enums import (
    TAG_ENUMS,
    Algorithm,
    BlockMode,
    Digest,
    Domain,
    ErrorCode,
    KeyPurpose,
    PaddingMode,
    SecurityLevel,
    Tag,
    TagType,
    name_of,
    type_of_tag,
)
from .process import (
    DEFAULT_WINDOW,
    ESCAPE,
    ExitStatus,
    Process,
    local_window,
    stdin_is_tty,
)
from .transport import Transport

PROTOCOL_VERSION = pb.PROTOCOL_VERSION_1

# A token request is the app talking to Play over the network, so it is bounded
# by that rather than by anything local. Preparing a Standard provider is the
# slowest of them.
INTEGRITY_TIMEOUT = 120.0

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

    def _to_wire(self) -> pb.KeyDescriptor:
        wire = pb.KeyDescriptor(domain=int(self.domain), nspace=self.nspace)
        if self.alias is not None:
            wire.alias = self.alias
        if self.blob is not None:
            wire.blob = self.blob
        return wire

    def __str__(self) -> str:
        domain = name_of(Domain, int(self.domain))
        if self.alias is not None:
            return f"{domain}:{self.nspace}:{self.alias}"
        if self.blob is not None:
            return f"{domain}:{self.nspace}:<{len(self.blob)}-byte blob>"
        return f"{domain}:{self.nspace}"


#: What `key` arguments accept: a bare alias is the ``Domain.APP`` case, which
#: is what almost every caller wants.
KeyRef = Union[str, KeyDescriptor]


def _key_descriptor(key: KeyRef) -> KeyDescriptor:
    if isinstance(key, str):
        return KeyDescriptor(domain=Domain.APP, nspace=0, alias=key)
    return key


@dataclass(frozen=True)
class KeyParameter:
    """``android.hardware.security.keymint.KeyParameter``.

    A tag and its value. The tag decides how the value travels: KeyMint packs
    the :class:`~keystork.enums.TagType` into the tag's top four bits, so no
    table of tags is needed to encode one, and a tag this client has never heard
    of still round-trips correctly.

    A ``BOOL`` tag carries no value at all -- KeyMint reads its presence.
    """

    tag: int
    value: Union[bool, int, bytes, None] = None

    def _to_wire(self) -> pb.KeyParameter:
        wire = pb.KeyParameter(tag=int(self.tag))
        tag_type = type_of_tag(int(self.tag))

        if tag_type is TagType.BOOL:
            wire.bool_value = True
        elif tag_type in (TagType.ENUM, TagType.ENUM_REP, TagType.UINT, TagType.UINT_REP):
            wire.integer = int(self.value)  # type: ignore[arg-type]
        elif tag_type in (TagType.ULONG, TagType.ULONG_REP, TagType.DATE):
            wire.long_integer = int(self.value)  # type: ignore[arg-type]
        elif tag_type in (TagType.BYTES, TagType.BIGNUM):
            wire.blob = bytes(self.value)  # type: ignore[arg-type]
        else:
            raise ValueError(f"cannot encode {self}: tag type is {tag_type.name}")
        return wire

    @classmethod
    def _from_wire(cls, wire: pb.KeyParameter) -> "KeyParameter":
        which = wire.WhichOneof("value")
        if which is None:
            return cls(tag=wire.tag, value=None)
        return cls(tag=wire.tag, value=getattr(wire, which))

    def __str__(self) -> str:
        name = name_of(Tag, int(self.tag))
        if self.value is None:
            return name
        if isinstance(self.value, bytes):
            return f"{name}=<{len(self.value)} bytes>"

        table = TAG_ENUMS.get(self.tag)  # type: ignore[arg-type]
        if table is not None:
            return f"{name}={name_of(table, int(self.value))}"
        return f"{name}={self.value}"


@dataclass(frozen=True)
class OperationBegun:
    """What ``createOperation`` returned, minus the handle the daemon keeps."""

    #: KeyMint's parameters for the operation. For an AES-GCM or CBC encryption
    #: without a caller-supplied nonce, this is where the generated one arrives.
    parameters: List[KeyParameter] = field(default_factory=list)

    #: Set when the key is auth-bound. This client cannot satisfy a challenge --
    #: that needs ``IKeystoreAuthorization`` -- so it means the operation will
    #: fail at finish.
    operation_challenge: Optional[int] = None

    #: keystore2 re-wrapped the key blob; a ``Domain.BLOB`` caller should keep it.
    upgraded_blob: Optional[bytes] = None

    @classmethod
    def _from_wire(cls, wire: pb.OperationBegun) -> "OperationBegun":
        return cls(
            parameters=[KeyParameter._from_wire(p) for p in wire.parameters],
            operation_challenge=(
                wire.operation_challenge if wire.HasField("operation_challenge") else None
            ),
            upgraded_blob=wire.upgraded_blob if wire.HasField("upgraded_blob") else None,
        )

    def parameter(self, tag: int) -> Optional[KeyParameter]:
        """The first parameter carrying `tag`, or ``None``."""
        for parameter in self.parameters:
            if parameter.tag == tag:
                return parameter
        return None

    @property
    def nonce(self) -> Optional[bytes]:
        """The IV/nonce KeyMint chose, when it chose one."""
        parameter = self.parameter(Tag.NONCE)
        return parameter.value if parameter is not None else None  # type: ignore[return-value]


@dataclass(frozen=True)
class OperationResult:
    """A whole operation, run in one round-trip."""

    begun: OperationBegun
    output: bytes

    @property
    def nonce(self) -> Optional[bytes]:
        return self.begun.nonce


@dataclass(frozen=True)
class Authorization:
    """One authorization: a parameter and the level that enforces it."""

    security_level: int
    parameter: KeyParameter

    @classmethod
    def _from_wire(cls, wire: pb.Authorization) -> "Authorization":
        return cls(
            security_level=wire.security_level,
            parameter=KeyParameter._from_wire(wire.parameter),
        )

    def __str__(self) -> str:
        return f"{self.parameter} [{name_of(SecurityLevel, self.security_level)}]"


@dataclass(frozen=True)
class KeyMetadata:
    """``android.system.keystore2.KeyMetadata`` -- how a key was generated.

    The authorization list is the useful part: it says which algorithm, digests,
    paddings and block modes the key will accept, which is what
    :class:`Session`'s crypto calls read so a caller does not have to repeat
    them.
    """

    key: KeyDescriptor
    security_level: int
    authorizations: List[Authorization] = field(default_factory=list)
    certificate: Optional[bytes] = None
    certificate_chain: Optional[bytes] = None
    modification_time_ms: int = 0

    @classmethod
    def _from_wire(cls, wire: pb.KeyMetadata) -> "KeyMetadata":
        return cls(
            key=KeyDescriptor._from_wire(wire.key),
            security_level=wire.key_security_level,
            authorizations=[Authorization._from_wire(a) for a in wire.authorizations],
            certificate=wire.certificate if wire.HasField("certificate") else None,
            certificate_chain=(
                wire.certificate_chain if wire.HasField("certificate_chain") else None
            ),
            modification_time_ms=wire.modification_time_ms,
        )

    def values_of(self, tag: int) -> List[Union[bool, int, bytes, None]]:
        """Every value carried under `tag`. Repeatable tags have several."""
        return [a.parameter.value for a in self.authorizations if a.parameter.tag == tag]

    def value_of(self, tag: int) -> Union[bool, int, bytes, None]:
        """The first value under `tag`, or ``None`` if the key has no such tag."""
        values = self.values_of(tag)
        return values[0] if values else None

    def has(self, tag: int) -> bool:
        """Whether `tag` is present at all, which is all a BOOL tag means."""
        return any(a.parameter.tag == tag for a in self.authorizations)

    @property
    def algorithm(self) -> Optional[int]:
        value = self.value_of(Tag.ALGORITHM)
        return int(value) if value is not None else None

    @property
    def key_size(self) -> Optional[int]:
        value = self.value_of(Tag.KEY_SIZE)
        return int(value) if value is not None else None

    @property
    def digests(self) -> List[int]:
        return [int(v) for v in self.values_of(Tag.DIGEST) if v is not None]

    @property
    def paddings(self) -> List[int]:
        return [int(v) for v in self.values_of(Tag.PADDING) if v is not None]

    @property
    def block_modes(self) -> List[int]:
        return [int(v) for v in self.values_of(Tag.BLOCK_MODE) if v is not None]

    @property
    def purposes(self) -> List[int]:
        return [int(v) for v in self.values_of(Tag.PURPOSE) if v is not None]

    @property
    def min_mac_length(self) -> Optional[int]:
        value = self.value_of(Tag.MIN_MAC_LENGTH)
        return int(value) if value is not None else None

    @property
    def caller_nonce(self) -> bool:
        """Whether the key lets the caller choose the IV rather than KeyMint."""
        return self.has(Tag.CALLER_NONCE)

    @property
    def auth_required(self) -> bool:
        """Whether the key is auth-bound, which this client cannot satisfy."""
        return not self.has(Tag.NO_AUTH_REQUIRED)

    def __str__(self) -> str:
        algorithm = name_of(Algorithm, self.algorithm) if self.algorithm is not None else "?"
        size = f"/{self.key_size}" if self.key_size else ""
        level = name_of(SecurityLevel, self.security_level)
        return f"{self.key} {algorithm}{size} [{level}]"


#: Preference order when a key permits several. Strongest-but-conventional
#: first: these only ever choose among values the key itself allows.
_DIGEST_PREFERENCE = (
    Digest.SHA_2_256,
    Digest.SHA_2_512,
    Digest.SHA_2_384,
    Digest.SHA_2_224,
    Digest.SHA1,
    Digest.MD5,
    Digest.NONE,
)
_BLOCK_MODE_PREFERENCE = (BlockMode.GCM, BlockMode.CBC, BlockMode.CTR, BlockMode.ECB)
_SIGN_PADDING_PREFERENCE = (PaddingMode.RSA_PSS, PaddingMode.RSA_PKCS1_1_5_SIGN, PaddingMode.NONE)
_ENCRYPT_PADDING_PREFERENCE = (
    PaddingMode.RSA_OAEP,
    PaddingMode.RSA_PKCS1_1_5_ENCRYPT,
    PaddingMode.NONE,
)


#: IV/nonce length in bytes, per algorithm and block mode. GCM's 12 is KeyMint's
#: fixed choice; CBC and CTR use one cipher block. A mode absent from here uses
#: no IV at all.
NONCE_LENGTHS = {
    (Algorithm.AES, BlockMode.GCM): 12,
    (Algorithm.AES, BlockMode.CBC): 16,
    (Algorithm.AES, BlockMode.CTR): 16,
    (Algorithm.TRIPLE_DES, BlockMode.CBC): 8,
}


def nonce_length(algorithm: Optional[int], block_mode: Optional[int]) -> int:
    """Bytes of IV/nonce this combination uses, or 0 if it uses none."""
    if algorithm is None or block_mode is None:
        return 0
    return NONCE_LENGTHS.get((algorithm, block_mode), 0)


def _preferred(preference: Sequence[int], allowed: Sequence[int]) -> Optional[int]:
    for candidate in preference:
        if candidate in allowed:
            return candidate
    # The key allows something no preference list mentions -- a newer KeyMint
    # value. Taking it is better than failing.
    return allowed[0] if allowed else None


def operation_parameters(
    purpose: int,
    *,
    block_mode: Optional[int] = None,
    padding: Optional[int] = None,
    digest: Optional[int] = None,
    nonce: Optional[bytes] = None,
    mac_length: Optional[int] = None,
    extra: Sequence[KeyParameter] = (),
) -> List[KeyParameter]:
    """Assemble the parameters for an operation, skipping what is ``None``.

    Only a convenience over building the list by hand: nothing is inferred and
    nothing is required beyond `purpose`, since which parameters a key needs is
    a property of how that key was generated.
    """
    parameters = [KeyParameter(Tag.PURPOSE, int(purpose))]
    if block_mode is not None:
        parameters.append(KeyParameter(Tag.BLOCK_MODE, int(block_mode)))
    if padding is not None:
        parameters.append(KeyParameter(Tag.PADDING, int(padding)))
    if digest is not None:
        parameters.append(KeyParameter(Tag.DIGEST, int(digest)))
    if nonce is not None:
        parameters.append(KeyParameter(Tag.NONCE, bytes(nonce)))
    if mac_length is not None:
        parameters.append(KeyParameter(Tag.MAC_LENGTH, int(mac_length)))
    parameters.extend(extra)
    return parameters


class Operation:
    """A streaming operation, held open on the session.

    Obtained from :meth:`Session.operation`, which is a context manager: leaving
    the block without finishing aborts, so a half-run operation never holds one
    of keystore2's slots.
    """

    def __init__(self, session: "KeystoreSession", begun: OperationBegun) -> None:
        self._session = session
        self._begun = begun
        self._done = False

    @property
    def begun(self) -> OperationBegun:
        return self._begun

    @property
    def nonce(self) -> Optional[bytes]:
        return self._begun.nonce

    @property
    def done(self) -> bool:
        """True once finished or aborted; further calls are the daemon's error."""
        return self._done

    def update_aad(self, aad: bytes) -> None:
        """Feed associated data. Must precede any :meth:`update`."""
        self._session._exchange(pb.KeystoreRequest(op_update_aad=pb.OpUpdateAadRequest(aad=bytes(aad))))

    def update(self, data: bytes) -> bytes:
        """Feed input, returning whatever KeyMint chose to emit -- often nothing."""
        response = self._session._exchange(
            pb.KeystoreRequest(op_update=pb.OpUpdateRequest(input=bytes(data)))
        )
        return response.op_update.output if response.op_update.HasField("output") else b""

    def finish(self, data: bytes = b"", signature: Optional[bytes] = None) -> bytes:
        """Complete the operation. `signature` is for ``KeyPurpose.VERIFY``."""
        request = pb.OpFinishRequest()
        if data:
            request.input = bytes(data)
        if signature is not None:
            request.signature = bytes(signature)

        try:
            response = self._session._exchange(pb.KeystoreRequest(op_finish=request))
        finally:
            # finish() consumes the operation on the device whether or not it
            # succeeded, so there is nothing left to abort either way.
            self._done = True
        return response.op_finish.output if response.op_finish.HasField("output") else b""

    def abort(self) -> None:
        """Give the operation back to keystore2 without completing it."""
        if self._done:
            return
        self._done = True
        self._session._exchange(pb.KeystoreRequest(op_abort=pb.OpAbortRequest()))


@dataclass(frozen=True)
class Device:
    """Where the daemon is, and how to reach it. Does not connect.

    Immutable and reusable: one ``Device`` can open any number of sessions, and
    holding one costs nothing. :meth:`dial` is the only thing that touches the
    network.
    """

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    timeout: Optional[float] = DEFAULT_TIMEOUT

    def dial(self) -> socket.socket:
        """Open one connection to the daemon."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise errors.ConnectionClosed(
                f"could not reach keystorkd at {self.host}:{self.port}: {exc} "
                f"(is `adb forward tcp:{self.port} localabstract:keystork` running?)"
            ) from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


#: How much of a file to ask for per round-trip. Matches the server's own clamp.
READ_CHUNK_BYTES = 1024 * 1024

#: Where the package manager records which UID each package runs as. Root-only,
#: which is why it is read with a top-level command before any session opens.
PACKAGES_LIST = "/data/system/packages.list"

#: What ``system`` and the CLI's ``shell`` run. An absolute path because the
#: daemon does no PATH search -- it calls execve and nothing else.
DEVICE_SHELL = "/system/bin/sh"

#: Android offsets each secondary user's UIDs by this much (AID_USER_OFFSET).
USER_OFFSET = 100000


def parse_packages_list(data: bytes) -> "Dict[str, int]":
    """Package name to user-0 UID, from the contents of `PACKAGES_LIST`.

    Each line is space-separated with the name first and its UID second;
    everything after that is ignored. The mapping is many-to-one -- packages
    sharing a ``sharedUserId`` share a UID -- so only this direction is
    well-defined.
    """
    packages: Dict[str, int] = {}
    for line in data.decode(errors="replace").splitlines():
        fields = line.split(" ", 2)
        if len(fields) < 2:
            continue
        try:
            packages[fields[0]] = int(fields[1])
        except ValueError:
            continue
    return packages


class Connection:
    """A connection to the daemon, at the top level.

    The daemon is root here, and every exchange is one command: read a file,
    stop the server, run a program, or open a session. Two of those are
    irreversible -- :meth:`open_keystore_session`, because the UID drop cannot
    be undone, and :meth:`exec`, because the connection becomes the child's
    stdio. After either, no command is valid.

    >>> with Connection(device) as conn:
    ...     data = conn.read_file(PACKAGES_LIST)
    ...     ks = conn.open_keystore_session(uid=10207)
    ...     ks.list()
    """

    def __init__(self, device: Optional[Device] = None) -> None:
        self._device = device or Device()
        self._transport = Transport(self._device.dial())
        self._session_open = False
        self._handed_to = ""

        try:
            greeting = self._transport.recv(pb.Greeting())
            if greeting.protocol_version != PROTOCOL_VERSION:
                raise errors.ProtocolError(
                    f"daemon speaks protocol version {greeting.protocol_version}, "
                    f"this client speaks {PROTOCOL_VERSION}"
                )
        except BaseException:
            self._transport.close()
            raise

    @property
    def device(self) -> Device:
        return self._device

    @property
    def session_open(self) -> bool:
        """True once something has taken over; no command is valid after that."""
        return self._session_open

    def _command(self, command: pb.Command, timeout: Optional[float] = None) -> pb.CommandResponse:
        if self._session_open:
            raise errors.ProtocolError(
                f"this connection is {self._handed_to}; "
                "top-level commands are no longer valid"
            )
        self._transport.send(command)
        # A command that works rather than answers -- inject waits on a zygote
        # fork -- needs a bound of its own; the default one bounds a round trip.
        with self._transport.deadline(timeout):
            response = self._transport.recv(pb.CommandResponse())
        if response.WhichOneof("body") == "error":
            raise errors.from_wire(response.error)
        return response

    def read_file(self, path: str, *, offset: int = 0, length: Optional[int] = None) -> bytes:
        """Read a file from the device, as root.

        Loops until the daemon reports end of file, or until `length` bytes have
        been collected. Only valid before a session opens: reading is a
        privileged operation and privileges are gone after that.
        """
        chunks: List[bytes] = []
        collected = 0
        while length is None or collected < length:
            want = READ_CHUNK_BYTES if length is None else min(READ_CHUNK_BYTES, length - collected)
            response = self._command(
                pb.Command(
                    read_file=pb.ReadFileRequest(path=path, offset=offset, max_length=want)
                )
            ).read_file
            chunks.append(response.data)
            collected += len(response.data)
            offset += len(response.data)
            if response.eof:
                break
            if not response.data:
                # No progress and no eof: stop rather than spin forever.
                break
        return b"".join(chunks)

    def packages(self) -> "Dict[str, int]":
        """Every package on the device, mapped to its user-0 UID."""
        return parse_packages_list(self.read_file(PACKAGES_LIST))

    def resolve_package(self, name: str, user: int = 0) -> int:
        """The UID `name` runs as, for Android user `user`."""
        packages = self.packages()
        if name not in packages:
            raise errors.IdentityError(f"no package named {name!r} in {PACKAGES_LIST}", 0)
        return packages[name] % USER_OFFSET + user * USER_OFFSET

    def kill_server(self) -> None:
        """Stop the daemon. Every live session goes with it."""
        self._command(pb.Command(kill_server=pb.KillServerRequest()))
        self.close()

    def exec(
        self,
        path: str,
        argv: Optional[Sequence[str]] = None,
        *,
        env: Optional[Sequence[str]] = None,
        clear_env: bool = False,
        cwd: Optional[str] = None,
        uid: Optional[int] = None,
        package: Optional[str] = None,
        user: int = 0,
        gid: Optional[int] = None,
        groups: Sequence[int] = (),
        pty: bool = False,
        rows: int = DEFAULT_WINDOW[0],
        cols: int = DEFAULT_WINDOW[1],
    ) -> Process:
        """Run `path` on the device and hand this connection to its stdio.

        One-way, like :meth:`open_keystore_session`: the connection carries the
        child's streams from here on and can never run another command.

        `path` goes to execve unchanged -- no PATH search, no word splitting,
        no globbing. `argv` defaults to ``[path]``. `env` entries are
        ``KEY=VALUE`` applied on top of the daemon's own environment unless
        `clear_env`.

        Leaving `uid` and `package` unset runs the child as root, which the
        daemon already is. Setting a uid without a `gid` uses the same number
        for both, which is the Android app convention. Either way this affects
        only the child -- unlike a keystore session, the connection's own
        privileges are untouched, because the child is a different process.

        `package` is `uid` by another name: it is resolved to one over this
        same connection, while it is still root, before the exec. `user`
        selects the Android user for it.

        `pty` allocates a terminal: the child's ``isatty`` is true, it gets a
        controlling terminal and a process group of its own, and stderr is no
        longer separable from stdout.

        The returned :class:`~keystork.Process` takes the socket over, so it is
        what owns the connection from here -- closing *it* is what closes the
        connection and, if the child is still running, kills it.
        """
        if package is not None:
            if uid is not None:
                raise ValueError("name a uid or a package, not both")
            # Costs a read_file or two, which is only possible up here at the
            # top level -- so it has to happen before the exec, not after.
            uid = self.resolve_package(package, user)

        request = pb.ExecRequest(
            path=path,
            argv=list(argv) if argv is not None else [],
            env=list(env) if env is not None else [],
            clear_env=clear_env,
            groups=list(groups),
        )
        if cwd is not None:
            request.cwd = cwd
        if uid is not None:
            if uid < 0:
                raise ValueError(f"uid must be non-negative, got {uid}")
            request.uid = uid
        if gid is not None:
            if gid < 0:
                raise ValueError(f"gid must be non-negative, got {gid}")
            request.gid = gid
        if pty:
            request.pty.rows = rows
            request.pty.cols = cols

        started = self._command(pb.Command(exec=request)).exec
        self._session_open = True
        self._handed_to = f"the stdio of pid {started.pid}"
        # The two directions run independently from here, so the framed
        # request/response transport has nothing left to do.
        return Process(self._transport.detach(), started)

    def open_integrity_session(
        self,
        package: str,
        *,
        uid: Optional[int] = None,
        user: int = 0,
        timeout_ms: Optional[int] = None,
    ) -> "IntegritySession":
        """Launch `package` with our code in place of its own, and talk to it.

        Seconds rather than a round trip: the daemon force-stops the package,
        seizes the zygote, launches the app, and steps the forked child until
        it takes the app's UID. Progress goes to logcat, since a single
        request/response has nowhere else to put it.

        One-way, like a keystore session: this connection can never open
        another session or run another top-level command, and the app lives
        exactly as long as it does -- closing the session ends the app.

        `uid` is resolved from the device's package list over this same
        connection if not given -- the daemon has no notion of packages beyond
        handing the name to ``am``.
        """
        if uid is None:
            uid = self.resolve_package(package, user)
        request = pb.OpenIntegritySessionRequest(package=package, uid=uid)
        if timeout_ms is not None:
            request.timeout_ms = timeout_ms

        # The daemon spends most of this waiting on a fork, so the usual
        # per-round-trip timeout is the wrong bound.
        deadline = (timeout_ms or 15000) / 1000 + 20
        opened = self._command(
            pb.Command(open_integrity_session=request), timeout=deadline
        ).open_integrity_session
        self._session_open = True
        self._handed_to = f"an integrity session with {package}"
        return IntegritySession._attach(self, package, opened)

    def _open_keystore(self, uid: int) -> pb.KeystoreSessionOpened:
        if uid < 0:
            raise ValueError(f"uid must be non-negative, got {uid}")
        response = self._command(
            pb.Command(open_keystore_session=pb.OpenKeystoreSessionRequest(uid=uid))
        )
        self._session_open = True
        self._handed_to = "a keystore session"
        return response.open_keystore_session

    def open_keystore_session(self, uid: int) -> "KeystoreSession":
        """Become `uid` and hand the connection over to a keystore session.

        One-way: this connection can never open another session or run another
        top-level command.
        """
        return KeystoreSession._attach(self, uid, self._open_keystore(uid), None)

    def close(self) -> None:
        self._transport.close()

    @property
    def closed(self) -> bool:
        return self._transport.closed

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else (self._handed_to or "top level")
        return f"<keystork.Connection {self._device} {state}>"


def kill_server(device: Optional[Device] = None) -> None:
    """Stop the daemon on `device`."""
    with Connection(device) as connection:
        connection.kill_server()


def run(
    path: str,
    argv: Optional[Sequence[str]] = None,
    *,
    device: Optional[Device] = None,
    stdin: bytes = b"",
    **kwargs,
) -> Tuple[ExitStatus, bytes, bytes]:
    """Run one program on the device and collect what it said.

    A connection of its own, opened and closed around the call, since a
    connection can only ever carry one process. `kwargs` are
    :meth:`Connection.exec`'s -- ``uid``, ``package``, ``cwd``, ``env`` and the
    rest.

    The raw form: bytes, and a status you have to look at yourself. Reach for
    :func:`system` unless the output is binary or the exit code is the answer.

    >>> status, out, err = keystork.run("/system/bin/am", ["am", "start", "-n", target])
    """
    connection = Connection(device)
    try:
        process = connection.exec(path, argv, **kwargs)
    except BaseException:
        connection.close()
        raise
    with process:
        return process.communicate(stdin)


def system(
    command: str,
    *,
    device: Optional[Device] = None,
    pty: Optional[bool] = None,
    escape: Optional[int] = ESCAPE,
    **kwargs,
) -> int:
    """``os.system``, pointed at the device.

    Runs `command` under ``sh -c`` on this process's own terminal -- output to
    this process's stdout and stderr, local stdin forwarded in -- captures
    nothing, and returns the exit code::

        keystork.system("ls -l /data/local/tmp")
        keystork.system("am start -n com.foo/.Bar")
        if keystork.system("pm path com.foo >/dev/null") != 0:
            ...

    The return value is the exit code as a shell reports it, ``128 + N`` when a
    signal killed it -- not the encoded wait status ``os.system`` hands back.
    :func:`run` is the one to use when the output is the point, or when it is
    binary.

    `command` goes to a shell, so pipes, redirection, globs, ``&&`` and ``$VAR``
    all mean what they look like -- and, exactly as in a shell, so does anything
    unquoted that came from somewhere you do not control. Build an argv with
    :func:`run` when the command is not a literal you typed.

    `pty` defaults to whether this process's stdin is a terminal, which is what
    makes an inherited terminal behave like one: the child's ``isatty`` is true,
    it gets colour, ``^C`` reaches it through the remote line discipline rather
    than raising here, and a full-screen program works. It also merges stderr
    into stdout, exactly as a shared terminal does.

    A pty is also what makes `escape` matter: with one, every key including
    ``^C`` belongs to the remote, so :data:`ESCAPE` (``^]``) is the way out of
    something that has stopped answering. Escaping gives up on the child --
    which the daemon then kills -- and reports 130, the code a shell uses for
    "the user stopped this". ``escape=None`` removes the hatch.

    `kwargs` are :meth:`Connection.exec`'s -- ``uid``, ``package``, ``gid``,
    ``cwd``, ``env``.
    """
    if pty is None:
        pty = stdin_is_tty()
    rows, cols = local_window()

    connection = Connection(device)
    try:
        process = connection.exec(
            DEVICE_SHELL, ["sh", "-c", command], pty=pty, rows=rows, cols=cols, **kwargs
        )
    except BaseException:
        connection.close()
        raise
    with process:
        status = process.interact(escape=escape)
    return 130 if status is None else status.returncode


class KeystoreSession:
    """One UID-scoped keystore2 session: a connection that has transitioned.

    Constructing one opens a connection and transitions it, so the session is
    live -- or has raised -- by the time you have the object. Closing it closes
    the connection, which is the same thing: the transition is one-way.

    >>> with KeystoreSession(uid=10123) as ks:
    ...     for key in ks.list():
    ...         print(key)

    Naming a package resolves it here in the client, by reading the device's
    package list over the same connection while it is still root:

    >>> with KeystoreSession(package="com.google.android.gms") as ks:
    ...     ks.uid
    10207

    :meth:`Connection.open_keystore_session` is the other way in, for when the
    connection has already done something at the top level.
    """

    def __init__(
        self,
        uid: Optional[int] = None,
        device: Optional[Device] = None,
        *,
        package: Optional[str] = None,
        user: int = 0,
    ) -> None:
        if (uid is None) == (package is None):
            raise ValueError("name exactly one of uid or package")
        if user < 0:
            raise ValueError(f"user must be non-negative, got {user}")

        connection = Connection(device)
        try:
            if package is not None:
                uid = connection.resolve_package(package, user)
            self._adopt(connection, uid, connection._open_keystore(uid), package)
        except BaseException:
            connection.close()
            raise

    @classmethod
    def _attach(
        cls,
        connection: Connection,
        uid: int,
        opened: pb.KeystoreSessionOpened,
        package: Optional[str],
    ) -> "KeystoreSession":
        """Wrap a connection that has already transitioned, without dialing."""
        session = cls.__new__(cls)
        session._adopt(connection, uid, opened, package)
        return session

    def _adopt(
        self,
        connection: Connection,
        uid: int,
        opened: pb.KeystoreSessionOpened,
        package: Optional[str],
    ) -> None:
        self._connection = connection
        self._transport = connection._transport
        self._uid = uid
        self._package = package
        self._interface_version = opened.keystore_interface_version
        self._characteristics: Dict[str, KeyMetadata] = {}

    # -- properties ---------------------------------------------------------

    @property
    def uid(self) -> int:
        """The UID every call in this session runs as, as resolved by the device."""
        return self._uid

    @property
    def package(self) -> Optional[str]:
        """The package this session was opened by name for, if it was."""
        return self._package

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

    def get_key_entry(self, key: KeyRef) -> KeyMetadata:
        """Read a key's metadata: authorizations, certificate, chain.

        This is the only way to learn how a key was generated, so it is what the
        crypto calls consult when you leave their parameters unset.
        """
        request = pb.GetKeyEntryRequest(key=_key_descriptor(key)._to_wire())
        response = self._exchange(pb.KeystoreRequest(get_key_entry=request))
        return KeyMetadata._from_wire(response.get_key_entry.metadata)

    def characteristics(self, key: KeyRef) -> KeyMetadata:
        """:meth:`get_key_entry`, cached for the life of the session.

        A key's authorizations are fixed at generation, so re-reading them
        within one session would only add round-trips.
        """
        cache_key = str(_key_descriptor(key))
        if cache_key not in self._characteristics:
            self._characteristics[cache_key] = self.get_key_entry(key)
        return self._characteristics[cache_key]

    # -- operations ---------------------------------------------------------

    def run_operation(
        self,
        key: KeyRef,
        parameters: Sequence[KeyParameter],
        *,
        aad: Optional[bytes] = None,
        input: Optional[bytes] = None,
        signature: Optional[bytes] = None,
        forced: bool = False,
        security_level: int = SecurityLevel.TRUSTED_ENVIRONMENT,
    ) -> OperationResult:
        """Create, run and finish an operation in one round-trip.

        The common path: `parameters` must name a ``Tag.PURPOSE`` and whatever
        else the key requires. Use :meth:`operation` instead when the input is
        too large to send as one message.
        """
        request = pb.RunOperationRequest(
            start=self._operation_start(key, parameters, forced, security_level)
        )
        if aad is not None:
            request.aad = bytes(aad)
        if input is not None:
            request.input = bytes(input)
        if signature is not None:
            request.signature = bytes(signature)

        result = self._exchange(pb.KeystoreRequest(run_operation=request)).run_operation
        return OperationResult(
            begun=OperationBegun._from_wire(result.begun),
            output=result.output if result.HasField("output") else b"",
        )

    @contextlib.contextmanager
    def operation(
        self,
        key: KeyRef,
        parameters: Sequence[KeyParameter],
        *,
        forced: bool = False,
        security_level: int = SecurityLevel.TRUSTED_ENVIRONMENT,
    ) -> Iterator[Operation]:
        """Open a streaming operation, for input too large to buffer.

        >>> with ks.operation(alias, params) as op:
        ...     for chunk in chunks:
        ...         op.update(chunk)
        ...     signature = op.finish()

        Leaving the block without finishing aborts, so an abandoned operation
        never keeps one of keystore2's slots.
        """
        request = pb.OpBeginRequest(
            start=self._operation_start(key, parameters, forced, security_level)
        )
        response = self._exchange(pb.KeystoreRequest(op_begin=request))
        operation = Operation(self, OperationBegun._from_wire(response.op_begin.begun))
        try:
            yield operation
        finally:
            if not operation.done and not self.closed:
                operation.abort()

    def sign(
        self,
        key: KeyRef,
        data: bytes,
        *,
        digest: Optional[int] = None,
        padding: Optional[int] = None,
        mac_length: Optional[int] = None,
        **kwargs,
    ) -> bytes:
        """Sign `data`, returning the signature.

        Every parameter is optional: what the key permits is read from its
        authorizations and the conventional choice taken. Pass any of them to
        override that.
        """
        parameters = self.crypto_parameters(
            key,
            KeyPurpose.SIGN,
            block_mode=None,
            padding=padding,
            digest=digest,
            nonce=None,
            mac_length=mac_length,
        )
        return self.run_operation(key, parameters, input=data, **kwargs).output

    def verify(
        self,
        key: KeyRef,
        data: bytes,
        signature: bytes,
        *,
        digest: Optional[int] = None,
        padding: Optional[int] = None,
        mac_length: Optional[int] = None,
        **kwargs,
    ) -> bool:
        """Whether `signature` is `data`'s signature under `key`.

        A bad signature is a ``VERIFICATION_FAILED`` from KeyMint, which is an
        answer rather than a failure, so it comes back as ``False``. Every other
        error still raises.

        **Symmetric keys only.** keystore2 refuses ``KeyPurpose.VERIFY`` on an
        asymmetric key -- "public operations on asymmetric keys are not
        supported", ``UNSUPPORTED_PURPOSE`` -- because verifying needs only the
        public key and belongs on the host. Verify an EC or RSA signature
        locally against the certificate instead.
        """
        parameters = self.crypto_parameters(
            key,
            KeyPurpose.VERIFY,
            block_mode=None,
            padding=padding,
            digest=digest,
            nonce=None,
            mac_length=mac_length,
        )
        try:
            self.run_operation(key, parameters, input=data, signature=signature, **kwargs)
        except errors.KeyMintError as exc:
            if exc.code == ErrorCode.VERIFICATION_FAILED:
                return False
            raise
        return True

    def encrypt(
        self,
        key: KeyRef,
        plaintext: bytes,
        *,
        block_mode: Optional[int] = None,
        padding: Optional[int] = None,
        digest: Optional[int] = None,
        nonce: Optional[bytes] = None,
        mac_length: Optional[int] = None,
        aad: Optional[bytes] = None,
        **kwargs,
    ) -> OperationResult:
        """Encrypt `plaintext`.

        Returns the whole :class:`OperationResult` rather than bare bytes,
        because for AES you also need the ``nonce`` KeyMint generated -- without
        it the ciphertext cannot be decrypted. A key generated without
        ``CALLER_NONCE`` will refuse a `nonce` you supply.
        """
        parameters = self.crypto_parameters(
            key,
            KeyPurpose.ENCRYPT,
            block_mode=block_mode,
            padding=padding,
            digest=digest,
            nonce=nonce,
            mac_length=mac_length,
        )
        return self.run_operation(key, parameters, input=plaintext, aad=aad, **kwargs)

    def decrypt(
        self,
        key: KeyRef,
        ciphertext: bytes,
        *,
        block_mode: Optional[int] = None,
        padding: Optional[int] = None,
        digest: Optional[int] = None,
        nonce: Optional[bytes] = None,
        mac_length: Optional[int] = None,
        aad: Optional[bytes] = None,
        **kwargs,
    ) -> bytes:
        """Decrypt `ciphertext`, returning the plaintext.

        `nonce` is required for any mode that used one, and must be the one
        encryption returned.
        """
        parameters = self.crypto_parameters(
            key,
            KeyPurpose.DECRYPT,
            block_mode=block_mode,
            padding=padding,
            digest=digest,
            nonce=nonce,
            mac_length=mac_length,
        )
        return self.run_operation(key, parameters, input=ciphertext, aad=aad, **kwargs).output

    # -- plumbing -----------------------------------------------------------

    def crypto_parameters(
        self,
        key: KeyRef,
        purpose: int,
        *,
        block_mode: Optional[int] = None,
        padding: Optional[int] = None,
        digest: Optional[int] = None,
        nonce: Optional[bytes] = None,
        mac_length: Optional[int] = None,
    ) -> List[KeyParameter]:
        """Fill in whatever the caller left unset from the key's own authorizations.

        Anything passed explicitly is used as passed. Anything left ``None`` is
        chosen from what the key permits, preferring the conventional value --
        SHA-256 over SHA-1, GCM over ECB. If a key permits only values these
        tables have never seen, the first permitted one is used rather than
        failing.

        Consulting the key costs one ``getKeyEntry``, cached per session, and is
        skipped entirely when every parameter was given.
        """
        if all(v is not None for v in (block_mode, padding, digest, mac_length)):
            return operation_parameters(
                purpose,
                block_mode=block_mode,
                padding=padding,
                digest=digest,
                nonce=nonce,
                mac_length=mac_length,
            )

        metadata = self.characteristics(key)
        algorithm = metadata.algorithm

        # A key with no DIGEST authorizations (AES, 3DES) leaves this None,
        # which is correct -- those algorithms take no digest.
        if digest is None and metadata.digests:
            digest = _preferred(_DIGEST_PREFERENCE, metadata.digests)

        if algorithm in (Algorithm.AES, Algorithm.TRIPLE_DES):
            if block_mode is None:
                block_mode = _preferred(_BLOCK_MODE_PREFERENCE, metadata.block_modes)
            if padding is None:
                if block_mode in (BlockMode.GCM, BlockMode.CTR):
                    # Stream modes pad nothing; naming anything else is an error.
                    padding = PaddingMode.NONE
                else:
                    padding = _preferred((PaddingMode.PKCS7, PaddingMode.NONE), metadata.paddings)
            if mac_length is None and block_mode == BlockMode.GCM:
                # KeyMint requires a tag length for GCM and the key sets a floor.
                mac_length = metadata.min_mac_length or 128
        elif algorithm == Algorithm.HMAC:
            if mac_length is None:
                mac_length = metadata.min_mac_length
        elif algorithm == Algorithm.RSA:
            if padding is None:
                preference = (
                    _SIGN_PADDING_PREFERENCE
                    if purpose in (KeyPurpose.SIGN, KeyPurpose.VERIFY)
                    else _ENCRYPT_PADDING_PREFERENCE
                )
                padding = _preferred(preference, metadata.paddings)

        return operation_parameters(
            purpose,
            block_mode=block_mode,
            padding=padding,
            digest=digest,
            nonce=nonce,
            mac_length=mac_length,
        )

    def _operation_start(
        self,
        key: KeyRef,
        parameters: Sequence[KeyParameter],
        forced: bool,
        security_level: int,
    ) -> pb.OperationStart:
        start = pb.OperationStart(
            key=_key_descriptor(key)._to_wire(),
            forced=forced,
            security_level=int(security_level),
        )
        for parameter in parameters:
            start.parameters.append(parameter._to_wire())
        return start

    def _list_page(
        self, domain: int, nspace: int, *, batched: bool, cursor: Optional[str]
    ) -> List[KeyDescriptor]:
        request = pb.ListRequest(domain=int(domain), nspace=nspace, batched=batched)
        if cursor is not None:
            request.starting_past_alias = cursor

        response = self._exchange(pb.KeystoreRequest(list=request))
        if response.WhichOneof("body") != "list":
            raise errors.ProtocolError(
                f"expected a list response, got {response.WhichOneof('body')!r}"
            )
        return [KeyDescriptor._from_wire(entry) for entry in response.list.entries]

    def _exchange(self, request: pb.KeystoreRequest) -> pb.KeystoreResponse:
        """One request, one response. The session allows nothing in between."""
        self._transport.send(request)
        response = self._transport.recv(pb.KeystoreResponse())
        if response.WhichOneof("body") == "error":
            raise errors.from_wire(response.error)
        return response

    def close(self) -> None:
        """End the session, and with it the connection it took over."""
        self._connection.close()

    @property
    def closed(self) -> bool:
        return self._transport.closed

    def __enter__(self) -> "KeystoreSession":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else f"keystore2 V{self._interface_version}"
        who = f"uid={self._uid}"
        if self._package is not None:
            who = f"{self._package} ({who})"
        return f"<keystork.KeystoreSession {who} on {self._connection.device} {state}>"


class IntegritySession:
    """A conversation with our own code, running inside an app's process.

    The app was launched with its own code taken off every classpath in the
    process before a line of it ran, so what answers here is ours -- but the
    process is the app's, at the app's UID and with its package and signing
    certificate, which is what Play Integrity identifies the caller by.

    >>> with keystork.Connection() as conn:
    ...     with conn.open_integrity_session("com.example.app") as integrity:
    ...         token = integrity.classic(nonce=os.urandom(32))

    The app lives exactly as long as this session. Closing it -- or dropping
    the connection -- ends the process, which is deliberate: nothing else on
    the device knows the process is there, so a survivor would be a process
    with no owner holding an app's identity.

    The daemon relays these messages without reading them; they are a contract
    between this class and the Java in the app.
    """

    def __init__(
        self,
        package: str,
        device: Optional[Device] = None,
        *,
        uid: Optional[int] = None,
        user: int = 0,
        timeout_ms: Optional[int] = None,
    ) -> None:
        connection = Connection(device)
        try:
            opened = connection.open_integrity_session(
                package, uid=uid, user=user, timeout_ms=timeout_ms
            )
        except BaseException:
            connection.close()
            raise
        self._adopt(connection, package, opened._opened)

    @classmethod
    def _attach(
        cls, connection: Connection, package: str, opened: pb.IntegritySessionOpened
    ) -> "IntegritySession":
        """Wrap a connection that has already transitioned, without dialing."""
        session = cls.__new__(cls)
        session._adopt(connection, package, opened)
        return session

    def _adopt(
        self, connection: Connection, package: str, opened: pb.IntegritySessionOpened
    ) -> None:
        self._connection = connection
        self._transport = connection._transport
        self._package = package
        self._opened = opened

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
        nonce: Union[bytes, str],
        *,
        cloud_project_number: Optional[int] = None,
    ) -> str:
        """Request a classic integrity token. Returns it as the API gave it.

        `nonce` may be raw bytes, which are encoded here as the API requires --
        URL-safe base64, unpadded and unwrapped, 16..500 bytes once decoded --
        or a string, which is passed through untouched for a caller who has
        already done that.

        `cloud_project_number` is only needed for an app Google Play does not
        know; the ordinary case is the app's own linked project, which the API
        finds for itself.

        The token is a JWE. Its verdicts are readable only by Play, or by
        whoever holds the app's decryption keys -- nothing here looks inside.
        """
        request = pb.ClassicTokenRequest(nonce=_integrity_nonce(nonce))
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
        :meth:`prepare_standard` first; the app has nothing to issue from
        otherwise.
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
        return f"<IntegritySession {self._package} ({state})>"


def _integrity_nonce(nonce: Union[bytes, str]) -> str:
    """The API's nonce format: URL-safe base64, no padding, no wrapping."""
    if isinstance(nonce, str):
        return nonce
    if not 16 <= len(nonce) <= 500:
        raise ValueError(f"a nonce must be 16..500 bytes, got {len(nonce)}")
    return base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
