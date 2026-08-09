"""Sessions and the calls you make on them.

A connection *is* a session: constructing a `Session` opens the socket, and the
daemon forks a child that permanently drops to the session's UID, so the UID is
fixed at handshake time and can never change. Acting as a second UID means
opening a second session.
"""

from __future__ import annotations

import contextlib
import socket
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence, Union

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

    def __init__(self, session: "Session", begun: OperationBegun) -> None:
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
        self._session._exchange(pb.Request(op_update_aad=pb.OpUpdateAadRequest(aad=bytes(aad))))

    def update(self, data: bytes) -> bytes:
        """Feed input, returning whatever KeyMint chose to emit -- often nothing."""
        response = self._session._exchange(
            pb.Request(op_update=pb.OpUpdateRequest(input=bytes(data)))
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
            response = self._session._exchange(pb.Request(op_finish=request))
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
        self._session._exchange(pb.Request(op_abort=pb.OpAbortRequest()))


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
        self._characteristics: Dict[str, KeyMetadata] = {}
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

    def get_key_entry(self, key: KeyRef) -> KeyMetadata:
        """Read a key's metadata: authorizations, certificate, chain.

        This is the only way to learn how a key was generated, so it is what the
        crypto calls consult when you leave their parameters unset.
        """
        request = pb.GetKeyEntryRequest(key=_key_descriptor(key)._to_wire())
        response = self._exchange(pb.Request(get_key_entry=request))
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

        result = self._exchange(pb.Request(run_operation=request)).run_operation
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
        response = self._exchange(pb.Request(op_begin=request))
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
