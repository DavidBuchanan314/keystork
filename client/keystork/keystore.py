"""keystore2's data model, and the session that makes calls against it.

`Connection.open_keystore_session` is the only way to get a `KeystoreSession`,
so the connection it took over is always in view -- which is the point, since
the transition is one-way and that connection can never do anything else.

A session's UID is fixed when it opens. The daemon's child drops to it before
any Binder call and keys are partitioned by exactly those credentials, so
acting as a second UID means ending the session and opening another.

The daemon is deliberately dumb: it makes one keystore2 Binder call as the
session's UID and hands the raw bytes back. Everything that is interpretation
-- naming enum values, pagination, typed errors, reading a key's own
authorizations so a caller need not repeat them -- happens here.
"""

from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Iterator, List, Mapping, Optional, Sequence, Union

from . import errors
from ._proto import keystork_pb2 as pb
from .enums import (
    TAG_ENUMS,
    Algorithm,
    BlockMode,
    Digest,
    Domain,
    EcCurve,
    ErrorCode,
    KeyPurpose,
    PaddingMode,
    SecurityLevel,
    Tag,
    TagType,
    name_of,
    type_of_tag,
)

if TYPE_CHECKING:
    from .attestation import Attestation
    from .connection import Connection

# Minimum keystore2 interface version each call needs. The daemon is built
# against the newest frozen interface and reports what the device actually
# implements, so this table is what turns "too new for this device" into a
# sentence instead of a bare UNKNOWN_TRANSACTION.
MIN_INTERFACE_VERSION = {
    "listEntries": 1,
    "listEntriesBatched": 3,
    "getNumberOfEntries": 3,
    "getSupplementaryAttestationInfo": 5,
}


@dataclass(frozen=True)
class KeyDescriptor:
    """android.system.keystore2.KeyDescriptor.

    Which fields carry meaning depends on `domain`: APP and SELINUX keys are
    named by `alias`, GRANT and KEY_ID keys are numbered by `nspace`, and a
    BLOB key carries its material in `blob`.
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


# What `key` arguments accept: a bare alias is the Domain.APP case, which is
# what almost every caller wants.
KeyRef = Union[str, KeyDescriptor]


def _key_descriptor(key: KeyRef) -> KeyDescriptor:
    if isinstance(key, str):
        return KeyDescriptor(domain=Domain.APP, nspace=0, alias=key)
    return key


@dataclass(frozen=True)
class KeyParameter:
    """android.hardware.security.keymint.KeyParameter.

    A tag and its value. The tag decides how the value travels: KeyMint packs
    the TagType into the tag's top four bits, so no table of tags is needed to
    encode one, and a tag this client has never heard of still round-trips
    correctly.

    A BOOL tag carries no value at all -- KeyMint reads its presence.
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
    """What createOperation returned, minus the handle the daemon keeps."""

    # KeyMint's parameters for the operation. For an AES-GCM or CBC encryption
    # without a caller-supplied nonce, this is where the generated one arrives.
    parameters: List[KeyParameter] = field(default_factory=list)

    # Set when the key is auth-bound. This client cannot satisfy a challenge --
    # that needs IKeystoreAuthorization -- so it means the operation will fail
    # at finish.
    operation_challenge: Optional[int] = None

    # keystore2 re-wrapped the key blob; a Domain.BLOB caller should keep it.
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
        """The first parameter carrying `tag`, or None."""
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


def _split_der(blob: bytes) -> List[bytes]:
    """Split concatenated DER certificates, which carry their own lengths.

    Enough ASN.1 to find where each one ends and no more: a certificate is a
    SEQUENCE, so the first byte is 0x30 and the next is either a short length or
    a count of the bytes that hold the long one. Anything that does not look
    like a certificate ends the walk rather than raising -- a chain this cannot
    read is worth returning in part, since the leaf comes first.
    """
    certificates: List[bytes] = []
    offset = 0
    while offset < len(blob):
        if blob[offset] != 0x30 or offset + 2 > len(blob):
            break
        first = blob[offset + 1]
        if first < 0x80:
            header, length = 2, first
        else:
            count = first & 0x7F
            if count == 0 or offset + 2 + count > len(blob):
                break
            header = 2 + count
            length = int.from_bytes(blob[offset + 2 : offset + 2 + count], "big")
        end = offset + header + length
        if end > len(blob):
            break
        certificates.append(blob[offset:end])
        offset = end
    return certificates


def _pem(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


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
    """android.system.keystore2.KeyMetadata -- how a key was generated.

    The authorization list is the useful part: it says which algorithm, digests,
    paddings and block modes the key will accept, which is what a
    `KeystoreSession`'s crypto calls read so a caller does not have to repeat
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
        """The first value under `tag`, or None if the key has no such tag."""
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
    def origin(self) -> Optional[int]:
        """Where the key material came from -- GENERATED, IMPORTED, UNKNOWN.

        A `KeyOrigin.GENERATED` at a hardware security level is the claim an
        attestation is there to back: the private key was made inside the
        secure hardware and has never been outside it.
        """
        value = self.value_of(Tag.ORIGIN)
        return int(value) if value is not None else None

    @property
    def attested(self) -> bool:
        """Whether this key came back with an attestation chain behind it.

        True only for a generation that named an `Tag.ATTESTATION_CHALLENGE`.
        An asymmetric key generated without one still has a `certificate` --
        self-signed, vouching for nothing.
        """
        return bool(self.certificate_chain)

    @property
    def certificates(self) -> List[bytes]:
        """The whole chain as separate DER certificates, leaf first.

        `certificate` and `certificate_chain` arrive as keystore2 hands them
        over: the leaf on its own, and the rest concatenated with no framing,
        because DER carries its own length. This is that undone -- the list an
        attestation is actually verified against, from the leaf holding the
        attestation extension up to a root you can pin against Google's
        published attestation roots.
        """
        return _split_der(self.certificate or b"") + _split_der(self.certificate_chain or b"")

    @property
    def attestation(self) -> Optional["Attestation"]:
        """The leaf's parsed attestation extension, or None if it has none.

        None for a key generated without a challenge, and for every symmetric
        key. See `keystork.attestation` -- this parses, it does not verify.
        """
        # Imported here rather than at the top: attestation builds the
        # KeyParameters above, so the dependency runs that way and not this.
        from .attestation import parse

        certificates = self.certificates
        return parse(certificates[0]) if certificates else None

    def pem_chain(self) -> str:
        """`certificates` as PEM, which is what every other tool wants.

        >>> Path("chain.pem").write_text(metadata.pem_chain())

        Then, for instance, `openssl x509 -in chain.pem -text` to read the leaf,
        whose attestation extension is OID 1.3.6.1.4.1.11129.2.1.17.
        """
        return "".join(_pem(der) for der in self.certificates)

    @property
    def auth_required(self) -> bool:
        """Whether the key is auth-bound, which this client cannot satisfy."""
        return not self.has(Tag.NO_AUTH_REQUIRED)

    def __str__(self) -> str:
        algorithm = name_of(Algorithm, self.algorithm) if self.algorithm is not None else "?"
        size = f"/{self.key_size}" if self.key_size else ""
        level = name_of(SecurityLevel, self.security_level)
        return f"{self.key} {algorithm}{size} [{level}]"


# Preference order when a key permits several. Strongest-but-conventional
# first: these only ever choose among values the key itself allows.
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


# IV/nonce length in bytes, per algorithm and block mode. GCM's 12 is KeyMint's
# fixed choice; CBC and CTR use one cipher block. A mode absent from here uses
# no IV at all.
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
    """Assemble the parameters for an operation, skipping what is None.

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


# Key size in bits when an algorithm needs one and the caller did not say. EC
# is absent on purpose: it takes its size from the curve, and KEY_SIZE is
# deprecated for EC keys -- DEFAULT_EC_CURVE is its counterpart.
DEFAULT_KEY_SIZES = {
    Algorithm.RSA: 2048,
    Algorithm.AES: 256,
    Algorithm.HMAC: 256,
    Algorithm.TRIPLE_DES: 168,
}

# The curve an EC key gets when the caller names neither a curve nor a size.
DEFAULT_EC_CURVE = EcCurve.P_256

# RSA's public exponent. 65537 is the only value KeyMint accepts.
RSA_PUBLIC_EXPONENT = 65537


def generation_parameters(
    algorithm: int,
    purposes: Sequence[int],
    *,
    key_size: Optional[int] = None,
    ec_curve: Optional[int] = None,
    digests: Sequence[int] = (),
    paddings: Sequence[int] = (),
    block_modes: Sequence[int] = (),
    rsa_public_exponent: Optional[int] = None,
    min_mac_length: Optional[int] = None,
    no_auth_required: bool = True,
    attestation_challenge: Optional[bytes] = None,
    include_unique_id: bool = False,
    device_ids: Optional[Mapping[int, bytes]] = None,
    creation_datetime_ms: Optional[int] = None,
    extra: Sequence[KeyParameter] = (),
) -> List[KeyParameter]:
    """Assemble the parameters for `generate_key`.

    A convenience over building the list by hand, and the same bargain as
    `operation_parameters`: repeatable tags take a sequence, anything left
    unset is simply absent, and nothing is second-guessed. The one thing it
    does supply is a `key_size` for an algorithm that needs one and an
    `rsa_public_exponent` for RSA, because KeyMint rejects a generation
    without them and there is only one sensible value.

    `no_auth_required` defaults to True, which is the opposite of KeyMint's
    default and deliberate: this client cannot satisfy an auth challenge -- that
    needs IKeystoreAuthorization -- so a key generated without it would be one
    nothing here could ever use. Pass False to make one anyway.

    `attestation_challenge` is what turns a generation into an attested one.
    The bytes are yours and reach KeyMint unchanged; they come back inside the
    leaf certificate's attestation extension, which is what proves the chain was
    produced for your challenge rather than replayed.

    `device_ids` maps ATTESTATION_ID_* tags to the values you claim the device
    has -- brand, model, serial, IMEI. KeyMint compares each against what it
    holds and fails the whole generation on any mismatch, so these are asserted
    rather than requested, and getting one wrong is how you learn it. Device ID
    attestation is also privileged: most devices refuse it outright, with
    CANNOT_ATTEST_IDS.
    """
    parameters = [KeyParameter(Tag.ALGORITHM, int(algorithm))]
    parameters.extend(KeyParameter(Tag.PURPOSE, int(p)) for p in purposes)

    if key_size is None and ec_curve is None:
        if algorithm == Algorithm.EC:
            # An EC key is sized by its curve, so leaving both unset has to
            # produce a curve. Falling through to DEFAULT_KEY_SIZES here would
            # emit neither, and KeyMint answers UNSUPPORTED_KEY_SIZE.
            ec_curve = DEFAULT_EC_CURVE
        else:
            key_size = DEFAULT_KEY_SIZES.get(algorithm)
    if key_size is not None:
        parameters.append(KeyParameter(Tag.KEY_SIZE, int(key_size)))
    if ec_curve is not None:
        parameters.append(KeyParameter(Tag.EC_CURVE, int(ec_curve)))

    if algorithm == Algorithm.RSA and rsa_public_exponent is None:
        rsa_public_exponent = RSA_PUBLIC_EXPONENT
    if rsa_public_exponent is not None:
        parameters.append(KeyParameter(Tag.RSA_PUBLIC_EXPONENT, int(rsa_public_exponent)))

    parameters.extend(KeyParameter(Tag.DIGEST, int(d)) for d in digests)
    parameters.extend(KeyParameter(Tag.PADDING, int(p)) for p in paddings)
    parameters.extend(KeyParameter(Tag.BLOCK_MODE, int(b)) for b in block_modes)

    if min_mac_length is not None:
        parameters.append(KeyParameter(Tag.MIN_MAC_LENGTH, int(min_mac_length)))
    if no_auth_required:
        parameters.append(KeyParameter(Tag.NO_AUTH_REQUIRED))
    if attestation_challenge is not None:
        parameters.append(KeyParameter(Tag.ATTESTATION_CHALLENGE, bytes(attestation_challenge)))
    if include_unique_id:
        parameters.append(KeyParameter(Tag.INCLUDE_UNIQUE_ID))
    for tag, value in (device_ids or {}).items():
        parameters.append(KeyParameter(int(tag), bytes(value)))
    if creation_datetime_ms is not None:
        parameters.append(KeyParameter(Tag.CREATION_DATETIME, int(creation_datetime_ms)))

    parameters.extend(extra)
    return parameters


class Operation:
    """A streaming operation, held open on the session.

    Obtained from `KeystoreSession.operation`, which is a context manager:
    leaving the block without finishing aborts, so a half-run operation never
    holds one of keystore2's slots.
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
        """Feed associated data. Must precede any `update`."""
        self._session._exchange(
            pb.KeystoreRequest(op_update_aad=pb.OpUpdateAadRequest(aad=bytes(aad)))
        )

    def update(self, data: bytes) -> bytes:
        """Feed input, returning whatever KeyMint chose to emit -- often nothing."""
        response = self._session._exchange(
            pb.KeystoreRequest(op_update=pb.OpUpdateRequest(input=bytes(data)))
        )
        return response.op_update.output if response.op_update.HasField("output") else b""

    def finish(self, data: bytes = b"", signature: Optional[bytes] = None) -> bytes:
        """Complete the operation. `signature` is for KeyPurpose.VERIFY."""
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


class KeystoreSession:
    """One UID-scoped keystore2 session: a connection that has transitioned.

    `Connection.open_keystore_session` is the only way in, so the connection
    this took over is always in view -- which is the point, since the
    transition is one-way and that connection can never do anything else.

    >>> with device.connect() as conn:
    ...     with conn.open_keystore_session(10123) as ks:
    ...         for key in ks.list():
    ...             print(key)

    A session is named by a UID and nothing else. To act as an installed app,
    turn its name into one first, while the connection is still root:

    >>> from keystork.util.packages import resolve_uid
    >>> with device.connect() as conn:
    ...     uid = resolve_uid(conn, "com.google.android.gms")
    ...     with conn.open_keystore_session(uid) as ks:
    ...         ks.uid
    10207

    Closing either closes both: the session *is* the connection past this
    point.
    """

    def __init__(self) -> None:
        raise TypeError("open a session with Connection.open_keystore_session()")

    @classmethod
    def _attach(
        cls,
        connection: "Connection",
        uid: int,
        opened: pb.KeystoreSessionOpened,
    ) -> "KeystoreSession":
        """Wrap a connection that has already transitioned, without dialing."""
        session = cls.__new__(cls)
        session._connection = connection
        session._transport = connection._transport
        session._uid = uid
        session._interface_version = opened.keystore_interface_version
        session._characteristics: Dict[str, KeyMetadata] = {}
        session._ended = False
        return session

    # -- properties ---------------------------------------------------------

    @property
    def uid(self) -> int:
        """The UID every call in this session runs as, as resolved by the device."""
        return self._uid

    @property
    def interface_version(self) -> int:
        """What the device's keystore2 reports from getInterfaceVersion()."""
        return self._interface_version

    def supports(self, call: str) -> bool:
        """Whether this device's keystore2 implements `call`."""
        return self._interface_version >= MIN_INTERFACE_VERSION[call]

    def require(self, call: str) -> None:
        """Raise UnsupportedByDevice unless `call` exists."""
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

        `domain=APP` scopes to the UID itself and ignores `nspace`; a SELINUX
        listing uses `nspace` as the namespace.

        By default this uses listEntriesBatched where the device has it and
        walks every page, falling back to the deprecated one-shot listEntries
        on older devices. Pass `batched` to force either.
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

        Always uses listEntriesBatched; the pagination loop lives here in the
        client, so each page is exactly one round-trip and one keystore2 call.
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
        """`get_key_entry`, cached for the life of the session.

        A key's authorizations are fixed at generation, so re-reading them
        within one session would only add round-trips.
        """
        cache_key = str(_key_descriptor(key))
        if cache_key not in self._characteristics:
            self._characteristics[cache_key] = self.get_key_entry(key)
        return self._characteristics[cache_key]

    def delete_key(self, key: KeyRef) -> None:
        """Delete a key. There is no undo.

        keystore2 has KeyMint delete the blob as well as the entry, so the
        private key is gone rather than merely unreachable -- which is the point
        of a hardware-backed key, and why nothing here asks twice.

        Deleting a key that is not there raises `KeystoreError` with
        `ResponseCode.KEY_NOT_FOUND`, because that is what keystore2 answers.
        """
        self._exchange(
            pb.KeystoreRequest(
                delete_key=pb.DeleteKeyRequest(key=_key_descriptor(key)._to_wire())
            )
        )
        self._characteristics.pop(str(_key_descriptor(key)), None)

    # -- generation ---------------------------------------------------------

    def generate_key(
        self,
        key: KeyRef,
        parameters: Sequence[KeyParameter],
        *,
        attestation_key: Optional[KeyRef] = None,
        flags: int = 0,
        entropy: bytes = b"",
        security_level: int = SecurityLevel.TRUSTED_ENVIRONMENT,
    ) -> KeyMetadata:
        """Generate a key under `key` and return its metadata.

        The low-level form: `parameters` is passed to KeyMint exactly as given,
        so it must name at least an ALGORITHM and a PURPOSE.
        `generation_parameters` builds a well-formed list, and
        `generate_key_pair` is the whole thing in one call.

        `attestation_key` signs the attestation with a key of your own instead
        of the factory batch key. It must itself have been generated with
        `KeyPurpose.ATTEST_KEY`, and the chain then roots in that key's own
        attestation rather than directly in the manufacturer's.

        `entropy` is stirred into KeyMint's RNG rather than trusted as it, so
        there is no way to make a key predictable with it, and no reason to
        pass any.
        """
        request = pb.GenerateKeyRequest(
            key=_key_descriptor(key)._to_wire(),
            flags=flags,
            entropy=bytes(entropy),
            security_level=int(security_level),
        )
        if attestation_key is not None:
            request.attestation_key.CopyFrom(_key_descriptor(attestation_key)._to_wire())
        for parameter in parameters:
            request.parameters.append(parameter._to_wire())

        response = self._exchange(pb.KeystoreRequest(generate_key=request))
        metadata = KeyMetadata._from_wire(response.generate_key.metadata)

        # The alias now names a different key, so anything cached under it is
        # about the one that was there before.
        self._characteristics.pop(str(_key_descriptor(key)), None)
        return metadata

    def generate_key_pair(
        self,
        key: KeyRef,
        *,
        algorithm: int = Algorithm.EC,
        purposes: Sequence[int] = (KeyPurpose.SIGN, KeyPurpose.VERIFY),
        key_size: Optional[int] = None,
        ec_curve: Optional[int] = None,
        digests: Sequence[int] = (Digest.SHA_2_256,),
        paddings: Sequence[int] = (),
        attestation_challenge: Optional[bytes] = None,
        device_ids: Optional[Mapping[int, bytes]] = None,
        include_unique_id: bool = False,
        no_auth_required: bool = True,
        attestation_key: Optional[KeyRef] = None,
        security_level: int = SecurityLevel.TRUSTED_ENVIRONMENT,
        extra: Sequence[KeyParameter] = (),
        **kwargs,
    ) -> KeyMetadata:
        """Generate an asymmetric key, attesting it when given a challenge.

        The ordinary case in one call. Defaults to a P-256 EC signing key,
        which is what almost everything wants:

        >>> metadata = ks.generate_key_pair("my_key", attestation_challenge=os.urandom(32))
        >>> metadata.attested
        True
        >>> len(metadata.certificates)
        4

        With `attestation_challenge` the chain runs from the leaf -- whose
        attestation extension carries the challenge, the key's own
        authorizations and the device's verified-boot state -- up to a root the
        manufacturer provisioned, which Google publishes for its own devices.
        Without one the key still gets a self-signed leaf and no chain, which
        proves nothing about where the key lives.

        An EC key is sized by its curve: naming neither gets `DEFAULT_EC_CURVE`,
        and KEY_SIZE is deprecated for EC, so pass `ec_curve` rather than
        `key_size` unless you specifically want the legacy form. RSA defaults to
        2048 bits with the only public exponent KeyMint allows. `paddings`
        matters for RSA, which refuses to sign without one, and is meaningless
        for EC.

        Attestation runs as the session's UID, and keystore2 puts that UID's
        package name and signing certificate into the extension itself. A
        session for a UID with no installed package -- root, or an unused app
        id -- fails here rather than attesting to nothing.
        """
        parameters = generation_parameters(
            algorithm,
            purposes,
            key_size=key_size,
            ec_curve=ec_curve,
            digests=digests,
            paddings=paddings,
            attestation_challenge=attestation_challenge,
            device_ids=device_ids,
            include_unique_id=include_unique_id,
            no_auth_required=no_auth_required,
            extra=extra,
            **kwargs,
        )
        return self.generate_key(
            key,
            parameters,
            attestation_key=attestation_key,
            security_level=security_level,
        )

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

        The common path: `parameters` must name a Tag.PURPOSE and whatever else
        the key requires. Use `operation` instead when the input is too large
        to send as one message.
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

        A bad signature is a VERIFICATION_FAILED from KeyMint, which is an
        answer rather than a failure, so it comes back as False. Every other
        error still raises.

        **Symmetric keys only.** keystore2 refuses KeyPurpose.VERIFY on an
        asymmetric key -- "public operations on asymmetric keys are not
        supported", UNSUPPORTED_PURPOSE -- because verifying needs only the
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

        Returns the whole `OperationResult` rather than bare bytes, because for
        AES you also need the nonce KeyMint generated -- without it the
        ciphertext cannot be decrypted. A key generated without CALLER_NONCE
        will refuse a `nonce` you supply.
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

        Anything passed explicitly is used as passed. Anything left None is
        chosen from what the key permits, preferring the conventional value --
        SHA-256 over SHA-1, GCM over ECB. If a key permits only values these
        tables have never seen, the first permitted one is used rather than
        failing.

        Consulting the key costs one getKeyEntry, cached per session, and is
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
        """End the session and give the connection back, still open.

        The daemon releases everything it reached as this UID and climbs back
        to root through the saved UID the drop kept, so the connection returns
        to the top level and can open another session -- for a different UID if
        you like, since each one is a fresh drop.

        Closing an already-closed session does nothing, and a connection that
        has gone away is not an error worth raising here: it is already in the
        state this was asking for.
        """
        if self._ended or self._transport.closed:
            return
        self._ended = True
        try:
            self._exchange(pb.KeystoreRequest(end_session=pb.EndSessionRequest()))
        except errors.ConnectionClosed:
            return
        self._connection._handed_back()

    @property
    def closed(self) -> bool:
        return self._ended or self._transport.closed

    def __enter__(self) -> "KeystoreSession":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else f"keystore2 V{self._interface_version}"
        return (
            f"<keystork.KeystoreSession uid={self._uid} "
            f"on {self._connection.device} {state}>"
        )
