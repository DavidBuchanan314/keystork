"""The key attestation extension, unpacked.

An attested key's leaf certificate carries an extension under OID
1.3.6.1.4.1.11129.2.1.17 whose contents are the point of attestation: the
challenge the key was generated for, the key's own authorizations as KeyMint
recorded them, which of those the secure hardware enforces, the device's
verified-boot state, and the package that asked for the key. Google documents
the schema at source.android.com/docs/security/features/keystore/attestation.

Everything here is parsing and nothing here is verification. A parsed
`Attestation` says what a certificate claims; it is evidence only once the
chain it came from has been verified against a root you trust, which is a job
for a real X.509 library and a current revocation list.

The ASN.1 is asn1crypto's -- the schema below is declared, not parsed by hand.
And the schema is not transcribed twice: an AuthorizationList's context tag
numbers are KeyMint's own tag numbers with the type bits stripped, so both the
field names and their ASN.1 types are derived from `keystork.enums.Tag`. A tag
gains a name here by being added there, and nowhere else.

The two lists come back as `KeyParameter`s, the same type
`KeyMetadata.authorizations` uses. Which list a tag lands in is the whole
question: `hardware_enforced` is what the secure hardware itself holds the key
to, while `software_enforced` is keystore2's record and no stronger than the OS.

    >>> metadata = ks.generate_key_pair("k", attestation_challenge=b"...")
    >>> att = metadata.attestation
    >>> att.challenge
    b'...'
    >>> att.application_id.packages
    [PackageInfo(name='com.example.app', version=1)]
    >>> str(att.root_of_trust)
    'UNVERIFIED, unlocked'
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, List, NamedTuple, Optional

from asn1crypto import core, x509

from .enums import SecurityLevel, Tag, TagType, VerifiedBootState, name_of, type_of_tag

if TYPE_CHECKING:
    from .keystore import KeyParameter

# The extension Android puts a key attestation in.
ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"


class AttestationError(ValueError):
    """An attestation extension was there but would not parse."""


class _IntegerSet(core.SetOf):
    _child_spec = core.Integer


class _RootOfTrust(core.Sequence):
    _fields = [
        ("verified_boot_key", core.OctetString),
        ("device_locked", core.Boolean),
        ("verified_boot_state", core.Enumerated),
        # Added in attestation version 3.
        ("verified_boot_hash", core.OctetString, {"optional": True}),
    ]


# The tags an AuthorizationList can carry, in the ascending order DER requires.
# Every one is OPTIONAL and EXPLICIT, and its ASN.1 type falls out of the
# KeyMint tag type -- which is why this is a list of tags rather than a schema.
_AUTHORIZATION_TAGS = (
    Tag.PURPOSE,
    Tag.ALGORITHM,
    Tag.KEY_SIZE,
    Tag.DIGEST,
    Tag.PADDING,
    Tag.EC_CURVE,
    Tag.RSA_PUBLIC_EXPONENT,
    Tag.RSA_OAEP_MGF_DIGEST,
    Tag.ROLLBACK_RESISTANCE,
    Tag.EARLY_BOOT_ONLY,
    Tag.ACTIVE_DATETIME,
    Tag.ORIGINATION_EXPIRE_DATETIME,
    Tag.USAGE_EXPIRE_DATETIME,
    Tag.USAGE_COUNT_LIMIT,
    Tag.NO_AUTH_REQUIRED,
    Tag.USER_AUTH_TYPE,
    Tag.AUTH_TIMEOUT,
    Tag.ALLOW_WHILE_ON_BODY,
    Tag.TRUSTED_USER_PRESENCE_REQUIRED,
    Tag.TRUSTED_CONFIRMATION_REQUIRED,
    Tag.UNLOCKED_DEVICE_REQUIRED,
    Tag.CREATION_DATETIME,
    Tag.ORIGIN,
    Tag.ROOT_OF_TRUST,
    Tag.OS_VERSION,
    Tag.OS_PATCHLEVEL,
    Tag.ATTESTATION_APPLICATION_ID,
    Tag.ATTESTATION_ID_BRAND,
    Tag.ATTESTATION_ID_DEVICE,
    Tag.ATTESTATION_ID_PRODUCT,
    Tag.ATTESTATION_ID_SERIAL,
    Tag.ATTESTATION_ID_IMEI,
    Tag.ATTESTATION_ID_MEID,
    Tag.ATTESTATION_ID_MANUFACTURER,
    Tag.ATTESTATION_ID_MODEL,
    Tag.VENDOR_PATCHLEVEL,
    Tag.BOOT_PATCHLEVEL,
    Tag.DEVICE_UNIQUE_ATTESTATION,
    Tag.ATTESTATION_ID_SECOND_IMEI,
    Tag.MODULE_HASH,
)


def _number_of(tag: int) -> int:
    """A KeyMint tag's number, which is what the extension tags a field with."""
    return int(tag) & 0x0FFFFFFF


def _spec_for(tag: int) -> type:
    """The ASN.1 type a tag's value takes, from the KeyMint type in the tag."""
    if tag == Tag.ROOT_OF_TRUST:
        # Declared BYTES in KeyMint, but a structure of its own here.
        return _RootOfTrust
    tag_type = type_of_tag(int(tag))
    if tag_type is TagType.BOOL:
        # Present or absent is the whole value, so it is encoded as NULL.
        return core.Null
    if tag_type in (TagType.BYTES, TagType.BIGNUM):
        return core.OctetString
    if tag_type in (TagType.ENUM_REP, TagType.UINT_REP, TagType.ULONG_REP):
        return _IntegerSet
    return core.Integer


class _AuthorizationList(core.Sequence):
    _fields = [
        (
            name_of(Tag, int(tag)),
            _spec_for(tag),
            {"explicit": _number_of(tag), "optional": True},
        )
        for tag in sorted(_AUTHORIZATION_TAGS, key=_number_of)
    ]


class _KeyDescription(core.Sequence):
    _fields = [
        ("attestation_version", core.Integer),
        ("attestation_security_level", core.Enumerated),
        ("keymint_version", core.Integer),
        ("keymint_security_level", core.Enumerated),
        ("attestation_challenge", core.OctetString),
        ("unique_id", core.OctetString),
        ("software_enforced", _AuthorizationList),
        ("hardware_enforced", _AuthorizationList),
    ]


class _AttestationPackageInfo(core.Sequence):
    _fields = [("package_name", core.OctetString), ("version", core.Integer)]


class _PackageInfoSet(core.SetOf):
    _child_spec = _AttestationPackageInfo


class _DigestSet(core.SetOf):
    _child_spec = core.OctetString


class _AttestationApplicationId(core.Sequence):
    _fields = [("package_infos", _PackageInfoSet), ("signature_digests", _DigestSet)]


@dataclass(frozen=True)
class RootOfTrust:
    """The device's verified-boot state, as the secure hardware reported it.

    The part of an attestation that is about the device rather than the key.
    `device_locked` False, or a `verified_boot_state` other than VERIFIED, means
    the OS that asked for the key is not one the OEM signed -- which is exactly
    what a rooted device attesting its own keys looks like.
    """

    verified_boot_key: bytes
    device_locked: bool
    verified_boot_state: int
    verified_boot_hash: Optional[bytes] = None

    @classmethod
    def _from_asn1(cls, parsed: _RootOfTrust) -> "RootOfTrust":
        raw_hash = parsed["verified_boot_hash"]
        return cls(
            verified_boot_key=bytes(parsed["verified_boot_key"]),
            device_locked=bool(parsed["device_locked"]),
            verified_boot_state=int(parsed["verified_boot_state"]),
            verified_boot_hash=None if raw_hash is core.VOID else bytes(raw_hash),
        )

    def __str__(self) -> str:
        state = name_of(VerifiedBootState, self.verified_boot_state)
        return f"{state}, {'locked' if self.device_locked else 'unlocked'}"


class PackageInfo(NamedTuple):
    """One package named in an attestation's application id."""

    name: str
    version: int


@dataclass(frozen=True)
class AttestationApplicationId:
    """Who asked for the key, as keystore2 recorded it.

    keystore2 builds this itself from the calling UID, which is what makes it
    worth anything: a caller cannot claim to be a package it is not. Several
    packages appear when they share a UID through sharedUserId.

    `signature_digests` are SHA-256 over each signing certificate's DER. Note
    SHA-256 -- the spatula header and Android-restricted API keys both use SHA-1
    over the same certificate, so the two are not interchangeable.
    """

    packages: List[PackageInfo] = field(default_factory=list)
    signature_digests: List[bytes] = field(default_factory=list)

    @classmethod
    def _parse(cls, der: bytes) -> "AttestationApplicationId":
        parsed = _AttestationApplicationId.load(der)
        return cls(
            packages=[
                PackageInfo(
                    name=bytes(info["package_name"]).decode("utf-8", "replace"),
                    version=int(info["version"]),
                )
                for info in parsed["package_infos"]
            ],
            signature_digests=[bytes(digest) for digest in parsed["signature_digests"]],
        )

    def __str__(self) -> str:
        return ", ".join(f"{p.name}@{p.version}" for p in self.packages) or "(no packages)"


def _authorizations(parsed: _AuthorizationList) -> List["KeyParameter"]:
    """An AuthorizationList as the KeyParameters it describes.

    Repeatable tags become one KeyParameter per value, so `values_of` finds them
    exactly as it does for authorizations that came off the wire.
    """
    from .keystore import KeyParameter

    parameters: List[KeyParameter] = []
    for name, spec, _params in _AuthorizationList._fields:
        value = parsed[name]
        if value is core.VOID:
            continue
        tag = int(Tag[name])

        if spec is core.Null:
            parameters.append(KeyParameter(tag, True))
        elif spec is _IntegerSet:
            parameters.extend(KeyParameter(tag, int(member)) for member in value)
        elif spec is core.OctetString:
            parameters.append(KeyParameter(tag, bytes(value)))
        elif spec is _RootOfTrust:
            # Kept as DER so the raw bytes stay reachable, untagged so it is
            # a RootOfTrust on its own rather than still inside its [704]
            # wrapper. Attestation.root_of_trust is what unpacks it.
            parameters.append(KeyParameter(tag, value.untag().dump()))
        else:
            parameters.append(KeyParameter(tag, int(value)))
    return parameters


@dataclass(frozen=True)
class Attestation:
    """A parsed key attestation extension."""

    attestation_version: int
    attestation_security_level: int
    keymint_version: int
    keymint_security_level: int
    challenge: bytes
    unique_id: bytes
    software_enforced: List["KeyParameter"] = field(default_factory=list)
    hardware_enforced: List["KeyParameter"] = field(default_factory=list)

    def values_of(self, tag: int, *, hardware_only: bool = False) -> List[Any]:
        """Every value under `tag`, hardware-enforced first."""
        found = [p.value for p in self.hardware_enforced if p.tag == tag]
        if not hardware_only:
            found += [p.value for p in self.software_enforced if p.tag == tag]
        return found

    def value_of(self, tag: int, *, hardware_only: bool = False) -> Any:
        """The first value under `tag`, preferring the hardware-enforced list."""
        values = self.values_of(tag, hardware_only=hardware_only)
        return values[0] if values else None

    def has(self, tag: int, *, hardware_only: bool = False) -> bool:
        """Whether `tag` is present at all, which is all a BOOL tag means."""
        return bool(self.values_of(tag, hardware_only=hardware_only))

    @property
    def root_of_trust(self) -> Optional[RootOfTrust]:
        """The device's boot state, or None if the attestation carried none."""
        raw = self.value_of(Tag.ROOT_OF_TRUST)
        if not isinstance(raw, bytes):
            return None
        return RootOfTrust._from_asn1(_RootOfTrust.load(raw))

    @property
    def application_id(self) -> Optional[AttestationApplicationId]:
        """The package that asked for the key, or None if absent."""
        raw = self.value_of(Tag.ATTESTATION_APPLICATION_ID)
        if not isinstance(raw, bytes):
            return None
        return AttestationApplicationId._parse(raw)

    @property
    def device_locked(self) -> Optional[bool]:
        root = self.root_of_trust
        return root.device_locked if root is not None else None

    @property
    def verified_boot_state(self) -> Optional[int]:
        root = self.root_of_trust
        return root.verified_boot_state if root is not None else None

    def _int(self, tag: int) -> Optional[int]:
        value = self.value_of(tag)
        return int(value) if isinstance(value, int) else None

    @property
    def os_version(self) -> Optional[int]:
        """As MMmmss, so 160000 is Android 16."""
        return self._int(Tag.OS_VERSION)

    @property
    def os_patch_level(self) -> Optional[int]:
        """As YYYYMM."""
        return self._int(Tag.OS_PATCHLEVEL)

    @property
    def vendor_patch_level(self) -> Optional[int]:
        """As YYYYMMDD."""
        return self._int(Tag.VENDOR_PATCHLEVEL)

    @property
    def boot_patch_level(self) -> Optional[int]:
        """As YYYYMMDD."""
        return self._int(Tag.BOOT_PATCHLEVEL)

    def __str__(self) -> str:
        level = name_of(SecurityLevel, self.keymint_security_level)
        root = self.root_of_trust
        return (
            f"v{self.attestation_version} {level} "
            f"challenge=<{len(self.challenge)} bytes>"
            + (f" [{root}]" if root is not None else "")
        )


def parse_key_description(der: bytes) -> Attestation:
    """Parse a KeyDescription: the extension's contents, already unwrapped.

    `parse` is what you usually want; this is for a KeyDescription that reached
    you some other way.
    """
    try:
        parsed = _KeyDescription.load(der, strict=True)
        return Attestation(
            attestation_version=int(parsed["attestation_version"]),
            attestation_security_level=int(parsed["attestation_security_level"]),
            keymint_version=int(parsed["keymint_version"]),
            keymint_security_level=int(parsed["keymint_security_level"]),
            challenge=bytes(parsed["attestation_challenge"]),
            unique_id=bytes(parsed["unique_id"]),
            software_enforced=_authorizations(parsed["software_enforced"]),
            hardware_enforced=_authorizations(parsed["hardware_enforced"]),
        )
    except AttestationError:
        raise
    except ValueError as exc:
        # Most often a tag number newer than this build's Tag enum: the schema
        # above is generated from it, so an unknown field has nowhere to go.
        raise AttestationError(f"could not parse the attestation extension: {exc}") from exc


def extension(certificate: bytes) -> Optional[bytes]:
    """The raw attestation extension of a DER certificate, or None.

    None means the certificate has no such extension, which is the ordinary
    answer for every certificate in a chain except the leaf, and for any key
    generated without a challenge.
    """
    parsed = x509.Certificate.load(certificate)
    for entry in parsed["tbs_certificate"]["extensions"]:
        if entry["extn_id"].dotted == ATTESTATION_OID:
            return bytes(entry["extn_value"])
    return None


def parse(certificate: bytes) -> Optional[Attestation]:
    """The attestation in a DER certificate, or None if it carries none.

    The leaf of the chain is the one that has it:

    >>> att = attestation.parse(metadata.certificates[0])
    """
    raw = extension(certificate)
    return None if raw is None else parse_key_description(raw)
