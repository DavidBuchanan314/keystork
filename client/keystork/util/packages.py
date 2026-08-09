"""What the package manager knows about a package: its UID and its signer.

Nothing below the client has a notion of packages. The daemon opens sessions
and execs processes by UID, and the client's own API takes a UID and nothing
else, so this module is the whole of the gap: read the package manager's own
files at the top level, parse them, and turn a name into the UID a session
wants or the certificate hash a Google API wants.

Both files are root-only, so every function taking a connection is a top-level
command and none of them work once a session has opened.
"""

from __future__ import annotations

import base64
import hashlib
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Dict

from .. import errors

if TYPE_CHECKING:
    from ..connection import Connection

# Where the package manager records which UID each package runs as. Root-only,
# which is why it is read with a top-level command before any session opens.
PACKAGES_LIST = "/data/system/packages.list"

# The package manager's full record, signing certificates included. Stored as
# Android Binary XML since Android 12; see `packages_xml`.
PACKAGES_XML = "/data/system/packages.xml"

# What an Android Binary XML file starts with ("ABX" and a version byte).
ABX_MAGIC = b"ABX\x00"

# The device's own converter, which is the only thing that needs to know the
# binary format. It is a shell script around `app_process`, and it insists on
# being called by a name ending in `abx2xml` -- so argv[0] has to be the path.
ABX2XML = "/system/bin/abx2xml"

# Android offsets each secondary user's UIDs by this much (AID_USER_OFFSET).
USER_OFFSET = 100000


def parse_packages_list(data: bytes) -> Dict[str, int]:
    """Package name to user-0 UID, from the contents of `PACKAGES_LIST`.

    Each line is space-separated with the name first and its UID second;
    everything after that is ignored. The mapping is many-to-one -- packages
    sharing a `sharedUserId` share a UID -- so only this direction is
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


def package_uids(conn: "Connection") -> Dict[str, int]:
    """Every package on `conn`'s device, mapped to its user-0 UID.

    Reads `PACKAGES_LIST` over the connection, so it is a root-only top-level
    command and only valid before a session opens.
    """
    return parse_packages_list(conn.read_file(PACKAGES_LIST))


def resolve_uid(conn: "Connection", package: str, user: int = 0) -> int:
    """The UID `package` runs as on `conn`'s device, for Android user `user`.

    This is how a package name becomes something the client can act on: every
    call that takes an identity takes a UID, and this is the only thing that
    turns a name into one. Do it while the connection is still at the top
    level -- it reads a root-only file, and a session has no way back.

    The list holds user-0 UIDs, so the app id is taken modulo the offset before
    `user`'s is added back -- an entry that already names a secondary user
    resolves the same as one that does not.
    """
    if user < 0:
        raise ValueError(f"user must be non-negative, got {user}")
    installed = package_uids(conn)
    if package not in installed:
        raise errors.IdentityError(f"no package named {package!r} in {PACKAGES_LIST}")
    return installed[package] % USER_OFFSET + user * USER_OFFSET


def packages_xml(conn: "Connection") -> bytes:
    """`PACKAGES_XML` as text XML, whatever the device happens to store.

    Android 12 and up write it as Android Binary XML, which nothing off-device
    reads. Rather than decode that here, the device's own `abx2xml` converts
    it -- one exec, on this same connection, which `run` hands back at the top
    level when the child exits. Older devices store text and are read directly.
    """
    if conn.read_file(PACKAGES_XML, length=len(ABX_MAGIC)) != ABX_MAGIC:
        return conn.read_file(PACKAGES_XML)
    return conn.check_output([ABX2XML, PACKAGES_XML, "-"])


def parse_signing_certs(data: bytes) -> Dict[str, bytes]:
    """Package name to signing certificate DER, from the text of `PACKAGES_XML`.

    A certificate is written out once, as hex in a `key` attribute under an
    `index`, and every later package signed by it carries the bare index --
    so resolving one means having read the whole file. Only the first
    certificate of a multiply-signed package is taken, which is the one
    `PackageInfo` reports.
    """
    root = ET.fromstring(data)
    by_index = {
        cert.get("index"): bytes.fromhex(cert.get("key", ""))
        for cert in root.iter("cert")
        if cert.get("key")
    }

    certs: Dict[str, bytes] = {}
    for package in root.iter("package"):
        name = package.get("name")
        sigs = package.find("sigs")
        cert = sigs.find("cert") if sigs is not None else None
        if name is None or cert is None:
            continue
        key = cert.get("key")
        der = bytes.fromhex(key) if key else by_index.get(cert.get("index"))
        if der:
            certs[name] = der
    return certs


def signing_cert(conn: "Connection", package: str) -> bytes:
    """The DER of the certificate `package` is signed with, read from the device."""
    certs = parse_signing_certs(packages_xml(conn))
    if package not in certs:
        raise errors.IdentityError(f"no signing certificate for {package!r} in {PACKAGES_XML}")
    return certs[package]


def cert_hash(der: bytes) -> str:
    """`base64(SHA1(der))` -- how Google's APIs name a signing certificate.

    SHA-1 is not doing anything security-critical here: it is an identifier
    Google's servers already hold, and the value has to match theirs.
    """
    return base64.b64encode(hashlib.sha1(der).digest()).decode("ascii")


def cert_fingerprint(der: bytes) -> str:
    """`SHA1(der)` as uppercase hex, unseparated -- the X-Android-Cert form.

    The same hash as `cert_hash` in the other encoding Google uses. An
    Android-restricted API key is checked against this and the package name, so
    it is what a caller off the device has to send to be taken for the app.
    """
    return hashlib.sha1(der).hexdigest().upper()


def package_cert_hash(conn: "Connection", package: str) -> str:
    """The `cert_hash` of `package`'s signing certificate, read from the device."""
    return cert_hash(signing_cert(conn, package))


def package_cert_fingerprint(conn: "Connection", package: str) -> str:
    """The `cert_fingerprint` of `package`'s signing certificate, read from the device.

    This is the installed certificate, so for an app distributed through Play
    it is Play's app-signing key rather than the upload key -- which is the one
    Google's servers will check against, and the reason reading it from the
    device beats looking it up.
    """
    return cert_fingerprint(signing_cert(conn, package))
