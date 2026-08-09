"""Mint an ``X-Goog-Spatula`` header offline, as GMS would for an app.

The header is how a Google API is told which app on which device is calling.
GMS computes it in-process, from a per-device secret it was provisioned with
and the calling package's identity:

    packageCertificateHash = base64(SHA1(signing-cert DER))
    hmac = HMAC-SHA256(macSecret, packageName + packageCertificateHash)

    SpatulaHeaderProto {
      packageInfo { packageName, packageCertificateHash }
      hmac, deviceId, keyId, keyCert
    }

base64 of that proto is the header value. Every input is a file on the device
and both files are root-only, so a header for any installed package can be
minted from here without the app running -- which is the point: no launch, no
injection, no GMS code, one connection.

The secret and the device's identifiers come from GMS's own `DeviceKey` blob;
the certificate hash comes from the package manager. See
:mod:`keystork.util.packages`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import TYPE_CHECKING

from .. import errors
from .._proto import spatula_pb2 as pb
from .packages import package_cert_hash

if TYPE_CHECKING:
    from ..session import Connection

#: The app GMS is, and whose data directory the device key lives in.
GMS_PACKAGE = "com.google.android.gms"


def device_key_path(user: int = 0) -> str:
    """Where GMS keeps the device key for Android user `user`.

    Per-user, because GMS is: a second user runs its own instance, provisioned
    separately and holding a different secret.
    """
    return f"/data/user/{user}/{GMS_PACKAGE}/files/device_key"


def device_key(conn: "Connection", user: int = 0) -> pb.DeviceKey:
    """GMS's provisioned `DeviceKey`, read from the device as root.

    Raises :class:`~keystork.errors.IdentityError` when the blob is missing or
    carries no ``macSecret``: an unrooted read, or a device GMS has never
    checked in on, and neither can produce a header.
    """
    path = device_key_path(user)
    raw = conn.read_file(path)
    if not raw:
        raise errors.IdentityError(f"{path} is empty; is GMS provisioned for user {user}?", 0)

    key = pb.DeviceKey()
    key.ParseFromString(raw)
    if not key.macSecret:
        raise errors.IdentityError(f"{path} carries no macSecret; cannot mint a spatula", 0)
    return key


def build_header(package: str, cert_hash: str, key: pb.DeviceKey) -> str:
    """The header value for `package`, from its cert hash and a `DeviceKey`.

    The whole computation, with nothing read from a device -- given a key blob
    lifted earlier, this mints a header for any package name you can name.
    """
    mac = hmac.new(key.macSecret, (package + cert_hash).encode(), hashlib.sha256)
    header = pb.SpatulaHeaderProto(
        packageInfo=pb.SpatulaHeaderProto.PackageInfo(
            packageName=package,
            packageCertificateHash=cert_hash,
        ),
        hmac=mac.digest(),
        deviceId=key.deviceId,
        keyId=key.keyId,
        keyCert=key.keyCert,
    )
    return base64.b64encode(header.SerializeToString()).decode("ascii")


def header(conn: "Connection", package: str, user: int = 0) -> str:
    """An ``X-Goog-Spatula`` value for `package`, minted over `conn`.

    Reads the device key and the package's signing certificate, so it is a
    top-level command twice over and only valid before a session opens.

    >>> with device.connect() as conn:
    ...     spatula.header(conn, "com.google.android.GoogleCamera")
    'Cj0KJmNvbS5nb29nbGUuYW5kcm9pZC5Hb29nbGVDYW1lcmESE...'
    """
    return build_header(package, package_cert_hash(conn, package), device_key(conn, user))
