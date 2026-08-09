"""Things built out of the client rather than part of it.

Each module here is one job done with what :class:`~keystork.Connection`
already offers -- read a file as root, run a program, resolve a package -- and
none of them add anything to the protocol. :mod:`packages` turns a package name
into the UID or the certificate hash something else wants; :mod:`spatula` mints
a GMS header from what the device already holds.
"""

from . import packages, spatula
from .packages import (
    PACKAGES_LIST,
    PACKAGES_XML,
    USER_OFFSET,
    cert_hash,
    package_cert_hash,
    parse_packages_list,
    parse_signing_certs,
    resolve_uid,
    signing_cert,
)

__all__ = [
    "PACKAGES_LIST",
    "PACKAGES_XML",
    "USER_OFFSET",
    "cert_hash",
    "package_cert_hash",
    "packages",
    "parse_packages_list",
    "parse_signing_certs",
    "resolve_uid",
    "signing_cert",
    "spatula",
]
