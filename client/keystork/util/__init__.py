"""Things built out of the client rather than part of it.

Each module here is one job done with what a `Connection` already offers --
read a file as root, run a program -- and none of them add anything to the
protocol or to the client's own API. `packages` turns a package name into the
UID or the certificate hash something else wants; `spatula` mints a GMS header
from what the device already holds.

`packages` is where the whole notion of a package lives. Nothing in the client
proper knows what one is -- sessions and processes are named by UID and only by
UID -- and `resolve_uid` is the one thing that turns a name into one.
"""

from . import packages, spatula
from .packages import (
    PACKAGES_LIST,
    PACKAGES_XML,
    USER_OFFSET,
    cert_hash,
    package_cert_hash,
    package_uids,
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
    "package_uids",
    "packages",
    "parse_packages_list",
    "parse_signing_certs",
    "resolve_uid",
    "signing_cert",
    "spatula",
]
