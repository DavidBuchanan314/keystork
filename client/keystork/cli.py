"""A thin CLI over the library. The library is the product.

    keystork list --uid 10123
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from . import errors
from .enums import Domain
from .session import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_TIMEOUT, KeyDescriptor, Session


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="report the session and the device's keystore2 version on stderr",
    )


def _add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"default: {DEFAULT_HOST}")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"default: {DEFAULT_PORT}")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"socket timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--uid", type=int, required=True, help="the UID this session acts as"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keystork", description="Drive a remote device's keystore2 over IP."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    listing = subcommands.add_parser("list", help="list the keys visible to a UID")
    _add_common_args(listing)
    _add_connection_args(listing)
    listing.add_argument(
        "--domain",
        default="APP",
        choices=[d.name for d in Domain],
        help="keystore2 domain to list (default: APP)",
    )
    listing.add_argument(
        "--nspace", type=int, default=0, help="namespace; ignored for domain APP"
    )
    listing.add_argument(
        "--batched",
        dest="batched",
        action="store_true",
        default=None,
        help="force listEntriesBatched (needs keystore2 V3)",
    )
    listing.add_argument(
        "--no-batched",
        dest="batched",
        action="store_false",
        help="force the deprecated one-shot listEntries",
    )
    listing.add_argument(
        "--long", action="store_true", help="show domain and namespace, not just aliases"
    )
    return parser


def _print_listing(entries: List[KeyDescriptor], long: bool, verbose: bool) -> None:
    for entry in entries:
        print(str(entry) if long else (entry.alias if entry.alias is not None else str(entry)))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        with Session(args.uid, args.host, args.port, args.timeout) as session:
            if args.verbose:
                print(
                    f"session uid={session.uid}, "
                    f"keystore2 interface V{session.interface_version}",
                    file=sys.stderr,
                )
            entries = session.list(
                domain=Domain[args.domain], nspace=args.nspace, batched=args.batched
            )
            _print_listing(entries, args.long, args.verbose)
    except errors.KeystorkError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
