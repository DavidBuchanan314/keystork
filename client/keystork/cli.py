"""A thin CLI over the library. The library is the product.

    keystork list --uid 10123
    keystork info --uid 10123 my_key
    keystork sign --uid 10123 my_key --text hello > sig
    keystork encrypt --uid 10123 my_aes --text secret --nonce-out iv.bin > ct

Crypto output is raw bytes on stdout so it pipes; pass ``--hex`` for a
hex string instead. Parameters left unset are read from the key itself.
"""

from __future__ import annotations

import argparse
import binascii
import sys
from typing import List, Optional, Sequence

from . import errors
from .enums import BlockMode, Digest, Domain, KeyPurpose, PaddingMode, Tag, name_of
from .session import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    KeyDescriptor,
    KeyMetadata,
    Session,
    nonce_length,
)


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


def _add_key_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("alias", help="key alias, in the session UID's own namespace")


def _add_input_args(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--in", dest="infile", metavar="FILE", help="read input from FILE")
    source.add_argument("--text", help="use this literal string as the input")
    parser.add_argument("-o", "--out", metavar="FILE", help="write output to FILE, not stdout")
    parser.add_argument("--hex", action="store_true", help="hex-encode the output")


def _add_parameter_args(parser: argparse.ArgumentParser, *, symmetric: bool) -> None:
    """The KeyMint knobs. Every one is optional: unset means read it off the key."""
    parser.add_argument(
        "--digest", choices=[d.name for d in Digest], help="default: read from the key"
    )
    parser.add_argument(
        "--padding", choices=[p.name for p in PaddingMode], help="default: read from the key"
    )
    parser.add_argument(
        "--mac-length", type=int, help="MAC/tag length in bits; default: read from the key"
    )
    if symmetric:
        parser.add_argument(
            "--block-mode", choices=[b.name for b in BlockMode], help="default: read from the key"
        )
        parser.add_argument("--aad", help="AEAD associated data, as a literal string")
        parser.add_argument(
            "--nonce",
            metavar="HEX",
            help="IV/nonce as hex. Normally unnecessary: encrypt prepends the nonce to its "
            "output and decrypt takes it back off. Give it when the ciphertext came from "
            "somewhere that did not.",
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

    info = subcommands.add_parser("info", help="show how a key was generated")
    _add_common_args(info)
    _add_connection_args(info)
    _add_key_arg(info)
    info.add_argument(
        "--authorizations",
        action="store_true",
        help="list every authorization rather than the summary",
    )
    info.add_argument("--cert-out", metavar="FILE", help="write the leaf certificate (DER) to FILE")
    info.add_argument("--chain-out", metavar="FILE", help="write the certificate chain to FILE")

    signing = subcommands.add_parser("sign", help="sign input with a key")
    _add_common_args(signing)
    _add_connection_args(signing)
    _add_key_arg(signing)
    _add_input_args(signing)
    _add_parameter_args(signing, symmetric=False)

    verifying = subcommands.add_parser(
        "verify",
        help="verify a signature (symmetric keys only)",
        description="Exits 0 when the signature verifies and 2 when it does not. "
        "keystore2 refuses this for asymmetric keys; verify those against the certificate.",
    )
    _add_common_args(verifying)
    _add_connection_args(verifying)
    _add_key_arg(verifying)
    _add_input_args(verifying)
    _add_parameter_args(verifying, symmetric=False)
    verifying.add_argument(
        "--signature", metavar="FILE", required=True, help="the signature to check"
    )

    encrypting = subcommands.add_parser("encrypt", help="encrypt input with a key")
    _add_common_args(encrypting)
    _add_connection_args(encrypting)
    _add_key_arg(encrypting)
    _add_input_args(encrypting)
    _add_parameter_args(encrypting, symmetric=True)

    decrypting = subcommands.add_parser("decrypt", help="decrypt input with a key")
    _add_common_args(decrypting)
    _add_connection_args(decrypting)
    _add_key_arg(decrypting)
    _add_input_args(decrypting)
    _add_parameter_args(decrypting, symmetric=True)

    return parser


def _read_input(args: argparse.Namespace) -> bytes:
    if args.text is not None:
        return args.text.encode()
    if args.infile:
        with open(args.infile, "rb") as handle:
            return handle.read()
    return sys.stdin.buffer.read()


def _write_output(data: bytes, path: Optional[str], as_hex: bool) -> None:
    encoded = data.hex().encode() + b"\n" if as_hex else data
    if path:
        with open(path, "wb") as handle:
            handle.write(encoded)
        return
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def _enum_value(table, name: Optional[str]) -> Optional[int]:
    return None if name is None else int(table[name])


def _parameter_kwargs(args: argparse.Namespace, *, symmetric: bool) -> dict:
    kwargs = {
        "digest": _enum_value(Digest, args.digest),
        "padding": _enum_value(PaddingMode, args.padding),
        "mac_length": args.mac_length,
    }
    if symmetric:
        kwargs["block_mode"] = _enum_value(BlockMode, args.block_mode)
        kwargs["aad"] = args.aad.encode() if args.aad else None
        if args.nonce is None:
            kwargs["nonce"] = None
        else:
            try:
                kwargs["nonce"] = binascii.unhexlify(args.nonce.strip())
            except binascii.Error as exc:
                raise errors.KeystorkError(f"--nonce is not hex: {exc}") from exc
    return kwargs


def _print_listing(entries: List[KeyDescriptor], long: bool) -> None:
    for entry in entries:
        print(str(entry) if long else (entry.alias if entry.alias is not None else str(entry)))


def _print_info(metadata: KeyMetadata, args: argparse.Namespace) -> None:
    if args.authorizations:
        for authorization in metadata.authorizations:
            print(authorization)
    else:
        from .enums import Algorithm, KeyPurpose, SecurityLevel

        def names(table, values):
            return ", ".join(name_of(table, v) for v in values) or "-"

        algorithm = (
            name_of(Algorithm, metadata.algorithm) if metadata.algorithm is not None else "-"
        )
        print(f"key          {metadata.key}")
        print(f"algorithm    {algorithm}")
        print(f"key size     {metadata.key_size or '-'}")
        print(f"level        {name_of(SecurityLevel, metadata.security_level)}")
        print(f"purposes     {names(KeyPurpose, metadata.purposes)}")
        print(f"digests      {names(Digest, metadata.digests)}")
        print(f"paddings     {names(PaddingMode, metadata.paddings)}")
        print(f"block modes  {names(BlockMode, metadata.block_modes)}")
        print(f"min mac len  {metadata.min_mac_length if metadata.min_mac_length else '-'}")
        print(f"caller nonce {metadata.caller_nonce}")
        print(f"auth bound   {metadata.auth_required}")
        print(f"certificate  {len(metadata.certificate) if metadata.certificate else 0} bytes")
        print(
            f"chain        {len(metadata.certificate_chain) if metadata.certificate_chain else 0}"
            " bytes"
        )

    if args.cert_out and metadata.certificate:
        _write_output(metadata.certificate, args.cert_out, False)
    if args.chain_out and metadata.certificate_chain:
        _write_output(metadata.certificate_chain, args.chain_out, False)


def _nonce_length_for(session: Session, args: argparse.Namespace) -> int:
    """How many leading bytes of the input are the nonce.

    Asks for the same parameters the decrypt itself will use, so an inferred
    block mode and an explicit ``--block-mode`` agree by construction.
    """
    parameters = session.crypto_parameters(
        args.alias,
        KeyPurpose.DECRYPT,
        block_mode=_enum_value(BlockMode, args.block_mode),
        padding=_enum_value(PaddingMode, args.padding),
        digest=_enum_value(Digest, args.digest),
        mac_length=args.mac_length,
    )
    block_mode = next((p.value for p in parameters if p.tag == Tag.BLOCK_MODE), None)
    return nonce_length(session.characteristics(args.alias).algorithm, block_mode)


def _run(session: Session, args: argparse.Namespace) -> int:
    if args.command == "list":
        entries = session.list(
            domain=Domain[args.domain], nspace=args.nspace, batched=args.batched
        )
        _print_listing(entries, args.long)
        return 0

    if args.command == "info":
        _print_info(session.get_key_entry(args.alias), args)
        return 0

    if args.command == "sign":
        signature = session.sign(
            args.alias, _read_input(args), **_parameter_kwargs(args, symmetric=False)
        )
        _write_output(signature, args.out, args.hex)
        return 0

    if args.command == "verify":
        with open(args.signature, "rb") as handle:
            signature = handle.read()
        ok = session.verify(
            args.alias,
            _read_input(args),
            signature,
            **_parameter_kwargs(args, symmetric=False),
        )
        if args.verbose:
            print("valid" if ok else "invalid", file=sys.stderr)
        return 0 if ok else 2

    if args.command == "encrypt":
        result = session.encrypt(
            args.alias, _read_input(args), **_parameter_kwargs(args, symmetric=True)
        )
        # The nonce is not secret and is useless to keep separately, so it rides
        # in front of the ciphertext. decrypt takes it back off.
        _write_output((result.nonce or b"") + result.output, args.out, args.hex)
        return 0

    if args.command == "decrypt":
        data = _read_input(args)
        kwargs = _parameter_kwargs(args, symmetric=True)
        if kwargs["nonce"] is None:
            length = _nonce_length_for(session, args)
            if length:
                if len(data) < length:
                    raise errors.KeystorkError(
                        f"input is {len(data)} bytes, too short to carry the {length}-byte "
                        "nonce this key's mode prepends"
                    )
                kwargs["nonce"], data = data[:length], data[length:]
        plaintext = session.decrypt(args.alias, data, **kwargs)
        _write_output(plaintext, args.out, args.hex)
        return 0

    raise errors.KeystorkError(f"unimplemented command {args.command!r}")


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
            return _run(session, args)
    except errors.KeystorkError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
