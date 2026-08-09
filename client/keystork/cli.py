"""A thin CLI over the library. The library is the product.

    keystork keystore --uid 10123 list
    keystork keystore --uid 10123 info my_key
    keystork keystore --uid 10123 sign my_key --text hello > sig
    keystork shell
    keystork kill-server

Crypto output is raw bytes on stdout so it pipes; pass ``--hex`` for a
hex string instead. Parameters left unset are read from the key itself.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import sys
from typing import List, Optional, Sequence

from . import errors
from .enums import BlockMode, Digest, Domain, KeyPurpose, PaddingMode, Tag, name_of
from .process import ESCAPE, local_window, stdin_is_tty
from .session import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEVICE_SHELL,
    Device,
    KeyDescriptor,
    KeyMetadata,
    KeystoreSession,
    nonce_length,
)
from .util.packages import resolve_uid


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="report the session and the device's keystore2 version on stderr",
    )


def _add_connection_args(parser: argparse.ArgumentParser) -> None:
    """Where the daemon is. Top-level, because it applies to every command."""
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"default: {DEFAULT_HOST}")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"default: {DEFAULT_PORT}")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"socket timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
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


def _parse_escape(text: str) -> Optional[int]:
    """``^]`` caret notation, a bare character, or ``none``."""
    if text.lower() in ("none", "off"):
        return None
    if len(text) == 2 and text[0] == "^":
        # The usual mapping: ^A is 1, ^] is 0x1d, ^? is DEL.
        return ord(text[1].upper()) ^ 0x40
    if len(text) == 1 and ord(text) < 0x100:
        return ord(text)
    raise argparse.ArgumentTypeError(
        f"{text!r} is not a single character, a ^X escape, or 'none'"
    )


def _describe_escape(byte: int) -> str:
    if byte < 0x20:
        return "^" + chr(byte + 0x40)
    if byte == 0x7F:
        return "^?"
    return chr(byte)


def _add_process_args(parser: argparse.ArgumentParser) -> None:
    """How a process is run. Shared by ``shell`` and ``exec``."""
    identity = parser.add_mutually_exclusive_group()
    identity.add_argument("--uid", type=int, help="run as this UID (default: root)")
    identity.add_argument(
        "--package", help="run as this package's UID, resolved over the same connection"
    )
    parser.add_argument(
        "--user", type=int, default=0, help="Android user id for --package (default: 0)"
    )
    parser.add_argument("--gid", type=int, help="run as this GID (default: whatever --uid is)")
    parser.add_argument(
        "--group",
        dest="groups",
        metavar="GID",
        type=int,
        action="append",
        default=[],
        help="supplementary group; repeatable. Default is the primary GID alone",
    )
    parser.add_argument("--cwd", metavar="DIR", help="chdir here before exec")
    parser.add_argument(
        "-e",
        "--env",
        metavar="KEY=VALUE",
        action="append",
        default=[],
        help="add to the daemon's environment, replacing an existing key; repeatable",
    )
    parser.add_argument(
        "-E",
        "--clear-env",
        action="store_true",
        help="start from an empty environment rather than the daemon's",
    )
    terminal = parser.add_mutually_exclusive_group()
    terminal.add_argument(
        "-t",
        dest="tty",
        action="store_true",
        default=None,
        help="allocate a pty even when the default would not",
    )
    terminal.add_argument(
        "-T", dest="tty", action="store_false", help="never allocate a pty"
    )
    parser.add_argument(
        "--escape",
        type=_parse_escape,
        default=ESCAPE,
        metavar="CHAR",
        help=f"key that ends a raw-mode session, in caret notation "
        f"(default: {_describe_escape(ESCAPE)}; 'none' to disable). Only ever read while "
        "the local terminal is raw, since that is the only time it is a keystroke rather "
        "than data",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keystork", description="Drive a remote device's keystore2 over IP."
    )
    _add_connection_args(parser)
    _add_common_args(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    # A keystore session is one of the things the daemon can do; --uid is how
    # that session is opened, so it lives here rather than at the top level.
    keystore = commands.add_parser("keystore", help="open a UID-scoped keystore2 session")
    identity = keystore.add_mutually_exclusive_group(required=True)
    identity.add_argument("--uid", type=int, help="the UID this session acts as")
    identity.add_argument(
        "--package",
        help="package name to act as; the device resolves it to a UID",
    )
    keystore.add_argument(
        "--user",
        type=int,
        default=0,
        help="Android user id for --package (default: 0; a work profile is usually 10)",
    )
    operations = keystore.add_subparsers(dest="operation", required=True)

    listing = operations.add_parser("list", help="list the keys visible to the UID")
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

    info = operations.add_parser("info", help="show how a key was generated")
    _add_key_arg(info)
    info.add_argument(
        "--authorizations",
        action="store_true",
        help="list every authorization rather than the summary",
    )
    info.add_argument("--cert-out", metavar="FILE", help="write the leaf certificate (DER) to FILE")
    info.add_argument("--chain-out", metavar="FILE", help="write the certificate chain to FILE")

    signing = operations.add_parser("sign", help="sign input with a key")
    _add_key_arg(signing)
    _add_input_args(signing)
    _add_parameter_args(signing, symmetric=False)

    verifying = operations.add_parser(
        "verify",
        help="verify a signature (symmetric keys only)",
        description="Exits 0 when the signature verifies and 2 when it does not. "
        "keystore2 refuses this for asymmetric keys; verify those against the certificate.",
    )
    _add_key_arg(verifying)
    _add_input_args(verifying)
    _add_parameter_args(verifying, symmetric=False)
    verifying.add_argument(
        "--signature", metavar="FILE", required=True, help="the signature to check"
    )

    encrypting = operations.add_parser("encrypt", help="encrypt input with a key")
    _add_key_arg(encrypting)
    _add_input_args(encrypting)
    _add_parameter_args(encrypting, symmetric=True)

    decrypting = operations.add_parser("decrypt", help="decrypt input with a key")
    _add_key_arg(decrypting)
    _add_input_args(decrypting)
    _add_parameter_args(decrypting, symmetric=True)

    reading = commands.add_parser(
        "read-file",
        help="read a file from the device as root",
        description="Runs as root, which is why it is a top-level command: "
        "privileges are gone once a keystore session opens.",
    )
    reading.add_argument("path", help="absolute path on the device")
    reading.add_argument("--offset", type=int, default=0, help="start at this byte")
    reading.add_argument("--length", type=int, default=None, help="stop after this many bytes")
    reading.add_argument("-o", "--out", metavar="FILE", help="write to FILE, not stdout")
    reading.add_argument("--hex", action="store_true", help="hex-encode the output")

    commands.add_parser(
        "packages",
        help="list the device's packages and the UIDs they run as",
    )

    shell = commands.add_parser(
        "shell",
        help="run a shell on the device",
        description=f"Runs {DEVICE_SHELL}, as root unless told otherwise. With no COMMAND "
        "this is an interactive session on a pty, with the local terminal in raw mode so "
        "the remote line discipline sees every keystroke -- ^C included. With one, the "
        "arguments are joined with spaces and handed to `sh -c`, on pipes rather than a "
        "pty unless -t. Exits with the command's own status.",
    )
    _add_process_args(shell)
    shell.add_argument(
        # Not `command`: the subparsers already own that destination, and
        # argparse would quietly overwrite the subcommand's own name with this.
        "command_words",
        metavar="COMMAND",
        nargs=argparse.REMAINDER,
        help="what to run; joined with spaces and passed to `sh -c`",
    )

    execing = commands.add_parser(
        "exec",
        help="run one program on the device, with no shell in the way",
        description="execve on the device: PATH is used exactly as given, with no PATH "
        "search, no word splitting and no globbing. Prefer this over `shell` whenever the "
        "arguments come from anywhere but a person.",
    )
    _add_process_args(execing)
    execing.add_argument("path", help="absolute path to the program")
    execing.add_argument(
        "args", nargs=argparse.REMAINDER, help="arguments after argv[0], which is PATH"
    )

    integrity = commands.add_parser(
        "integrity",
        help="launch an app with our code in place of its own and ask it for tokens",
        description="Force-stops the package, seizes the zygote, launches the app, and catches "
        "the forked process at the point it takes the app's UID -- before ActivityThread.main, "
        "so none of the app's own code ever runs. The app then answers token requests for as "
        "long as this command lasts, and is killed when it ends. Opening the session takes "
        "seconds rather than a round trip; watch `keystork exec /system/bin/logcat -s keystorkd "
        "keystork-dex` for the detail.",
    )
    integrity.add_argument("package", help="the app to launch and act as")
    integrity.add_argument(
        "--uid", type=int, help="the UID to expect (default: resolved from the package list)"
    )
    integrity.add_argument("--user", type=int, default=0, help="Android user id (default: 0)")
    integrity.add_argument(
        "--timeout-ms", type=int, help="give up if the app has not forked in this long"
    )
    integrity.add_argument(
        "--nonce",
        help="classic: the nonce, already URL-safe base64 (default: 32 random bytes)",
    )
    integrity.add_argument(
        "--cloud-project",
        type=int,
        help="cloud project number; required for standard, optional for classic",
    )
    integrity.add_argument(
        "--standard",
        metavar="REQUEST_HASH",
        help="ask for a standard token bound to this hash, rather than a classic one",
    )
    integrity.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="issue this many tokens on the one session (default: 1)",
    )

    commands.add_parser(
        "kill-server",
        help="stop the daemon",
        description="SIGTERMs every live session and stops the daemon. "
        "Other clients lose their connections.",
    )

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


def _nonce_length_for(session: KeystoreSession, args: argparse.Namespace) -> int:
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


def _run(session: KeystoreSession, args: argparse.Namespace) -> int:
    if args.operation == "list":
        entries = session.list(
            domain=Domain[args.domain], nspace=args.nspace, batched=args.batched
        )
        _print_listing(entries, args.long)
        return 0

    if args.operation == "info":
        _print_info(session.get_key_entry(args.alias), args)
        return 0

    if args.operation == "sign":
        signature = session.sign(
            args.alias, _read_input(args), **_parameter_kwargs(args, symmetric=False)
        )
        _write_output(signature, args.out, args.hex)
        return 0

    if args.operation == "verify":
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

    if args.operation == "encrypt":
        result = session.encrypt(
            args.alias, _read_input(args), **_parameter_kwargs(args, symmetric=True)
        )
        # The nonce is not secret and is useless to keep separately, so it rides
        # in front of the ciphertext. decrypt takes it back off.
        _write_output((result.nonce or b"") + result.output, args.out, args.hex)
        return 0

    if args.operation == "decrypt":
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

    raise errors.KeystorkError(f"unimplemented operation {args.operation!r}")


def _run_process(device: Device, args: argparse.Namespace, path: str, argv: List[str]) -> int:
    """Start a process and join the local stdio to it until it exits."""
    pty = args.tty
    if pty is None:
        # adb's rule, and for the same reason: a pty is what makes an
        # interactive session work and what corrupts a redirected one.
        pty = args.interactive_default

    env = list(args.env)
    if pty and not any(entry.startswith("TERM=") for entry in env):
        env.append("TERM=" + os.environ.get("TERM", "xterm-256color"))
    rows, cols = local_window()

    connection = device.connect()
    try:
        uid = args.uid
        if args.package is not None:
            uid = resolve_uid(connection, args.package, args.user)
        process = connection.exec(
            path,
            argv,
            env=env,
            clear_env=args.clear_env,
            cwd=args.cwd,
            uid=uid,
            gid=args.gid,
            groups=args.groups,
            pty=pty,
            rows=rows,
            cols=cols,
        )
    except BaseException:
        connection.close()
        raise

    with process:
        if args.verbose:
            who = f"uid={uid}" if uid is not None else "root"
            print(
                f"pid {process.pid} as {who}{', pty' if process.pty else ''}",
                file=sys.stderr,
            )
        # Raw mode is where the escape is both live and needed, and where the
        # user has no other way out -- so that is where it gets announced.
        if process.pty and stdin_is_tty() and args.escape is not None:
            print(
                f"keystork: '{_describe_escape(args.escape)}' disconnects "
                "(and kills the remote process)",
                file=sys.stderr,
            )
        status = process.interact(escape=args.escape)

    if status is None:
        # The terminal is out of raw mode by now, but the remote left the
        # cursor mid-prompt, so start a line of our own.
        print("\nkeystork: disconnected", file=sys.stderr)
        return 130
    if args.verbose:
        print(f"pid {process.pid} {status}", file=sys.stderr)
    return status.returncode


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    device = Device(args.host, args.port, args.timeout)

    try:
        if args.command == "kill-server":
            with device.connect() as connection:
                connection.kill_server()
            if args.verbose:
                print(f"stopped keystorkd on {device}", file=sys.stderr)
            return 0

        if args.command == "read-file":
            with device.connect() as connection:
                data = connection.read_file(args.path, offset=args.offset, length=args.length)
            _write_output(data, args.out, args.hex)
            return 0

        if args.command == "packages":
            with device.connect() as connection:
                packages = connection.packages()
            for name in sorted(packages):
                print(f"{packages[name]}\t{name}")
            return 0

        if args.command == "integrity":
            with device.connect() as connection:
                with connection.open_integrity_session(
                    args.package, uid=args.uid, user=args.user, timeout_ms=args.timeout_ms
                ) as integrity:
                    if args.verbose:
                        arm, bind = integrity.steps
                        print(
                            f"pid {integrity.pid} uid {integrity.uid}, "
                            f"stepped {arm}+{bind} syscalls",
                            file=sys.stderr,
                        )

                    if args.standard is not None:
                        if args.cloud_project is None:
                            print(
                                "--standard needs --cloud-project", file=sys.stderr
                            )
                            return 2
                        integrity.prepare_standard(args.cloud_project)

                    for _ in range(max(1, args.repeat)):
                        if args.standard is not None:
                            print(integrity.standard(args.standard))
                        else:
                            # A nonce given on the command line goes to the API
                            # exactly as typed; only the generated one is
                            # encoded here, and it says so on stderr under -v
                            # so the value can be checked against the verdict.
                            nonce = args.nonce
                            if nonce is None:
                                nonce = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
                                if args.verbose:
                                    print(f"nonce {nonce}", file=sys.stderr)
                            print(
                                integrity.classic(
                                    nonce, cloud_project_number=args.cloud_project
                                )
                            )
            return 0

        if args.command == "shell":
            if args.command_words:
                # Joined with spaces, as adb does: `sh -c` re-splits it, which
                # is the whole point of asking for a shell.
                shell_argv = ["sh", "-c", " ".join(args.command_words)]
                args.interactive_default = False
            else:
                shell_argv = ["sh"]
                args.interactive_default = stdin_is_tty()
            return _run_process(device, args, DEVICE_SHELL, shell_argv)

        if args.command == "exec":
            args.interactive_default = False
            return _run_process(device, args, args.path, [args.path] + args.args)

        with device.connect() as connection:
            with connection.open_keystore_session(
                args.uid, package=args.package, user=args.user
            ) as session:
                if args.verbose:
                    who = f"uid={session.uid}"
                    if session.package is not None:
                        who = f"{session.package} {who}"
                    print(
                        f"session {who}, keystore2 interface V{session.interface_version}",
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
