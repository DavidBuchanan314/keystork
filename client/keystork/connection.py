"""Devices and connections: how you reach the daemon and what it will do.

A `Device` is an address and nothing more; `Device.connect` is where the
network starts; and a `Connection` talks to the daemon as root. Each step is a
verb on the thing before it, and `Device` is the only one you construct.

At the top level the daemon is root, and every exchange is one command: read a
file, stop the server, run a program, or open a session. Opening a session or
running a program hands the connection over -- what happens after that lives in
`keystork.keystore`, `keystork.integrity` and `keystork.process`.

Identity is a UID here and only a UID. Nothing below this line knows what a
package is; `keystork.util.packages.resolve_uid` turns a name into a number,
over a connection that is still at the top level, and the number is what you
pass.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple, Union

from . import errors
from ._proto import keystork_pb2 as pb
from .integrity import IntegritySession
from .keystore import KeystoreSession
from .process import DEFAULT_WINDOW, ESCAPE, ExitStatus, Process, local_window, stdin_is_tty
from .transport import Transport

PROTOCOL_VERSION = pb.PROTOCOL_VERSION_1

# Where `adb forward tcp:9432 localabstract:keystork` puts the daemon.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9432

# Socket timeout, in seconds. Applies to the connect and to every read, so it
# bounds a single round-trip rather than the session as a whole.
DEFAULT_TIMEOUT = 30.0

# How much of a file to ask for per round-trip. Matches the server's own clamp.
READ_CHUNK_BYTES = 1024 * 1024

# What the CLI's `shell` command runs. An absolute path because the daemon does
# no PATH search -- it calls execve and nothing else.
DEVICE_SHELL = "/system/bin/sh"


@dataclass(frozen=True)
class Device:
    """Where the daemon is, and how to reach it. Does not connect.

    Immutable and reusable: one Device can open any number of connections, and
    holding one costs nothing. `connect` is where the network starts.

    >>> device = keystork.Device(host="127.0.0.1", port=9432)
    >>> with device.connect() as conn:
    ...     with conn.open_keystore_session(10123) as ks:
    ...         ks.list()
    """

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    timeout: Optional[float] = DEFAULT_TIMEOUT

    def connect(self) -> "Connection":
        """Open a connection to the daemon, greeting and all.

        The whole library is this chain: a device is an address, a connection
        is a conversation with the daemon, and a session is a connection that
        has been handed over. Each step is a verb on the thing before it, and
        each is the only way to reach the next.
        """
        return Connection._open(self)

    def dial(self) -> socket.socket:
        """Open one raw socket to the daemon, with no protocol on it.

        `connect` is what you want; this is the plumbing under it.
        """
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise errors.ConnectionClosed(
                f"could not reach keystorkd at {self.host}:{self.port}: {exc} "
                f"(is `adb forward tcp:{self.port} localabstract:keystork` running?)"
            ) from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


class Connection:
    """A connection to the daemon, at the top level.

    The daemon is root here, and every exchange is one command: read a file,
    stop the server, run a program, or open a session. A keystore session hands
    the connection back when it ends; `exec` and `open_integrity_session` do
    not, because a connection carrying a process's stdio or a conversation with
    an app has nowhere left to put a command.

    `Device.connect` is the only way to get one -- a connection is a device's
    network, so it is the device that opens it.

    >>> with device.connect() as conn:
    ...     data = conn.read_file("/data/system/packages.list")
    ...     with conn.open_keystore_session(10207) as ks:
    ...         ks.list()
    """

    def __init__(self) -> None:
        # The name is exported for annotations and isinstance; opening one is
        # the device's job, since the connection is the device's network.
        raise TypeError("open a connection with Device.connect()")

    @classmethod
    def _open(cls, device: Device) -> "Connection":
        """Dial, read the greeting, and check the version. See Device.connect."""
        connection = cls.__new__(cls)
        connection._device = device
        connection._transport = Transport(device.dial())
        connection._handed_to = ""

        try:
            greeting = connection._transport.recv(pb.Greeting())
            if greeting.protocol_version != PROTOCOL_VERSION:
                raise errors.ProtocolError(
                    f"daemon speaks protocol version {greeting.protocol_version}, "
                    f"this client speaks {PROTOCOL_VERSION}"
                )
        except BaseException:
            connection._transport.close()
            raise
        return connection

    @property
    def device(self) -> Device:
        return self._device

    @property
    def session_open(self) -> bool:
        """True while something has taken over; no command is valid until it ends."""
        return bool(self._handed_to)

    def _handed_back(self) -> None:
        """Whatever took the connection over gave it back, at the top level.

        Either a keystore session ended, or an exec'd child exited. The daemon
        sends the child's exit last, after reaping and draining, so both ends
        agree the stream is at a frame boundary with nothing behind it -- which
        is the same state a session leaves it in.
        """
        self._handed_to = ""

    def _closed_by_process(self) -> None:
        """A Process dropped the socket to kill a child that was still running.

        That is the only way to stop one from here, and it takes the connection
        with it -- so this connection is closed, and says so rather than
        failing later on a socket somebody else shut.
        """
        self._transport.detach()

    def _command(self, command: pb.Command, timeout: Optional[float] = None) -> pb.CommandResponse:
        if self._handed_to:
            raise errors.ProtocolError(
                f"this connection is {self._handed_to}; "
                "top-level commands are no longer valid"
            )
        self._transport.send(command)
        # A command that works rather than answers -- inject waits on a zygote
        # fork -- needs a bound of its own; the default one bounds a round trip.
        with self._transport.deadline(timeout):
            response = self._transport.recv(pb.CommandResponse())
        if response.WhichOneof("body") == "error":
            raise errors.from_wire(response.error)
        return response

    def read_file(self, path: str, *, offset: int = 0, length: Optional[int] = None) -> bytes:
        """Read a file from the device, as root.

        Loops until the daemon reports end of file, or until `length` bytes have
        been collected. Only valid before a session opens: reading is a
        privileged operation and privileges are gone after that.
        """
        chunks: List[bytes] = []
        collected = 0
        while length is None or collected < length:
            want = READ_CHUNK_BYTES if length is None else min(READ_CHUNK_BYTES, length - collected)
            response = self._command(
                pb.Command(
                    read_file=pb.ReadFileRequest(path=path, offset=offset, max_length=want)
                )
            ).read_file
            chunks.append(response.data)
            collected += len(response.data)
            offset += len(response.data)
            if response.eof:
                break
            if not response.data:
                # No progress and no eof: stop rather than spin forever.
                break
        return b"".join(chunks)

    def kill_server(self) -> None:
        """Stop the daemon. Every live session goes with it."""
        self._command(pb.Command(kill_server=pb.KillServerRequest()))
        self.close()

    def exec(
        self,
        path: str,
        argv: Optional[Sequence[str]] = None,
        *,
        env: Optional[Sequence[str]] = None,
        clear_env: bool = False,
        cwd: Optional[str] = None,
        uid: Optional[int] = None,
        gid: Optional[int] = None,
        groups: Sequence[int] = (),
        pty: bool = False,
        rows: int = DEFAULT_WINDOW[0],
        cols: int = DEFAULT_WINDOW[1],
    ) -> Process:
        """Run `path` on the device and hand this connection to its stdio.

        One-way, like `open_keystore_session`: the connection carries the
        child's streams from here on and can never run another command.

        `path` goes to execve unchanged -- no PATH search, no word splitting,
        no globbing. `argv` defaults to `[path]`. `env` entries are `KEY=VALUE`
        applied on top of the daemon's own environment unless `clear_env`.

        Leaving `uid` unset runs the child as root, which the daemon already
        is. Setting one without a `gid` uses the same number for both, which is
        the Android app convention. Either way this affects only the child --
        unlike a keystore session, the connection's own privileges are
        untouched, because the child is a different process.

        To run as an installed app, resolve its UID first, while this
        connection is still at the top level:

        >>> from keystork.util.packages import resolve_uid
        >>> with device.connect() as conn:
        ...     conn.exec("/system/bin/id", uid=resolve_uid(conn, "com.android.chrome"))

        `pty` allocates a terminal: the child's `isatty` is true, it gets a
        controlling terminal and a process group of its own, and stderr is no
        longer separable from stdout.

        The returned `Process` takes the socket over, so it is what owns the
        connection from here -- closing *it* is what closes the connection and,
        if the child is still running, kills it.
        """
        request = pb.ExecRequest(
            path=path,
            argv=list(argv) if argv is not None else [],
            env=list(env) if env is not None else [],
            clear_env=clear_env,
            groups=list(groups),
        )
        if cwd is not None:
            request.cwd = cwd
        if uid is not None:
            if uid < 0:
                raise ValueError(f"uid must be non-negative, got {uid}")
            request.uid = uid
        if gid is not None:
            if gid < 0:
                raise ValueError(f"gid must be non-negative, got {gid}")
            request.gid = gid
        if pty:
            request.pty.rows = rows
            request.pty.cols = cols

        started = self._command(pb.Command(exec=request)).exec
        self._handed_to = f"the stdio of pid {started.pid}"
        # Borrowed rather than detached: the two directions run independently
        # while the child lives, but its exit puts the stream back at a frame
        # boundary, and the connection resumes at the top level.
        return Process(self._transport.borrow(), started, self)

    def run(
        self,
        path: str,
        argv: Optional[Sequence[str]] = None,
        *,
        stdin: bytes = b"",
        **kwargs,
    ) -> Tuple[ExitStatus, bytes, bytes]:
        """Run one program to completion here and collect what it said.

        The bounded form of `exec`: it waits, returns `(status, stdout, stderr)`
        as bytes, and leaves this connection at the top level, ready for the
        next thing.

        `kwargs` are `exec`'s -- `uid`, `cwd`, `env` and the rest.

        >>> with device.connect() as conn:
        ...     status, out, err = conn.run("/system/bin/getprop", ["getprop", "ro.build.id"])
        """
        with self.exec(path, argv, **kwargs) as process:
            return process.communicate(stdin)

    def check_output(
        self,
        args: Union[str, Sequence[str]],
        *,
        stdin: bytes = b"",
        **kwargs,
    ) -> bytes:
        """Run a program, return its stdout, and raise if it failed.

        `subprocess.check_output`'s bargain, and its signature: `args` is an
        argv whose first entry is the program, or a bare string naming a
        program that takes no arguments.

        >>> with device.connect() as conn:
        ...     conn.check_output(["/system/bin/getprop", "ro.product.model"]).strip()
        b'SM-A075F'

        **Absolute paths only.** Unlike the local one this does no PATH search,
        because the daemon's exec is execve and nothing else -- no PATH, no
        word splitting, no globbing. `check_output("id")` is an `IdentityError`;
        `"/system/bin/id"` is the same thing spelled so that only one thing can
        happen.

        Raises `CommandFailed` on a non-zero exit or a signal, carrying the
        status and *both* streams -- stderr is usually where the reason is, and
        losing it is what makes this pattern annoying elsewhere. A program that
        could not be started at all raises `IdentityError` instead: that
        happens before anything ran.

        `system` is the one with a shell, for when the command line is a
        literal you typed.
        """
        if isinstance(args, str):
            path, argv = args, [args]
        else:
            argv = list(args)
            if not argv:
                raise ValueError("check_output needs at least a program to run")
            path = argv[0]

        status, stdout, stderr = self.run(path, argv, stdin=stdin, **kwargs)
        if not status.ok:
            raise errors.CommandFailed(path, status, stdout, stderr)
        return stdout

    def system(
        self,
        command: str,
        *,
        pty: Optional[bool] = None,
        escape: Optional[int] = ESCAPE,
        **kwargs,
    ) -> int:
        """`os.system`, pointed at the device, on this connection.

        Runs `command` under `sh -c` with the output on your own terminal --
        captured nowhere -- and hands back the exit code, `128 + N` when a
        signal killed it. The connection is usable again afterwards, so several
        of these in a row cost one connection rather than one each:

        >>> with device.connect() as conn:
        ...     conn.system("uname -a")
        ...     conn.system("id", uid=10207)

        `command` goes to a shell, so pipes, redirection, globs, `&&` and `$VAR`
        all mean what they look like -- and so does anything unquoted that came
        from somewhere you do not control. Build an argv with `run` when the
        command is not a literal you typed.

        `pty` defaults to whether this process's stdin is a terminal, which is
        what makes an inherited terminal behave like one: the child's `isatty`
        is true, it gets colour, ^C reaches it through the remote line
        discipline rather than raising here, and a full-screen program works.
        It also merges stderr into stdout, exactly as a shared terminal does.

        A pty is what makes `escape` matter: with one, every key including ^C
        belongs to the remote, so ESCAPE (^]) is the way out of something that
        has stopped answering. Escaping gives up on the child -- which the
        daemon then kills -- and reports 130. **It takes the connection with
        it**, since dropping the connection is what kills a child that is no
        longer answering; a clean exit does not. `escape=None` removes the
        hatch.

        `kwargs` are `exec`'s -- `uid`, `gid`, `cwd`, `env`.
        """
        if pty is None:
            pty = stdin_is_tty()
        rows, cols = local_window()

        with self.exec(
            DEVICE_SHELL, ["sh", "-c", command], pty=pty, rows=rows, cols=cols, **kwargs
        ) as process:
            status = process.interact(escape=escape)
        return 130 if status is None else status.returncode

    def open_integrity_session(
        self,
        package: str,
        uid: int,
        *,
        timeout_ms: Optional[int] = None,
    ) -> IntegritySession:
        """Launch `package` with our code in place of its own, and talk to it.

        Seconds rather than a round trip: the daemon force-stops the package,
        seizes the zygote, launches the app, and steps the forked child until
        it takes the app's UID. Progress goes to logcat, since a single
        request/response has nowhere else to put it.

        One-way, like a keystore session: this connection can never open
        another session or run another top-level command, and the app lives
        exactly as long as it does -- closing the session ends the app.

        Both arguments are needed and they are not the same thing. The name is
        what the daemon hands to `am` to launch the app; the UID is what it
        waits for the forked child to take, and what it checks the child
        against. Resolve it over this connection before opening the session:

        >>> from keystork.util.packages import resolve_uid
        >>> with device.connect() as conn:
        ...     uid = resolve_uid(conn, "com.example.app")
        ...     with conn.open_integrity_session("com.example.app", uid) as app:
        ...         app.classic(nonce)
        """
        if uid < 0:
            raise ValueError(f"uid must be non-negative, got {uid}")
        request = pb.OpenIntegritySessionRequest(package=package, uid=uid)
        if timeout_ms is not None:
            request.timeout_ms = timeout_ms

        # The daemon spends most of this waiting on a fork, so the usual
        # per-round-trip timeout is the wrong bound.
        deadline = (timeout_ms or 15000) / 1000 + 20
        opened = self._command(
            pb.Command(open_integrity_session=request), timeout=deadline
        ).open_integrity_session
        self._handed_to = f"an integrity session with {package}"
        return IntegritySession._attach(self, package, opened)

    def open_keystore_session(self, uid: int) -> KeystoreSession:
        """Become a UID and hand the connection over to a keystore session.

        One-way: this connection can never open another session or run another
        top-level command. The UID drop cannot be undone.

        Keys are partitioned by exactly these credentials, so the UID is the
        whole of what a session is. For an installed app, resolve its name
        first, while this connection is still root:

        >>> from keystork.util.packages import resolve_uid
        >>> with device.connect() as conn:
        ...     with conn.open_keystore_session(resolve_uid(conn, "com.example.app")) as ks:
        ...         ks.list()
        """
        if uid < 0:
            raise ValueError(f"uid must be non-negative, got {uid}")

        response = self._command(
            pb.Command(open_keystore_session=pb.OpenKeystoreSessionRequest(uid=uid))
        )
        self._handed_to = "a keystore session"
        return KeystoreSession._attach(self, uid, response.open_keystore_session)

    def close(self) -> None:
        self._transport.close()

    @property
    def closed(self) -> bool:
        return self._transport.closed

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else (self._handed_to or "top level")
        return f"<keystork.Connection {self._device} {state}>"
