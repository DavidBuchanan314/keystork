"""A process running on the device, with its stdio on the connection.

`Connection.exec` starts one and hands the connection over to it. From then on
neither side answers the other: the daemon sends output whenever the child
produces it, this end sends stdin whenever it has some, and the last thing on
the wire is the exit status.

    >>> with keystork.Connection() as conn:
    ...     proc = conn.exec("/system/bin/id")
    ...     status, out, err = proc.communicate()

Nothing here is a shell. `path` goes to execve unchanged -- no PATH search, no
word splitting, no globbing -- so anything wanting those runs ``sh -c``
explicitly, which is what the CLI's ``shell`` command does.
"""

from __future__ import annotations

import contextlib
import os
import selectors
import signal as _signal
import socket
import sys
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple

from . import errors
from ._proto import keystork_pb2 as pb
from .transport import FrameReader, encode_frame

#: Which stream a chunk of output came from. A pty has only one, and it arrives
#: as :data:`STDOUT`.
STDOUT = pb.ExecOutput.STREAM_STDOUT
STDERR = pb.ExecOutput.STREAM_STDERR

#: How much to read from the socket, or from local stdin, in one go.
CHUNK_BYTES = 65536

#: How much queued stdin stops :meth:`Process.interact` reading more of the
#: local one. Matches the daemon's own mark. Without it, redirecting a file
#: into a child that is not reading would pull the whole file into memory here:
#: poll reports a regular file ready every single time it is asked.
OUTBOUND_HIGH_WATER = 1024 * 1024

#: What a pty gets when nobody says otherwise, and what a terminal of unknown
#: size is assumed to be.
DEFAULT_WINDOW = (24, 80)

#: ``^]``, telnet's, and the way out of a raw-mode session. Raw mode is exactly
#: the situation that needs one: every key -- ``^C`` and ``^Z`` included -- is a
#: byte for the remote line discipline, so nothing typed can reach this end.
#: Honoured only while the local terminal *is* raw, because that is the only
#: time stdin is keystrokes rather than data that must survive untouched.
ESCAPE = 0x1D

# Not DefaultSelector: on Linux that is epoll, which refuses a regular file
# with EPERM -- and local stdin is a regular file the moment anyone redirects
# one into it. poll has no such restriction and reports a regular file as
# always ready, which is exactly right.
_Selector = getattr(selectors, "PollSelector", selectors.DefaultSelector)


@dataclass(frozen=True)
class ExitStatus:
    """How a remote process ended. Exactly one field is set."""

    exit_code: Optional[int] = None
    term_signal: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def returncode(self) -> int:
        """A single number, by the shell's convention of 128 + N for a signal."""
        if self.term_signal is not None:
            return 128 + self.term_signal
        return self.exit_code or 0

    def __str__(self) -> str:
        if self.term_signal is not None:
            name = _signal.Signals(self.term_signal).name if _has_signal(self.term_signal) else "?"
            return f"killed by {name} ({self.term_signal})"
        return f"exited {self.exit_code}"


def _has_signal(number: int) -> bool:
    try:
        _signal.Signals(number)
    except ValueError:
        return False
    return True


class Process:
    """A live remote process. Built by :meth:`keystork.Connection.exec`.

    The socket is non-blocking for the whole of the process's life, and every
    method here is a step in a pump rather than a round-trip: :meth:`send`
    queues, :meth:`stream` and :meth:`interact` do the actual work of moving
    bytes in both directions.
    """

    def __init__(self, sock: socket.socket, started: pb.ExecStarted) -> None:
        self._sock = sock
        self._sock.setblocking(False)
        self._reader = FrameReader()
        self._outbound = bytearray()
        self._pid = started.pid
        self._pty = started.pty
        self._status: Optional[ExitStatus] = None
        self._hung_up = False

    @property
    def pid(self) -> int:
        """On the device, and also the child's process group."""
        return self._pid

    @property
    def pty(self) -> bool:
        """Whether a terminal was allocated. False means three plain pipes."""
        return self._pty

    @property
    def status(self) -> Optional[ExitStatus]:
        """How it ended, or ``None`` while it is still running."""
        return self._status

    @property
    def finished(self) -> bool:
        return self._status is not None

    # -- sending --------------------------------------------------------

    def send(self, data: bytes) -> None:
        """Queue bytes for the child's stdin.

        Queued, not written: a child that is not reading would otherwise block
        this end, and this end has output to collect. The bytes go out as the
        socket accepts them, during :meth:`stream` or :meth:`interact`.
        """
        if data:
            self._queue(pb.ExecInput(stdin_data=bytes(data)))

    def send_eof(self) -> None:
        """Say that no more stdin will follow.

        Without a pty this closes the child's stdin, which is what lets a
        ``cat`` finish. With one there is nothing to close, so the daemon
        writes EOT instead -- an end-of-file to a terminal in canonical mode,
        and an ordinary ``^D`` byte to one in raw mode.
        """
        self._queue(pb.ExecInput(stdin_eof=pb.ExecStdinEof()))

    def resize(self, rows: int, cols: int) -> None:
        """Tell the pty its new size. Ignored when there is no pty."""
        self._queue(pb.ExecInput(resize=pb.WindowSize(rows=rows, cols=cols)))

    def signal(self, number: int) -> None:
        """Signal the child's whole process group.

        A pty client rarely needs this: ``^C`` is a byte like any other and the
        remote line discipline raises the signal itself.
        """
        self._queue(pb.ExecInput(signal=number))

    # -- receiving ------------------------------------------------------

    def stream(self) -> Iterator[Tuple[int, bytes]]:
        """Yield ``(stream, data)`` until the process exits.

        Also drives the outbound queue, so anything :meth:`send` accepted is on
        its way while this runs. Raises :class:`~keystork.ConnectionClosed` if
        the daemon hangs up before reporting an exit.
        """
        while not self.finished:
            for chunk in self._pump():
                yield chunk

    def communicate(self, stdin: bytes = b"") -> Tuple[ExitStatus, bytes, bytes]:
        """Feed `stdin`, collect everything, wait for the exit.

        The straightforward path for a command with a bounded amount to say.
        Both directions move together, so a large `stdin` and a talkative child
        cannot deadlock each other.
        """
        self.send(stdin)
        self.send_eof()

        out = bytearray()
        err = bytearray()
        for stream, data in self.stream():
            (out if stream == STDOUT else err).extend(data)
        assert self._status is not None
        return self._status, bytes(out), bytes(err)

    def wait(self) -> ExitStatus:
        """Wait for the exit, discarding any output still to come."""
        for _ in self.stream():
            pass
        assert self._status is not None
        return self._status

    def interact(self, escape: Optional[int] = ESCAPE) -> Optional[ExitStatus]:
        """Join this process's stdio to the local one, and pump until it exits.

        Local stdin goes to the child; the child's stdout and stderr go to the
        local ones. When both ends are terminals -- a pty on the device, a tty
        here -- the local one is put in raw mode for the duration and its size
        is tracked, so the remote program sees every keystroke as it is typed
        and ``^C`` reaches it as a byte rather than killing this client.

        That last part is also why `escape` exists. In raw mode nothing typed
        can reach *this* process, so a remote that stops responding would
        otherwise have to be escaped from another terminal. Typing `escape`
        (:data:`ESCAPE`, ``^]``, by default) returns immediately; ``None``
        disables it.

        The escape byte is watched for **only while the local terminal is
        raw**. Anywhere else stdin is data rather than keystrokes, and quietly
        treating a byte of it as a command would corrupt it.

        Returns the exit status, or ``None`` if `escape` was what ended it.
        There is no third answer and no detaching: the connection *is* the
        child's stdio, so leaving kills it.
        """
        stdin_fd = _fileno(sys.stdin)
        raw = self._pty and stdin_fd is not None and os.isatty(stdin_fd)

        with _RawTerminal(stdin_fd if raw else None) as terminal:
            if raw:
                self.resize(*_window_size(stdin_fd))
            return self._interact(stdin_fd, terminal, escape if raw else None)

    def close(self) -> None:
        """Drop the connection. A still-running child is killed by the daemon."""
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "Process":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __repr__(self) -> str:
        state = str(self._status) if self._status is not None else "running"
        return f"<keystork.Process pid={self._pid}{' pty' if self._pty else ''} {state}>"

    # -- the pump -------------------------------------------------------

    def _queue(self, message: pb.ExecInput) -> None:
        self._outbound += encode_frame(message.SerializeToString())

    def _flush(self) -> None:
        while self._outbound:
            try:
                sent = self._sock.send(self._outbound)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                raise errors.ConnectionClosed(f"write failed: {exc}") from exc
            del self._outbound[:sent]

    def _receive(self) -> None:
        try:
            chunk = self._sock.recv(CHUNK_BYTES)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            raise errors.ConnectionClosed(f"read failed: {exc}") from exc
        if not chunk:
            self._hung_up = True
            return
        self._reader.feed(chunk)

    def _decode(self) -> List[Tuple[int, bytes]]:
        """Every buffered frame, as output chunks. Records the exit if it lands."""
        chunks: List[Tuple[int, bytes]] = []
        for frame in self._reader:
            event = pb.ExecEvent()
            try:
                event.ParseFromString(frame)
            except Exception as exc:
                raise errors.ProtocolError(f"could not parse an exec event: {exc}") from exc

            body = event.WhichOneof("body")
            if body == "output":
                chunks.append((event.output.stream, event.output.data))
            elif body == "exit":
                which = event.exit.WhichOneof("status")
                self._status = ExitStatus(
                    exit_code=event.exit.exit_code if which == "exit_code" else None,
                    term_signal=event.exit.term_signal if which == "term_signal" else None,
                )
            elif body == "error":
                raise errors.from_wire(event.error)
            else:
                raise errors.ProtocolError("exec event carries nothing this client understands")
        return chunks

    def _select(self, extra: Sequence[int] = ()) -> List[int]:
        """Block until something can move. Returns whichever of `extra` is readable."""
        with _Selector() as selector:
            events = selectors.EVENT_READ
            if self._outbound:
                events |= selectors.EVENT_WRITE
            selector.register(self._sock, events, None)
            for fd in extra:
                selector.register(fd, selectors.EVENT_READ, fd)

            ready = []
            for key, mask in selector.select():
                if key.data is None:
                    if mask & selectors.EVENT_WRITE:
                        self._flush()
                    if mask & selectors.EVENT_READ:
                        self._receive()
                else:
                    ready.append(key.data)
            return ready

    def _pump(self) -> List[Tuple[int, bytes]]:
        """One turn of the crank: move what can move, decode what arrived."""
        chunks = self._decode()
        if chunks or self.finished:
            return chunks

        self._flush()
        if not self._hung_up:
            self._select()
        chunks = self._decode()

        if self._hung_up and not self.finished and not chunks:
            raise errors.ConnectionClosed(
                f"the daemon closed the connection before pid {self._pid} reported an exit"
            )
        return chunks

    def _interact(
        self,
        stdin_fd: Optional[int],
        terminal: "_RawTerminal",
        escape: Optional[int],
    ) -> Optional[ExitStatus]:
        watching = [fd for fd in (stdin_fd, terminal.winch_fd) if fd is not None]
        if stdin_fd is None:
            # No local stdin to forward, so the child should not be left
            # waiting on one.
            self.send_eof()

        while not self.finished:
            for stream, data in self._decode():
                _write_local(stream, data)

            if self.finished:
                break
            self._flush()
            if self._hung_up:
                # One last look for the exit event, then give up on it.
                for stream, data in self._decode():
                    _write_local(stream, data)
                if not self.finished:
                    raise errors.ConnectionClosed(
                        f"the daemon closed the connection before pid {self._pid} reported an exit"
                    )
                break

            # Everything but the local input, once enough of it is queued: a
            # resize still has to get through while the child is behind.
            ready = list(watching)
            if len(self._outbound) >= OUTBOUND_HIGH_WATER and stdin_fd in ready:
                ready.remove(stdin_fd)

            for fd in self._select(ready):
                if fd == terminal.winch_fd:
                    terminal.drain_winch()
                    assert stdin_fd is not None
                    self.resize(*_window_size(stdin_fd))
                    continue

                try:
                    data = os.read(fd, CHUNK_BYTES)
                except OSError:
                    data = b""
                if data:
                    if escape is not None and fd == stdin_fd:
                        struck = data.find(escape)
                        if struck >= 0:
                            # Whatever was typed ahead of it still belongs to
                            # the remote, and may as well arrive; a keystroke
                            # is normally a read of its own, so this is the
                            # paste case rather than the usual one.
                            self.send(data[:struck])
                            with contextlib.suppress(errors.ConnectionClosed):
                                self._flush()
                            return None
                    self.send(data)
                else:
                    # Local stdin is done. Stop watching it -- a closed
                    # descriptor is readable forever -- and let the child know.
                    watching.remove(fd)
                    self.send_eof()

        assert self._status is not None
        return self._status


def _fileno(stream) -> Optional[int]:
    try:
        return stream.fileno()
    except (AttributeError, OSError, ValueError):
        return None


def _write_local(stream: int, data: bytes) -> None:
    target = sys.stdout if stream == STDOUT else sys.stderr
    buffer = getattr(target, "buffer", None)
    if buffer is None:
        target.write(data.decode(errors="replace"))
        target.flush()
        return

    # Flush the text layer first. Remote output goes out as bytes, underneath
    # it -- so anything the caller print()ed and has not flushed (which is
    # everything, once stdout is a pipe rather than a terminal) would otherwise
    # surface *after* output that was actually produced later.
    target.flush()
    buffer.write(data)
    buffer.flush()


def _terminal_size(fd: Optional[int]) -> Optional[Tuple[int, int]]:
    if fd is None:
        return None
    try:
        size = os.get_terminal_size(fd)
    except (OSError, ValueError):
        return None
    return size.lines, size.columns


def _window_size(fd: int) -> Tuple[int, int]:
    return _terminal_size(fd) or DEFAULT_WINDOW


def stdin_is_tty() -> bool:
    """Whether *this* process's stdin is a terminal.

    What decides whether a remote pty is the right default: a pty is how an
    inherited terminal is emulated, and there is nothing to emulate when the
    caller has none.
    """
    fd = _fileno(sys.stdin)
    return fd is not None and os.isatty(fd)


def local_window() -> Tuple[int, int]:
    """This process's own terminal size, or :data:`DEFAULT_WINDOW` if it has none.

    stdout is tried after stdin, so a piped-in command run from a terminal
    still gets that terminal's width.
    """
    for stream in (sys.stdin, sys.stdout):
        size = _terminal_size(_fileno(stream))
        if size is not None:
            return size
    return DEFAULT_WINDOW


class _RawTerminal:
    """Raw mode on a local tty, plus a descriptor that becomes readable on SIGWINCH.

    The pipe is how a resize reaches a ``select``: Python retries an interrupted
    syscall rather than surfacing the interruption (PEP 475), so a plain signal
    handler would not be noticed until the next keystroke.

    Passing ``None`` makes the whole thing inert, which is the non-tty case.
    """

    def __init__(self, fd: Optional[int]) -> None:
        self._fd = fd
        self._saved = None
        self._pipe: Optional[Tuple[int, int]] = None
        self._previous_wakeup = -1
        self._previous_handler = None

    @property
    def winch_fd(self) -> Optional[int]:
        return self._pipe[0] if self._pipe is not None else None

    def drain_winch(self) -> None:
        assert self._pipe is not None
        try:
            os.read(self._pipe[0], CHUNK_BYTES)
        except OSError:
            pass

    def __enter__(self) -> "_RawTerminal":
        if self._fd is None:
            return self

        import termios
        import tty

        self._saved = termios.tcgetattr(self._fd)
        tty.setraw(self._fd)

        # set_wakeup_fd is main-thread-only, and SIGWINCH needs a handler
        # installed before Python will write to the pipe at all.
        try:
            read_fd, write_fd = os.pipe()
            os.set_blocking(read_fd, False)
            os.set_blocking(write_fd, False)
            self._previous_wakeup = _signal.set_wakeup_fd(write_fd)
            self._previous_handler = _signal.signal(_signal.SIGWINCH, lambda *_: None)
            self._pipe = (read_fd, write_fd)
        except (ValueError, OSError, AttributeError):
            # Not the main thread, or a platform without SIGWINCH. The session
            # still works; it just will not follow a resize.
            self._pipe = None
        return self

    def __exit__(self, *exc_info) -> None:
        if self._pipe is not None:
            _signal.set_wakeup_fd(self._previous_wakeup)
            if self._previous_handler is not None:
                _signal.signal(_signal.SIGWINCH, self._previous_handler)
            for fd in self._pipe:
                os.close(fd)
            self._pipe = None

        if self._saved is not None:
            import termios

            # TCSADRAIN, not TCSANOW: whatever the remote program wrote last
            # should land before the terminal changes out from under it.
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
            self._saved = None
