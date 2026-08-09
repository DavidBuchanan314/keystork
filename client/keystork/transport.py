"""Length-prefixed protobuf framing over a stream socket.

Frames are a 4-byte big-endian length followed by that many bytes of serialized
protobuf. Commands and keystore requests are strictly synchronous -- one
request, one response -- so `Transport` is deliberately blocking and
unmultiplexed.

The exec subprotocol is the exception: both sides send unprompted, so it cannot
block on either. `FrameReader` and `encode_frame` are the same framing with the
socket left to the caller, which is what `keystork.process` selects on.
"""

from __future__ import annotations

import contextlib
import socket
import struct
from typing import Optional

from .errors import ConnectionClosed, ProtocolError

# Must match kMaxFrameBytes in the server's framing.h.
MAX_FRAME_BYTES = 16 * 1024 * 1024

_HEADER = struct.Struct(">I")


def encode_frame(payload: bytes) -> bytes:
    """One framed message, ready to be written."""
    if len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError(
            f"message of {len(payload)} bytes exceeds the {MAX_FRAME_BYTES}-byte frame limit"
        )
    return _HEADER.pack(len(payload)) + payload


class FrameReader:
    """The framing, decoupled from the read.

    Bytes go in as they arrive off a non-blocking socket and whole frames come
    out, so a caller that must also watch other descriptors is never left
    sitting inside a read waiting for the rest of a message.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        self._buffer += data

    def __iter__(self):
        """Every whole frame buffered right now, consuming as it goes."""
        while True:
            if len(self._buffer) < _HEADER.size:
                return
            (length,) = _HEADER.unpack_from(self._buffer)
            if length > MAX_FRAME_BYTES:
                raise ProtocolError(
                    f"daemon announced a {length}-byte frame, "
                    f"over the {MAX_FRAME_BYTES}-byte limit"
                )
            end = _HEADER.size + length
            if len(self._buffer) < end:
                return
            frame = bytes(self._buffer[_HEADER.size : end])
            del self._buffer[:end]
            yield frame


class Transport:
    """Frames messages onto a connected socket. Not thread-safe by design."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock: socket.socket | None = sock

    @property
    def closed(self) -> bool:
        return self._sock is None

    def send(self, message) -> None:
        """Serialize and write one protobuf message."""
        sock = self._require_open()
        payload = message.SerializeToString()
        if len(payload) > MAX_FRAME_BYTES:
            raise ProtocolError(
                f"message of {len(payload)} bytes exceeds the {MAX_FRAME_BYTES}-byte frame limit"
            )
        try:
            sock.sendall(_HEADER.pack(len(payload)) + payload)
        except OSError as exc:
            self.close()
            raise ConnectionClosed(f"write failed: {exc}") from exc

    def recv(self, message):
        """Read one frame and parse it into `message`, which is returned."""
        header = self._read_exactly(_HEADER.size, at_frame_boundary=True)
        (length,) = _HEADER.unpack(header)
        if length > MAX_FRAME_BYTES:
            self.close()
            raise ProtocolError(
                f"server announced a {length}-byte frame, over the {MAX_FRAME_BYTES}-byte limit"
            )

        payload = self._read_exactly(length) if length else b""
        try:
            message.ParseFromString(payload)
        except Exception as exc:  # protobuf raises DecodeError, and subclasses vary
            raise ProtocolError(f"could not parse {type(message).__name__}: {exc}") from exc
        return message

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    @contextlib.contextmanager
    def deadline(self, timeout: Optional[float]):
        """Widen the socket timeout for one exchange, then put it back.

        For the commands that go away and do something rather than answering
        immediately. `None` leaves the socket as it is.
        """
        sock = self._require_open()
        if timeout is None:
            yield
            return
        previous = sock.gettimeout()
        sock.settimeout(timeout)
        try:
            yield
        finally:
            if self._sock is not None:
                self._sock.settimeout(previous)

    def borrow(self) -> socket.socket:
        """Lend the socket out, keeping it.

        For an exec session, whose two directions run independently while the
        child lives. The borrower is expected to hand it back in the state it
        found it -- blocking, at a frame boundary -- which for exec is exactly
        what the child's exit event guarantees.
        """
        return self._require_open()

    def detach(self) -> socket.socket:
        """Give the socket up for good.

        This transport is spent afterwards and closing it is a no-op; whoever
        took it owns closing it now.
        """
        sock = self._require_open()
        self._sock = None
        return sock

    def _require_open(self) -> socket.socket:
        if self._sock is None:
            raise ConnectionClosed("the session is closed")
        return self._sock

    def _read_exactly(self, count: int, at_frame_boundary: bool = False) -> bytes:
        sock = self._require_open()
        chunks = []
        remaining = count
        while remaining:
            try:
                chunk = sock.recv(remaining)
            except OSError as exc:
                self.close()
                raise ConnectionClosed(f"read failed: {exc}") from exc
            if not chunk:
                self.close()
                # A hang-up between frames is the daemon ending the session --
                # usually because it refused the connection or the child died.
                # A hang-up mid-frame is a broken exchange either way.
                if at_frame_boundary and remaining == count:
                    raise ConnectionClosed("the daemon closed the session")
                raise ProtocolError(
                    f"connection closed {count - remaining} bytes into a {count}-byte read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
