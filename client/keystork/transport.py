"""Length-prefixed protobuf framing over a stream socket.

Frames are a 4-byte big-endian length followed by that many bytes of serialized
protobuf. The exchange is strictly synchronous -- one request, one response --
so this is deliberately a blocking, unmultiplexed transport.
"""

from __future__ import annotations

import socket
import struct

from .errors import ConnectionClosed, ProtocolError

# Must match kMaxFrameBytes in the server's framing.h.
MAX_FRAME_BYTES = 16 * 1024 * 1024

_HEADER = struct.Struct(">I")


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
