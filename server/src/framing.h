#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace keystork {

// Every message is a 4-byte big-endian length followed by that many bytes of
// serialized protobuf. A frame longer than this is rejected without reading the
// body: the largest thing this protocol legitimately carries is a chunk of key
// material or a certificate chain, all far below the cap, so an oversized
// length is either a bug or an attempt to make the daemon allocate.
inline constexpr uint32_t kMaxFrameBytes = 16u * 1024u * 1024u;

enum class FrameStatus {
  kOk,
  kEof,        // clean EOF on a frame boundary: the peer hung up normally
  kTruncated,  // EOF partway through a length or body
  kTooLarge,   // length prefix exceeded kMaxFrameBytes
  kIoError,
};

// Blocking read of one whole frame into `out`. Retries on EINTR.
FrameStatus ReadFrame(int fd, std::string* out);

// Blocking write of one whole frame. Returns false on any I/O failure,
// including EPIPE when the peer has gone away.
bool WriteFrame(int fd, const std::string& payload);

// Writes the 4-byte big-endian length prefix for a `length`-byte body.
void EncodeFrameHeader(uint32_t length, uint8_t header[4]);

const char* ToString(FrameStatus status);

// The same framing for a socket that cannot be blocked on: bytes go in as they
// arrive and whole frames come out. The exec subprotocol needs this because it
// polls the client alongside the child's stdio, so it can never afford to sit
// inside ReadFrame waiting for the rest of a message.
class FrameBuffer {
 public:
  void Append(const void* data, size_t length);

  // Moves the next whole frame into `out` and returns true. False means only
  // that more bytes are needed -- unless over_limit(), which is fatal and
  // sticky: the length prefix named a frame past kMaxFrameBytes, so the stream
  // can no longer be resynchronized.
  bool Next(std::string* out);

  bool over_limit() const { return over_limit_; }

  // Bytes appended but not yet part of a whole frame. Whoever stops using a
  // FrameBuffer mid-stream has to take these with them: they were read off the
  // socket and are gone from it, so dropping them would silently eat whatever
  // the peer sent next.
  std::string Rest() const { return buffer_.substr(head_); }

 private:
  std::string buffer_;
  size_t head_ = 0;
  bool over_limit_ = false;
};

}  // namespace keystork
