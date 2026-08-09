#pragma once

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

const char* ToString(FrameStatus status);

}  // namespace keystork
