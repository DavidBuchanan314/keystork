#include "framing.h"

#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace keystork {
namespace {

// Reads exactly `len` bytes. Returns kOk, or kEof if nothing at all had been
// read yet, or kTruncated if the peer vanished mid-way.
FrameStatus ReadFully(int fd, void* buf, size_t len) {
  auto* p = static_cast<uint8_t*>(buf);
  size_t done = 0;
  while (done < len) {
    ssize_t n = ::read(fd, p + done, len - done);
    if (n > 0) {
      done += static_cast<size_t>(n);
      continue;
    }
    if (n == 0) return done == 0 ? FrameStatus::kEof : FrameStatus::kTruncated;
    if (errno == EINTR) continue;
    return FrameStatus::kIoError;
  }
  return FrameStatus::kOk;
}

bool WriteFully(int fd, const void* buf, size_t len) {
  const auto* p = static_cast<const uint8_t*>(buf);
  size_t done = 0;
  while (done < len) {
    ssize_t n = ::write(fd, p + done, len - done);
    if (n > 0) {
      done += static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

}  // namespace

FrameStatus ReadFrame(int fd, std::string* out) {
  uint8_t header[4];
  FrameStatus status = ReadFully(fd, header, sizeof(header));
  if (status != FrameStatus::kOk) return status;

  const uint32_t len = (static_cast<uint32_t>(header[0]) << 24) |
                       (static_cast<uint32_t>(header[1]) << 16) |
                       (static_cast<uint32_t>(header[2]) << 8) |
                       static_cast<uint32_t>(header[3]);
  if (len > kMaxFrameBytes) return FrameStatus::kTooLarge;

  out->assign(len, '\0');
  if (len == 0) return FrameStatus::kOk;

  // A zero-length body is legal (an all-defaults message), but a truncated one
  // is not, so an EOF here is kTruncated rather than kEof.
  status = ReadFully(fd, out->data(), len);
  return status == FrameStatus::kEof ? FrameStatus::kTruncated : status;
}

bool WriteFrame(int fd, const std::string& payload) {
  if (payload.size() > kMaxFrameBytes) return false;

  const uint32_t len = static_cast<uint32_t>(payload.size());
  const uint8_t header[4] = {
      static_cast<uint8_t>(len >> 24),
      static_cast<uint8_t>(len >> 16),
      static_cast<uint8_t>(len >> 8),
      static_cast<uint8_t>(len),
  };
  if (!WriteFully(fd, header, sizeof(header))) return false;
  return payload.empty() || WriteFully(fd, payload.data(), payload.size());
}

const char* ToString(FrameStatus status) {
  switch (status) {
    case FrameStatus::kOk: return "ok";
    case FrameStatus::kEof: return "eof";
    case FrameStatus::kTruncated: return "truncated frame";
    case FrameStatus::kTooLarge: return "frame exceeds maximum size";
    case FrameStatus::kIoError: return "i/o error";
  }
  return "unknown";
}

}  // namespace keystork
