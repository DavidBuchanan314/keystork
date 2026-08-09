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

void EncodeFrameHeader(uint32_t length, uint8_t header[4]) {
  header[0] = static_cast<uint8_t>(length >> 24);
  header[1] = static_cast<uint8_t>(length >> 16);
  header[2] = static_cast<uint8_t>(length >> 8);
  header[3] = static_cast<uint8_t>(length);
}

bool WriteFrame(int fd, const std::string& payload) {
  if (payload.size() > kMaxFrameBytes) return false;

  uint8_t header[4];
  EncodeFrameHeader(static_cast<uint32_t>(payload.size()), header);
  if (!WriteFully(fd, header, sizeof(header))) return false;
  return payload.empty() || WriteFully(fd, payload.data(), payload.size());
}

void FrameBuffer::Append(const void* data, size_t length) {
  // Reclaim what has already been handed out before growing, so a long-lived
  // stream does not keep every frame it ever carried.
  if (head_ > 0 && head_ == buffer_.size()) {
    buffer_.clear();
    head_ = 0;
  } else if (head_ > buffer_.size() / 2) {
    buffer_.erase(0, head_);
    head_ = 0;
  }
  buffer_.append(static_cast<const char*>(data), length);
}

bool FrameBuffer::Next(std::string* out) {
  if (over_limit_) return false;

  const size_t available = buffer_.size() - head_;
  if (available < 4) return false;

  const auto* p = reinterpret_cast<const uint8_t*>(buffer_.data()) + head_;
  const uint32_t length = (static_cast<uint32_t>(p[0]) << 24) |
                          (static_cast<uint32_t>(p[1]) << 16) |
                          (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
  if (length > kMaxFrameBytes) {
    over_limit_ = true;
    return false;
  }
  if (available - 4 < length) return false;

  out->assign(buffer_, head_ + 4, length);
  head_ += 4 + length;
  return true;
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
