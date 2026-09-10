// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>

namespace andrix::terminal {

// Output-only framing. Keyboard input remains a separately bounded byte stream.
// The caller must still enforce Binder identity, attachment generation and lease.
constexpr size_t kHeaderSize = 24;
constexpr size_t kFramePayloadLimit = 4096;
constexpr uint64_t kMaximumOffset = (uint64_t{1} << 63) - 1;
constexpr size_t kJournalLimit = 128 * 1024;

struct Header {
  uint32_t length = 0;
  uint64_t session = 0;
  uint64_t offset = 0;
};

// Big endian: magic "ATX1", payload length, session id, first byte offset.
// No zero-length, wrapped-offset or zero/negative-Java-long session frames.
bool encode_header(const Header& header, std::array<char, kHeaderSize>* bytes);
bool decode_header(std::string_view bytes, Header* header);
std::string encode_frame(uint64_t session, uint64_t offset, std::string_view payload);

struct Read {
  bool valid = false;
  bool gap = false;
  uint64_t offset = 0;
  std::string bytes;
};

// A bounded output journal, NOT a complete transcript. Sending does not consume
// bytes. The UI acknowledges only after applying complete frames to its parser.
// Overflow advances begin() and is explicit in read(); it never rebases offsets.
// The coordinator uses this core for its framed VT stream; host tests alone do
// not qualify Binder/SELinux or Android UI lifecycle behavior.
class OutputJournal {
 public:
  explicit OutputJournal(size_t capacity = kJournalLimit,
                         uint64_t sequence_limit = kMaximumOffset);
  bool append(std::string_view bytes); // offset exhaustion fails without mutation
  Read read(uint64_t offset, size_t maximum = kFramePayloadLimit) const;
  // Called by the producer only after a complete frame is written. A partially
  // written frame is discarded on socket replacement and MUST NOT advance this.
  bool delivered(uint64_t next_offset);
  // Untrusted RPC input must also pass the existing identity/generation/lease
  // guards. An acknowledgement beyond delivered data cannot free queued output.
  bool acknowledge(uint64_t next_offset);
  uint64_t begin() const { return begin_; }
  uint64_t end() const { return end_; }
  uint64_t acknowledged() const { return acknowledged_; }
  uint64_t delivered_end() const { return delivered_; }
  uint64_t dropped() const { return dropped_; }
  size_t size() const { return bytes_.size(); }

 private:
  const size_t capacity_;
  const uint64_t sequence_limit_;
  std::deque<char> bytes_;
  uint64_t begin_ = 0;
  uint64_t end_ = 0;
  uint64_t acknowledged_ = 0;
  uint64_t delivered_ = 0;
  uint64_t dropped_ = 0;
};

} // namespace andrix::terminal
