// SPDX-License-Identifier: Apache-2.0
#include "terminal_protocol.h"

#include <algorithm>
#include <utility>

namespace andrix::terminal {
namespace {
void put(char* target, uint64_t value, size_t length) {
  for (size_t i = 0; i < length; ++i)
    target[i] = static_cast<char>(value >> ((length - i - 1) * 8));
}
uint64_t get(const char* source, size_t length) {
  uint64_t value = 0;
  for (size_t i = 0; i < length; ++i)
    value = (value << 8) | static_cast<unsigned char>(source[i]);
  return value;
}
bool valid(const Header& h) {
  return h.length > 0 && h.length <= kFramePayloadLimit && h.session > 0 &&
         h.session <= kMaximumOffset && h.offset <= kMaximumOffset - h.length;
}
} // namespace

bool encode_header(const Header& header, std::array<char, kHeaderSize>* bytes) {
  if (!bytes || !valid(header)) return false;
  auto& b = *bytes;
  b[0] = 'A'; b[1] = 'T'; b[2] = 'X'; b[3] = '1';
  put(b.data() + 4, header.length, 4);
  put(b.data() + 8, header.session, 8);
  put(b.data() + 16, header.offset, 8);
  return true;
}

bool decode_header(std::string_view bytes, Header* header) {
  if (!header || bytes.size() != kHeaderSize || bytes.substr(0, 4) != "ATX1") return false;
  Header h{static_cast<uint32_t>(get(bytes.data() + 4, 4)),
           get(bytes.data() + 8, 8), get(bytes.data() + 16, 8)};
  if (!valid(h)) return false;
  *header = h;
  return true;
}

std::string encode_frame(uint64_t session, uint64_t offset, std::string_view payload) {
  if (payload.size() > kFramePayloadLimit) return {};
  Header header{static_cast<uint32_t>(payload.size()), session, offset};
  std::array<char, kHeaderSize> bytes{};
  if (!encode_header(header, &bytes)) return {};
  std::string frame(bytes.data(), bytes.size());
  frame.append(payload);
  return frame;
}

OutputJournal::OutputJournal(size_t capacity, uint64_t sequence_limit)
    : capacity_(std::min(capacity, kJournalLimit)),
      sequence_limit_(std::min(sequence_limit, kMaximumOffset)) {}

bool OutputJournal::append(std::string_view bytes) {
  if (bytes.size() > sequence_limit_ - end_) return false;
  for (char byte : bytes) {
    ++end_;
    if (capacity_ == 0) {
      ++begin_;
      ++dropped_;
      continue;
    }
    if (bytes_.size() == capacity_) {
      bytes_.pop_front();
      ++begin_;
      ++dropped_;
    }
    bytes_.push_back(byte);
  }
  return true;
}

Read OutputJournal::read(uint64_t offset, size_t maximum) const {
  if (offset > end_ || maximum == 0 || maximum > kFramePayloadLimit) return {};
  const uint64_t start = std::max(offset, begin_);
  const size_t count = static_cast<size_t>(std::min<uint64_t>(maximum, end_ - start));
  std::string result;
  result.reserve(count);
  const size_t index = static_cast<size_t>(start - begin_);
  for (size_t i = 0; i < count; ++i) result.push_back(bytes_[index + i]);
  return {true, offset < begin_, start, std::move(result)};
}

bool OutputJournal::delivered(uint64_t next_offset) {
  if (next_offset > end_) return false;
  delivered_ = std::max(delivered_, next_offset);
  return true;
}

bool OutputJournal::acknowledge(uint64_t next_offset) {
  if (next_offset > delivered_) return false;
  if (next_offset <= acknowledged_) return true;
  acknowledged_ = next_offset;
  while (begin_ < next_offset) {
    bytes_.pop_front();
    ++begin_;
  }
  return true;
}

} // namespace andrix::terminal
