// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "work_peer.h"

namespace andrix {

// Internal candidate framing, not a released operation/API schema. Higher
// layers must validate operation, exact manager/work reference and retry key.
// The transport cannot turn matching packet metadata into authority.
enum class WorkFrameKind : uint32_t { Request = 1, Reply = 2 };
struct WorkFrameHeader {
  uint64_t magic = 0x414e445857434831ULL;
  uint32_t version = 1;
  WorkFrameKind kind = WorkFrameKind::Request;
  uint64_t correlation = 0;
  uint32_t operation = 0, bytes = 0, descriptors = 0, reserved = 0;
};
static_assert(sizeof(WorkFrameHeader) == 40);
constexpr size_t kWorkFrameBytes = 64 * 1024;
constexpr size_t kWorkFrameDescriptors = 3;

class WorkFrame {
 public:
  WorkFrame() = default;
  ~WorkFrame();
  WorkFrame(const WorkFrame&) = delete;
  WorkFrame& operator=(const WorkFrame&) = delete;
  const WorkFrameHeader& header() const { return header_; }
  std::span<const uint8_t> body() const { return {bytes_.data(), size_}; }
  size_t descriptor_count() const { return count_; }
  int Take(size_t index);
  void Reset();

 private:
  friend int ReceiveCorrelatedWorkFrame(int, const WorkPeerEndpoint&,
                                        WorkFrame&);
  WorkFrameHeader header_{};
  std::array<uint8_t, kWorkFrameBytes> bytes_{};
  size_t size_ = 0, count_ = 0;
  std::array<int, kWorkFrameDescriptors> descriptors_{-1, -1, -1};
};

int SendWorkFrame(int socket, const WorkFrameHeader& header,
                  std::span<const uint8_t> body = {},
                  std::span<const int> descriptors = {});
// Nonblocking framing, connection correlation and actual UID/GID checks ONLY.
// Same-principal FD sharing is allowed. No PID is used as authority. A service
// must not dispatch operations without the separate MAC authorization layer.
int ReceiveCorrelatedWorkFrame(int socket, const WorkPeerEndpoint& endpoint,
                               WorkFrame& result);
// Requires an actually authorized peer and enforces request/reply direction.
// Missing SO_PEERSEC has no UID-only authorization fallback.
int ReceiveAuthorizedWorkFrame(int socket, const AuthorizedWorkPeer& peer,
                               WorkFrame& result);

}  // namespace andrix
