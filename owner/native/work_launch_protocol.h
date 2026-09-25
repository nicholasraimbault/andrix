// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <sys/types.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include "work_admission.h"

namespace andrix {

// Private complete launch transition, not a public service or credential API.
enum class WorkLaunchOperation : uint32_t { Prepare = 1, Staged, Wake, Failed };
struct LaunchObjectIdentity {
  uint64_t device = 0, inode = 0;
  bool operator==(const LaunchObjectIdentity&) const = default;
};
struct WorkLaunchPacket {
  uint64_t magic = 0x414e44584c41554eULL;
  uint32_t version = 3;
  WorkLaunchOperation operation = WorkLaunchOperation::Prepare;
  WorkIdentity work{};
  AuthorityEpoch epoch{};
  LaunchObjectIdentity aggregate{}, scope{};
  // Bits 0, 1 and 2 explicitly close stdin, stdout and stderr. All other bits
  // are invalid. The default preserves the existing all open launch vehicle.
  uint32_t stdio_closed = 0;
  int32_t error = 0;
  uint32_t reserved = 0;
  // Internal selection only. A value of 1 requires a separate immutable
  // PrincipalLaunch descriptor. It is never part of the ordinary request.
  uint32_t principal_profile = 0;
};
static_assert(sizeof(WorkLaunchPacket) <= 256);
enum class LaunchFd : size_t {
  Gate,
  Description,
  Aggregate,
  Scope,
  Input,
  Output,
  Error,
  Principal,
  Home,
  Count
};
constexpr size_t kLaunchFdCount = static_cast<size_t>(LaunchFd::Count);
constexpr uint32_t kWorkLaunchStdioMask = 0x7;
// Actual SCM_RIGHTS count for a valid packet, not the fixed Prepare input size.
// Non-Prepare operations retain stdio_closed but never carry descriptors.
size_t ExpectedWorkLaunchFdCount(const WorkLaunchPacket& packet);
struct WorkLaunchMessage {
  WorkLaunchPacket packet{};
  std::array<int, kLaunchFdCount> descriptors{-1, -1, -1, -1, -1, -1, -1, -1, -1};
  // Number received, not the number of roles or descriptors still owned.
  size_t count = 0;
  WorkLaunchMessage() = default;
  ~WorkLaunchMessage();
  WorkLaunchMessage(const WorkLaunchMessage&) = delete;
  WorkLaunchMessage& operator=(const WorkLaunchMessage&) = delete;
  int Take(LaunchFd role);
};
struct LaunchPeer {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};
int ConfigureWorkLaunchSocket(int socket);
// Prepare borrows exactly kLaunchFdCount fixed roles. Explicitly closed
// standard roles must be -1. The Principal role must be -1 when
// principal_profile is 0, and valid when it is 1, as must the captured Home
// directory role. Other management and open
// standard roles must be valid descriptors. The wire follows the fixed role
// order with closed roles omitted; Principal and Home follow standard I/O.
// Every other operation takes count == 0 and sends no descriptors.
int SendWorkLaunch(int socket, const WorkLaunchPacket& packet,
                   const int* descriptors = nullptr, size_t count = 0);
// Nonblocking. Actual per-message kernel credentials, strict framing and FD
// ownership. Prepare receipts map back to fixed roles, with -1 for closed
// standard roles. A claimed PID/UID or socketpair creator-only peer record is
// not enough.
int ReceiveWorkLaunch(int socket, LaunchPeer expected,
                      WorkLaunchMessage& result);

}  // namespace andrix
