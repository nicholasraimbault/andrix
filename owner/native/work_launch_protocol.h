// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <sys/types.h>

#include <array>
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
  uint32_t version = 1;
  WorkLaunchOperation operation = WorkLaunchOperation::Prepare;
  WorkIdentity work{};
  AuthorityEpoch epoch{};
  LaunchObjectIdentity aggregate{}, scope{};
  int32_t error = 0;
  uint32_t reserved = 0;
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
  Count
};
constexpr size_t kLaunchFdCount = static_cast<size_t>(LaunchFd::Count);
struct WorkLaunchMessage {
  WorkLaunchPacket packet{};
  std::array<int, kLaunchFdCount> descriptors{-1, -1, -1, -1, -1, -1, -1};
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
int SendWorkLaunch(int socket, const WorkLaunchPacket& packet,
                   const int* descriptors = nullptr, size_t count = 0);
// Nonblocking. Actual per-message kernel credentials, strict framing and FD
// ownership. A claimed PID/UID or socketpair creator-only peer record is not
// enough.
int ReceiveWorkLaunch(int socket, LaunchPeer expected,
                      WorkLaunchMessage& result);

}  // namespace andrix
