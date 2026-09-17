// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <sys/types.h>

#include <array>
#include <cstdint>

#include "captured_cgroup.h"

namespace andrix::supervision {

// Private local IPC between the Android supervisor and its fixed cleanup
// worker. No public socket, arbitrary exec, UID/profile selector or owner work
// identity.
enum class WorkerOperation : uint32_t {
  Initialize = 1,
  Kill,
  Observe,
  Step,
  DropCursor,
  ConfirmRemoved,
  Exit
};
struct WorkerPacket {
  uint32_t magic = 0x44534350;
  uint32_t version = 1;
  uint64_t boot = 0, instance = 0, worker = 0, sequence = 0;
  WorkerOperation operation = WorkerOperation::Initialize;
  uint32_t quantum = 0;
  GroupError error = GroupError::None;
  int32_t error_number = 0;
  GroupPopulation population = GroupPopulation::Unknown;
  CursorState cursor = CursorState::Progress;
  std::array<GroupIdentity, 4> objects{};
  CleanupLimits limits{};
  CleanupStats stats{};
  std::array<char, 128> name{};
};
static_assert(sizeof(WorkerPacket) <= 512);

struct WorkerPeer {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};
struct ReceivedWorkerPacket {
  WorkerPacket packet{};
  std::array<int, 4> descriptors{-1, -1, -1, -1};
  size_t descriptor_count = 0;
  ReceivedWorkerPacket() = default;
  ~ReceivedWorkerPacket();
  ReceivedWorkerPacket(const ReceivedWorkerPacket&) = delete;
  ReceivedWorkerPacket& operator=(const ReceivedWorkerPacket&) = delete;
};

// SO_PASSCRED is mandatory on BOTH endpoints. The actual sender of each packet
// is checked with SCM_CREDENTIALS, not socketpair's creator-only SO_PEERCRED.
int ConfigureWorkerSocket(int fd);
int SendWorkerPacket(int fd, const WorkerPacket& packet,
                     const int* descriptors = nullptr, size_t count = 0);
int ReceiveWorkerPacket(int fd, WorkerPeer expected,
                        ReceivedWorkerPacket& received);

// The fixed trusted bootstrap validates its UID/SID and parent before entry.
// It must have closed all unrelated inherited FDs. This loop validates actual
// per-message peer credentials and immutable instance/worker/sequence binding.
// Blocking kernel operations occur here, never in the supervisor event loop.
int RunCleanupWorker(int fd, WorkerPeer parent);

}  // namespace andrix::supervision
