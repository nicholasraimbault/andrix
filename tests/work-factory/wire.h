// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>

namespace andrix::factory_proof {
constexpr uint32_t kMagic = 0x46504332;
constexpr uint64_t kMemory = 268435456;
constexpr char kManagerService[] = "andrix.proof.factory";
constexpr char kGuardian[] = "/system_ext/bin/andrix-factory-guardian-probe";
constexpr char kWorker[] = "/system_ext/bin/andrix-factory-worker-probe";
constexpr char kUidGroup[] = "/sys/fs/cgroup/system/uid_7500";
constexpr char kSocketLabel[] = "u:object_r:andrix_factory_probe_socket:s0";

enum Phase : int32_t {
  Preparing,
  Ready,
  Holding,
  Held,
  Released,
  Stopping,
  Removed
};
enum Operation : uint32_t { Hello = 1, State, Hold, Release, Stop, Accept };
struct Packet {
  uint32_t magic = kMagic;
  uint32_t operation = 0;
  uint64_t manager = 0;
  uint64_t work = 0;
  int32_t guardian = 0;
  int32_t entry = 0;
  int32_t phase = 0;
  int32_t entry_exited = 0;
  int32_t descendants[2] = {};
  uint64_t pulses = 0;
  int32_t crash = 0;
  int32_t reserved = 0;
};
static_assert(sizeof(Packet) < 512);

constexpr uint32_t kWorkerMagic = 0x46505732;
enum WorkerKind : uint32_t { WorkerHeld = 1, WorkerPulse };
struct WorkerEvent {
  uint32_t magic = kWorkerMagic;
  uint32_t kind = 0;
  int32_t pid = 0, parent = 0, session = 0, group = 0, uid = 0;
  int32_t binder_errno = 0, cgroup_errno = 0;
};
static_assert(sizeof(WorkerEvent) < 512);
}  // namespace andrix::factory_proof
