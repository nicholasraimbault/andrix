// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstddef>
#include <cstdint>
namespace andrix::work_probe {
constexpr uint32_t kMagic = 0x574c5052;
constexpr size_t kBody = 8192, kOutput = 4096;
enum class Operation : uint32_t {
  Inspect = 1,
  Start,
  Release,
  ContinueCreation,
  Stop
};
enum Flags : uint32_t { HoldCreation = 1, HoldRelease = 2, QueueThenStop = 4 };
struct Command {
  uint32_t magic = kMagic;
  Operation operation = Operation::Inspect;
  uint64_t boot = 0, instance = 0, manager = 0;
  uint32_t slot = 0, flags = 0, bytes = 0, reserved = 0;
};
struct Snapshot {
  uint32_t magic = kMagic;
  int32_t error = 0;
  uint64_t boot = 0, instance = 0, manager = 0, serial = 0, platform = 0,
           generation = 0;
  uint64_t device = 0, inode = 0, output_bytes = 0;
  int32_t pid = 0, exit_code = 0, launch_error = 0, cleanup_error = 0;
  uint32_t started = 0, creator_pending = 0, staged = 0, queued = 0,
           committed = 0, stopped = 0, reaped = 0, no_process = 0, empty = 0,
           retired = 0, blocked = 0, gate_refused = 0, authority_failed = 0;
  char output[kOutput]{};
};
}  // namespace andrix::work_probe
