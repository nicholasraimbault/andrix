// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>
namespace andrix::delegated_probe {
constexpr uint32_t kMagic = 0x44505246;
enum Operation : uint32_t { Inspect = 1, Populate, Release, Exit };
struct Packet {
  uint32_t magic = kMagic;
  Operation operation = Inspect;
  uint64_t boot = 0, instance = 0;
  int32_t pid = 0, children[2]{};
  uint64_t pulses[2]{}, root_device = 0, root_inode = 0, requests = 0;
  int32_t aggregate_write_errno = 0, ancestor_write_errno = 0;
  uint32_t released = 0;
  char group[256]{};
};
struct ReadyMessage {
  uint64_t magic = 0x44454c4547415445ULL, boot = 0, instance = 0, device = 0,
           inode = 0;
};
static_assert(sizeof(Packet) <= 512);
}  // namespace andrix::delegated_probe
