// SPDX-License-Identifier: Apache-2.0
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>

#include "snapshot_output.h"

namespace proof = andrix::work_probe;

int main() {
  static_assert(proof::kMagic != 0x574c5052);  // Old C string protocol.
  static_assert(sizeof(proof::Snapshot) == offsetof(proof::Snapshot, output) +
                                             proof::kOutput);
  proof::Snapshot state;
  std::string json = "stale";
  assert(proof::SnapshotOutputJson(state, json) && json == "\"\"");

  // The original failure: the proc SID has a NUL before the later shell output.
  constexpr char payload[] = "u:r:andrix_owner:s0\0FRESH_CE_OWNER_EXECUTION\n";
  memcpy(state.output, payload, sizeof(payload) - 1);
  state.output_size = sizeof(payload) - 1;
  state.output_bytes = state.output_size;
  assert(std::string_view(state.output).size() < state.output_size);
  assert(proof::SnapshotOutputJson(state, json));
  assert(json == "\"u:r:andrix_owner:s0\\u0000FRESH_CE_OWNER_EXECUTION\\u000a\"");

  // An explicit short window does not expose later buffer contents. Neither the
  // cumulative count nor an early terminator is the retained window length.
  state.output_size = 1;
  state.output_bytes = std::numeric_limits<uint64_t>::max();
  assert(proof::SnapshotOutputJson(state, json) && json == "\"u\"");
  state.output[0] = '\0';
  assert(proof::SnapshotOutputJson(state, json) && json == "\"\\u0000\"");

  memset(state.output, '\xff', sizeof(state.output));
  state.output_size = proof::kOutput - 1;
  assert(proof::SnapshotOutputJson(state, json));
  assert(json.size() == 2 + 6 * (proof::kOutput - 1));
  state.output_size = proof::kOutput;
  assert(!proof::SnapshotOutputJson(state, json) && json.empty());
  state.output_size = std::numeric_limits<uint32_t>::max();
  assert(!proof::SnapshotOutputJson(state, json) && json.empty());

  // Exercise the actual fixed snapshot bytes over a local packet socket. This
  // is transport/encoding evidence, not peer authentication or Android policy.
  state = {};
  state.output_size = 256;
  state.output_bytes = 10000;  // A tail of a longer diagnostic capture.
  for (unsigned int i = 0; i < state.output_size; ++i)
    state.output[i] = static_cast<char>(i);
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
  assert(send(pair[0], &state, sizeof(state), MSG_NOSIGNAL) ==
         static_cast<ssize_t>(sizeof(state)));
  proof::Snapshot received;
  assert(recv(pair[1], &received, sizeof(received), MSG_TRUNC) ==
         static_cast<ssize_t>(sizeof(received)));
  assert(close(pair[0]) == 0 && close(pair[1]) == 0);
  assert(memcmp(&state, &received, sizeof(state)) == 0);
  assert(proof::SnapshotOutputJson(received, json));
  assert(json.find("\\u0000\\u0001") != std::string::npos);
  assert(json.find("\\\"") != std::string::npos);
  assert(json.find("\\\\") != std::string::npos);
  assert(json.ends_with("\\u00fe\\u00ff\""));
  // Python independently parses this JSON and checks all 256 byte values.
  puts(json.c_str());
}
