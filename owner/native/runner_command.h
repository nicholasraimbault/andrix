// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace andrix {
enum class RunnerMode { Invalid, Plain, TmuxNew, TmuxAttach };
struct RunnerCommand {
  RunnerMode mode = RunnerMode::Invalid;
  std::string socket_name;
};
inline RunnerCommand runner_command(int argc, const char* const* argv, bool keep_enabled) {
  if (argc == 1) return {RunnerMode::Plain, {}};
  if (!keep_enabled || argc != 3 || !argv || !argv[1] || !argv[2]) return {};
  const std::string_view mode(argv[1]), id(argv[2]);
  if (mode != "--tmux-new" && mode != "--tmux-attach") return {};
  if (id.empty() || id.size() > 19 || id.front() == '0') return {};
  uint64_t value = 0;
  for (char c : id) {
    if (c < '0' || c > '9' || value > (uint64_t{INT64_MAX} - (c - '0')) / 10) return {};
    value = value * 10 + (c - '0');
  }
  return {mode == "--tmux-new" ? RunnerMode::TmuxNew : RunnerMode::TmuxAttach,
          "andrix-" + std::string(id)};
}
} // namespace andrix
