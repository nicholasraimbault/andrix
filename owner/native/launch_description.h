// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace andrix {

// Ordinary owner execution only. No bootstrap path, UID/GID/capability/SID,
// supervisor resource path, authority epoch or inherited management descriptor.
// Execve semantics: arguments include argv[0]; no implicit shell or PATH
// search.
struct LaunchDescription {
  std::string executable;
  std::vector<std::string> arguments;
  std::vector<std::string> environment;
  std::string directory;
  bool operator==(const LaunchDescription&) const = default;
};
struct LaunchLimits {
  size_t bytes = 256 * 1024;
  size_t arguments = 1024;
  size_t environment = 1024;
};  // Candidate parser bounds, not permanent owner program restrictions.
enum class LaunchError { None, Invalid, Limit, Framing, NotSealed, Io };
struct LaunchFailure {
  LaunchError code = LaunchError::None;
  int error = 0;
};

// Byte strings, not a command language. Embedded NUL is refused. Environment
// order, duplicate keys and LD_* values are preserved for the final OWNER exec;
// they must never be applied to the trusted bootstrap's own environment.
bool EncodeLaunch(const LaunchDescription& description, LaunchLimits limits,
                  std::vector<uint8_t>& result, LaunchFailure& failure);
bool DecodeLaunch(const std::vector<uint8_t>& bytes, LaunchLimits limits,
                  LaunchDescription& result, LaunchFailure& failure);
// Create immutable descriptor-owned request bytes outside any control mutex.
// Caller owns the returned read-only FD. There is no file/path fallback if
// memfd seals fail. A verified reopen of our own held descriptor removes write
// access.
int SealLaunch(const LaunchDescription& description, LaunchLimits limits,
               LaunchFailure& failure);
// Does not take ownership. Read only, bounded and all-or-nothing. Actual source
// authentication and work/epoch association remain the private transport's job.
bool ReadLaunch(int fd, LaunchLimits limits, LaunchDescription& result,
                LaunchFailure& failure);

}  // namespace andrix
