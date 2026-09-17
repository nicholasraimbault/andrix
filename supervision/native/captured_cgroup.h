// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace andrix::supervision {

// Internal kernel primitive. It is not a caller authorization or service API.
struct GroupIdentity {
  uint64_t device = 0;
  uint64_t inode = 0;
  bool operator==(const GroupIdentity&) const = default;
};

enum class GroupPopulation { Unknown, Populated, Empty, Removed };
struct PopulationResult {
  GroupPopulation state = GroupPopulation::Unknown;
  int error = 0;
};

enum class GroupError {
  None,
  InvalidArgument,
  WrongFilesystem,
  IdentityChanged,
  UnknownPopulation,
  Populated,
  Removed,
  Busy,
  Limit,
  Io,
};
struct Failure {
  GroupError code = GroupError::None;
  int error = 0;
  const char* operation = "";
};

struct CleanupLimits {
  size_t max_depth;
  size_t max_directory_visits;
  size_t max_entry_visits;
  size_t max_total_steps;
  size_t max_steps_per_call;
};

struct CleanupStats {
  size_t steps = 0;
  size_t directory_visits = 0;
  size_t entry_visits = 0;
  size_t removed_directories = 0;
};

// A trusted supervisor can transfer this exact descriptor cohort to its private
// cleanup process. It is not a serialized capability for an untrusted caller.
// Descriptor order is parent, root, kill, events. Metadata must travel through
// the authenticated private channel with the descriptors, never be re-resolved.
struct CgroupTransfer {
  std::array<int, 4> descriptors{-1, -1, -1, -1};
  std::array<GroupIdentity, 4> identities{};
  CleanupLimits limits{};
  CleanupStats stats{};
  std::string name;
  CgroupTransfer() = default;
  ~CgroupTransfer();
  CgroupTransfer(const CgroupTransfer&) = delete;
  CgroupTransfer& operator=(const CgroupTransfer&) = delete;
};

class ReclamationCursor;
class CapturedCgroup : public std::enable_shared_from_this<CapturedCgroup> {
 public:
  // The trusted allocator must have created this root exclusively, and must
  // retain exclusive ownership of its parent namespace until retirement.
  // Capture preserves an object; it does not prove fresh creation or grant
  // rights. Linux openat2 with beneath/no-symlink/no-mount-crossing is
  // required, no fallback.
  static std::shared_ptr<CapturedCgroup> Capture(int parent,
                                                 std::string_view name,
                                                 CleanupLimits limits,
                                                 Failure& failure);
  ~CapturedCgroup();
  CapturedCgroup(const CapturedCgroup&) = delete;
  CapturedCgroup& operator=(const CapturedCgroup&) = delete;

  GroupIdentity identity() const;
  std::unique_ptr<CgroupTransfer> Export(Failure& failure) const;
  static std::shared_ptr<CapturedCgroup> Adopt(
      std::unique_ptr<CgroupTransfer> transfer, Failure& failure);
  // Reconcile a lost worker reply using a formerly valid captured core event FD
  // reporting ENODEV AND absence of its owned parent entry. ENOENT alone is not
  // sufficient. A replaced name or permission error stays an explicit failure.
  Failure ConfirmRemoved();
  PopulationResult ObservePopulation() const;
  Failure Kill()
      const;  // Exact captured cgroup.kill only. Never numeric PID/PGID.

  // Caller must already have a valid lifecycle cleanup permit: Stop latched,
  // initial process exit/reap accounted for, all mutators closed and fresh
  // quiescence. This performs an additional fresh kernel emptiness check.
  // One cursor at a time. Dropping a cursor retains the root and cumulative
  // limits.
  std::unique_ptr<ReclamationCursor> BeginReclaim(Failure& failure);
  CleanupStats stats() const;
  bool removed() const;

 private:
  struct Impl;
  explicit CapturedCgroup(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
  friend class ReclamationCursor;
};

enum class CursorState { Progress, Retired, Blocked };
struct CleanupStep {
  CursorState state = CursorState::Progress;
  size_t steps = 0;
  Failure failure;
};

class ReclamationCursor {
 public:
  ~ReclamationCursor();
  ReclamationCursor(const ReclamationCursor&) = delete;
  ReclamationCursor& operator=(const ReclamationCursor&) = delete;

  // Bounded operation count, NOT a wall-time guarantee for kernel syscalls.
  // Run on the selected bounded cleanup lane, not blindly on init's critical
  // loop. Progress state and stats are single-owner; calls must not overlap.
  CleanupStep Step(size_t budget);

 private:
  struct Impl;
  ReclamationCursor(std::shared_ptr<CapturedCgroup> scope,
                    std::unique_ptr<Impl> impl);
  std::shared_ptr<CapturedCgroup> scope_;
  std::unique_ptr<Impl> impl_;
  friend class CapturedCgroup;
};

const char* population_name(GroupPopulation value);
const char* group_error_name(GroupError value);
namespace detail {
// Parsing alone supplies no kernel provenance or authorization.
PopulationResult ParsePopulation(std::string_view text);
}  // namespace detail

}  // namespace andrix::supervision
