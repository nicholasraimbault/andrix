// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

namespace andrix {

// Internal identities, not caller supplied authority. The work registry must
// allocate non-reused identities for its manager lifetime.
struct WorkIdentity {
  uint64_t manager = 0;
  uint64_t serial = 0;
  bool operator==(const WorkIdentity&) const = default;
};
struct AuthorityEpoch {
  uint64_t platform = 0;
  uint64_t generation = 0;
  int32_t user = -1;
  bool operator==(const AuthorityEpoch&) const = default;
};

enum class AdmissionPhase {
  Unbound,
  Binding,
  Admitted,
  Prepared,
  Publishing,
  Released,
  Entered,
  Stopped
};
enum class EntryResult {
  Entered,
  NotReleased,
  Stopped,
  Expired,
  Foreign,
  AlreadyEntered
};
enum class AdmissionResult {
  Accepted,
  NotReady,
  Revoked,
  Foreign,
  Stopped,
  WrongState,
  Capacity,
  Invalid
};

class AdmissionAuthority;
// One shared kernel object per reserved work. A wake packet is never permission.
// The trusted launcher claims it at the declared launch commitment, then closes
// and unmaps management handles before the final owner-role transition. Claim
// success is permission, not successful program exec. Linux lock-free shared
// uint32 atomics and a sealed-size memfd are required.
class WorkAdmission {
 public:
  static std::shared_ptr<WorkAdmission> Reserve(WorkIdentity work, int& error);
  // Takes ownership even on failure. Caller must authenticate the private peer
  // and expected request/epoch independently; matching bytes alone are not
  // trust.
  static std::shared_ptr<WorkAdmission> Adopt(int owned_fd, WorkIdentity work,
                                              AuthorityEpoch epoch, int& error);
  ~WorkAdmission();
  WorkAdmission(const WorkAdmission&) = delete;
  WorkAdmission& operator=(const WorkAdmission&) = delete;
  int Export(int& error) const;
  WorkIdentity work() const;
  std::optional<AuthorityEpoch> epoch() const;
  AdmissionPhase phase() const;
  bool entered() const;
  // No registry, observer, admission or terminal mutex; no syscall or external
  // I/O. Closes permission only. This is NOT process exit, cleanup or work
  // completion.
  bool Stop();
  EntryResult ClaimEntry(WorkIdentity work, AuthorityEpoch epoch, uint64_t now);

 private:
  struct Shared;
  WorkAdmission(int fd, Shared* mapping);
  bool Bind(AuthorityEpoch epoch);
  bool Prepared();
  bool Publish(uint64_t now, uint64_t deadline);
  int fd_;
  Shared* shared_;
  friend class AdmissionAuthority;
};

// Bounded control state driven by an authenticated platform adapter. Observe's
// deadline must come from query ISSUE time, not reply arrival. This class does
// not itself establish Android authority, authenticate callers or create work.
// A first binding stays fixed; mismatch, expiry or revocation fails
// permanently. A fresh authority object may admit NEW work, never rebind an old
// gate.
class AdmissionAuthority {
 public:
  static constexpr size_t kMaximumAdmissions =
      64;  // Candidate bound, not product quota.
  explicit AdmissionAuthority(size_t capacity = kMaximumAdmissions)
      : capacity_(capacity) {}
  ~AdmissionAuthority();
  AdmissionResult Observe(AuthorityEpoch epoch, uint64_t deadline,
                          uint64_t now);
  void Revoke();
  AdmissionResult Admit(const std::shared_ptr<WorkAdmission>& work,
                        uint64_t now);
  // Only the trusted verified staging/profile/resource transition may report
  // Prepared. The fixed final MAC transition still verifies the actual owner
  // profile before arbitrary execution. Late completion adds cleanup duties,
  // never permission for a stopped request.
  AdmissionResult Prepared(const std::shared_ptr<WorkAdmission>& work,
                           uint64_t now);
  // The adapter may shorten this publication for an outstanding query's
  // earlier failure deadline. The ceiling can never extend authority freshness.
  AdmissionResult Release(const std::shared_ptr<WorkAdmission>& work,
                          uint64_t now, uint64_t deadline_ceiling = UINT64_MAX);
  // Releases this registry slot only after its gate is stopped. External
  // creator, process and resource accounting remain the manager's separate
  // obligations.
  AdmissionResult Retire(const std::shared_ptr<WorkAdmission>& work);
  bool failed() const;

 private:
  bool Fresh(uint64_t now);  // Caller holds mutex_.
  void RevokeLocked();
  bool Registered(const std::shared_ptr<WorkAdmission>& work) const;
  mutable std::mutex mutex_;
  const size_t capacity_;
  std::array<std::shared_ptr<WorkAdmission>, kMaximumAdmissions> admissions_{};
  std::optional<AuthorityEpoch> epoch_;
  uint64_t deadline_ = 0, observed_ = 0;
  bool failed_ = false;
};

}  // namespace andrix
