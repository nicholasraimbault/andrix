// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "work_admission.h"

namespace andrix {

// Immutable principal credentials for one admitted work. They travel on the
// trusted launch path separately from the owner's executable, arguments and
// environment in LaunchDescription, which cannot select them. A trusted
// factory resolves them from Package Manager and user state. This component
// only validates, encodes, seals and reads that data. It is not authority,
// allocates no UID, stores no grant and is not a credential setter. The
// existing static UID 7500 launcher and owner entry do not read this record
// and retain their separate credential and Binder policy. The first consumer is an opt-in disposable
// ordinary Package Manager backed principal. No production UID range, signer
// or representation is selected here.
//
// Package name and UID identify the Android policy subject. They are never
// grants: Android's permission and AppOps services decide each capability
// when it is used. Nothing here expires, renews or records authority.
struct PrincipalBinding {
  // The validated native principal binding and its incarnation.
  uint64_t instance = 0, generation = 0;
  // Android user and its UserManager serial, which distinguishes a recycled
  // user ID.
  int32_t user = -1;
  int64_t user_serial = -1;
  // Package Manager's resolved application UID in that user; gid == uid.
  uint32_t uid = 0, gid = 0;
  std::string package_name;
  bool operator==(const PrincipalBinding&) const = default;
};
struct PrincipalProfile {
  PrincipalBinding binding;
  // The complete supplementary groups, applied exactly as listed. Empty
  // means none, never inherited or default groups.
  std::vector<uint32_t> supplementary_groups;
  std::string selinux_context;
  bool operator==(const PrincipalProfile&) const = default;
};
struct PrincipalLaunch {
  WorkIdentity work;
  AuthorityEpoch epoch;
  PrincipalProfile profile;
  bool operator==(const PrincipalLaunch&) const = default;
};

// Transport and parser bounds, not product quotas.
constexpr size_t kPrincipalLaunchMaximumBytes = 4096;
constexpr size_t kPrincipalMaximumGroups = 64;
constexpr size_t kPrincipalMaximumPackageName = 255;
constexpr size_t kPrincipalMaximumContext = 255;

// Syntax and identity class only. Passing is not authorization.
// - instance and generation are in [1, INT64_MAX]. user and user_serial are
//   not negative.
// - uid is an ordinary Android application UID of that user: user * 100000
//   plus an app ID in 10000..19999, with gid == uid. Root, system, shell, the
//   static owner, SDK sandbox, shared GID and isolated UIDs do not qualify.
//   No allocation is implied: Package Manager assigns the app ID.
// - package_name is ASCII, at most 255 bytes, with two or more segments
//   separated by '.'. Each is a letter, then letters, digits or underscores.
// - supplementary_groups holds at most 64 strictly ascending groups, none 0
//   or Linux's invalid ID 0xffffffff. Nothing is added, removed, sorted or
//   inherited, and no group is checked against a list.
// - selinux_context is user:role:type:range, at most 255 bytes of printable
//   ASCII without whitespace, in the normalized form the kernel reports for
//   Android's sN and cN level names. A consumer can therefore verify its
//   transition by exact comparison. Syntax is not permission to choose a role
//   or type: the trusted factory selects the exact context from policy, and an
//   owner request never supplies it.
bool ValidPrincipalProfile(const PrincipalProfile& profile);

// A launch needs nonzero uint64_t work identities, matching the existing work
// registry, epoch identifiers in [1, INT64_MAX], and epoch.user == binding.user. The strict little-endian version 1 record has
// exactly one encoding per value, within kPrincipalLaunchMaximumBytes. Invalid
// input fails with EINVAL. result changes only on success.
bool EncodePrincipalLaunch(const PrincipalLaunch& launch,
                           std::vector<uint8_t>& result, int& error);
// Accepts only what EncodePrincipalLaunch produces for a valid launch.
// EMSGSIZE above the bound, otherwise EPROTO for another magic or version, a
// size mismatch, nonzero reserved field, truncation, trailing byte or invalid
// value. result changes only on success.
bool DecodePrincipalLaunch(std::span<const uint8_t> bytes,
                           PrincipalLaunch& result, int& error);
// Returns an owned read-only close-on-exec descriptor for a memfd holding
// exactly the record, sealed against write, grow, shrink and further sealing.
// A verified reopen of the held memfd through /proc removes write access, and
// no mapping remains. Returns -1 with error set on failure. Call it outside
// any control mutex.
int SealPrincipalLaunch(const PrincipalLaunch& launch, int& error);
// Borrows the descriptor and never closes it or moves its offset. Requires a
// read-only, not O_PATH, completely sealed regular file within the bound whose
// exact bytes decode for the expected work and epoch, including its user.
// result changes only on success. Errors: EINVAL for an invalid expectation
// or an object that is not a completely sealed regular file, EBADF for a bad
// or O_PATH descriptor, EACCES for write access, EMSGSIZE, EPROTO, and ESTALE
// for another work, epoch or user.
//
// Sealing gives integrity, not authentication. An accepted descriptor's bytes
// can no longer change, but that proves neither who wrote them nor that they
// are current. The consumer must receive the descriptor over an authenticated
// private channel from the expected trusted coordinator, such as a Prepare
// message whose kernel credentials ReceiveWorkLaunch matched. It must take
// the expectations from that authenticated handoff, never from the record.
// Freshness comes from the admission gate, released only under a live
// authority epoch, and from closing admission before a binding generation is
// retired or reused.
bool ReadPrincipalLaunch(int borrowed_fd, WorkIdentity expected_work,
                         AuthorityEpoch expected_epoch,
                         PrincipalProfile& result, int& error);

}  // namespace andrix
