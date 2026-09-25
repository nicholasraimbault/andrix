// SPDX-License-Identifier: Apache-2.0
// Host record, validation and descriptor controls. Not Package Manager
// resolution, credential transition or Android MAC qualification.
#include "principal_profile.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <utility>
#include <vector>

using namespace andrix;
namespace {
using Bytes = std::vector<uint8_t>;
constexpr uint64_t kLargest = std::numeric_limits<int64_t>::max();
constexpr int kSeals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
// Offsets in typical()'s record: package length, group count, context length.
constexpr size_t kPackageLength = 88, kGroupCount = 110, kContextLength = 122;

PrincipalLaunch typical() {
  PrincipalLaunch launch;
  launch.work = {11, 1};
  launch.epoch = {91, 8, 0};
  launch.profile.binding = {5, 3, 0, 0, 10123, 10123, "com.example.native"};
  launch.profile.supplementary_groups = {3003, 9997};
  launch.profile.selinux_context = "u:r:untrusted_app:s0:c139,c295,c512,c768";
  return launch;
}
// A different valid launch. Every refusal must leave it untouched.
PrincipalLaunch sentinel() {
  PrincipalLaunch launch;
  launch.work = {99, 98};
  launch.epoch = {97, 96, 10};
  launch.profile.binding = {95, 94, 10, 93, 1019999, 1019999,
                            "sentinel.Unchanged"};
  launch.profile.supplementary_groups = {1, 2, 3};
  launch.profile.selinux_context = "u:r:sentinel:s0";
  return launch;
}
PrincipalLaunch identity(int32_t user, uint32_t uid, uint32_t gid) {
  auto launch = typical();
  launch.epoch.user = launch.profile.binding.user = user;
  launch.profile.binding.uid = uid;
  launch.profile.binding.gid = gid;
  return launch;
}
size_t open_descriptors() {
  DIR* directory = opendir("/proc/self/fd");
  assert(directory);
  size_t count = 0;
  while (auto* entry = readdir(directory))
    if (entry->d_name[0] != '.') ++count;
  closedir(directory);
  return count;
}
void put(Bytes& out, uint64_t value, size_t size) {
  for (size_t n = 0; n < size; ++n)
    out.push_back(static_cast<uint8_t>(value >> (8 * n)));
}
void patch(Bytes& bytes, size_t at, uint64_t value, size_t size) {
  for (size_t n = 0; n < size; ++n)
    bytes.at(at + n) = static_cast<uint8_t>(value >> (8 * n));
}
void put(Bytes& out, const std::string& text) {
  put(out, text.size(), 4);
  out.insert(out.end(), text.begin(), text.end());
}
// An independent statement of the documented version 1 layout. It also
// encodes invalid values, so decoding is tested on exactly one changed field.
Bytes reference(const PrincipalLaunch& launch) {
  const auto& binding = launch.profile.binding;
  Bytes out;
  put(out, 0x4158504c, 4);
  put(out, 1, 4);
  put(out, 0, 4);
  put(out, 0, 4);
  put(out, launch.work.manager, 8);
  put(out, launch.work.serial, 8);
  put(out, launch.epoch.platform, 8);
  put(out, launch.epoch.generation, 8);
  put(out, static_cast<uint32_t>(launch.epoch.user), 4);
  put(out, binding.instance, 8);
  put(out, binding.generation, 8);
  put(out, static_cast<uint32_t>(binding.user), 4);
  put(out, static_cast<uint64_t>(binding.user_serial), 8);
  put(out, binding.uid, 4);
  put(out, binding.gid, 4);
  put(out, binding.package_name);
  put(out, launch.profile.supplementary_groups.size(), 4);
  for (uint32_t group : launch.profile.supplementary_groups) put(out, group, 4);
  put(out, launch.profile.selinux_context);
  patch(out, 8, out.size(), 4);
  return out;
}
// A memfd holding bytes and the given seals. O_RDWR returns the creating
// descriptor. Other flags reopen it through /proc and close the original.
int object(const Bytes& bytes, int seals, int flags = O_RDONLY) {
  const int fd =
      static_cast<int>(syscall(SYS_memfd_create, "principal-test", 3U));
  assert(fd >= 0);
  assert(pwrite(fd, bytes.data(), bytes.size(), 0) ==
         static_cast<ssize_t>(bytes.size()));
  assert(!seals || !fcntl(fd, F_ADD_SEALS, seals));
  if (flags == O_RDWR) return fd;
  const int reopened = open(("/proc/self/fd/" + std::to_string(fd)).c_str(),
                            flags | O_CLOEXEC);
  assert(reopened >= 0 && !close(fd));
  return reopened;
}
bool mapped(const std::string& name) {
  const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  std::string maps;
  char buffer[4096];
  ssize_t count = 0;
  while ((count = read(fd, buffer, sizeof(buffer))) > 0)
    maps.append(buffer, static_cast<size_t>(count));
  assert(count == 0 && !close(fd));
  return maps.find(name) != std::string::npos;
}
// Every accepting path agrees, and each replaces its whole output.
void accepted(const PrincipalLaunch& launch) {
  assert(ValidPrincipalProfile(launch.profile));
  const size_t baseline = open_descriptors();
  Bytes bytes{9, 9, 9};
  int error = -1;
  assert(EncodePrincipalLaunch(launch, bytes, error) && error == 0);
  assert(bytes == reference(launch));
  assert(bytes.size() <= kPrincipalLaunchMaximumBytes);
  auto decoded = sentinel();
  error = -1;
  assert(DecodePrincipalLaunch(bytes, decoded, error) && error == 0 &&
         decoded == launch);
  error = -1;
  const int fd = SealPrincipalLaunch(launch, error);
  assert(fd >= 0 && error == 0);
  auto profile = sentinel().profile;
  error = -1;
  assert(ReadPrincipalLaunch(fd, launch.work, launch.epoch, profile, error) &&
         error == 0 && profile == launch.profile);
  assert(!close(fd) && open_descriptors() == baseline);
}
// Encoding refuses the value, and decoding its exact layout refuses it too.
void refused(const PrincipalLaunch& launch) {
  const size_t baseline = open_descriptors();
  Bytes untouched{1, 2, 3};
  int error = 0;
  assert(!EncodePrincipalLaunch(launch, untouched, error) && error == EINVAL &&
         untouched == Bytes({1, 2, 3}));
  auto decoded = sentinel();
  error = 0;
  assert(!DecodePrincipalLaunch(reference(launch), decoded, error) &&
         error == EPROTO && decoded == sentinel());
  error = 0;
  assert(SealPrincipalLaunch(launch, error) == -1 && error == EINVAL);
  assert(open_descriptors() == baseline);
}
void profile_refused(const PrincipalLaunch& launch) {
  assert(!ValidPrincipalProfile(launch.profile));
  refused(launch);
}
void decode_refused(const Bytes& bytes, int expected) {
  auto decoded = sentinel();
  int error = 0;
  assert(!DecodePrincipalLaunch(bytes, decoded, error) && error == expected &&
         decoded == sentinel());
}
// Refusal leaves the output unchanged and a borrowed descriptor open.
void read_refused(int fd, int expected, WorkIdentity work = typical().work,
                  AuthorityEpoch epoch = typical().epoch) {
  const size_t baseline = open_descriptors();
  const bool open_before = fcntl(fd, F_GETFD) >= 0;
  auto result = sentinel().profile;
  int error = 0;
  assert(!ReadPrincipalLaunch(fd, work, epoch, result, error) &&
         error == expected && result == sentinel().profile);
  assert((fcntl(fd, F_GETFD) >= 0) == open_before);
  assert(open_descriptors() == baseline);
}

void round_trips() {
  const auto launch = typical();
  accepted(launch);
  Bytes bytes;
  int error = 0;
  assert(EncodePrincipalLaunch(launch, bytes, error));
  // Fixed fields, then the package, groups and context with their lengths.
  assert(bytes.size() == 100 + 18 + 2 * 4 + 40);
  assert(bytes[kPackageLength] == 18 && bytes[kGroupCount] == 2 &&
         bytes[kContextLength] == 40);
  // An explicit empty group list stays empty. No group is implied.
  auto none = launch;
  none.profile.supplementary_groups.clear();
  accepted(none);
  assert(EncodePrincipalLaunch(none, bytes, error) &&
         bytes.size() == 100 + 18 + 40);
  for (size_t n = 0; n < 4; ++n) assert(bytes[kGroupCount + n] == 0);
  auto decoded = sentinel();
  assert(DecodePrincipalLaunch(bytes, decoded, error) && decoded == none &&
         decoded.profile.supplementary_groups.empty());
  // Defaults are not a launch.
  assert(!ValidPrincipalProfile(PrincipalProfile{}));
  refused(PrincipalLaunch{});
  // Smallest and largest accepted values of every field.
  PrincipalLaunch smallest;
  smallest.work = {1, 1};
  smallest.epoch = {1, 1, 0};
  smallest.profile.binding = {1, 1, 0, 0, 10000, 10000, "a.b"};
  smallest.profile.selinux_context = "u:r:t:s0";
  accepted(smallest);
  PrincipalLaunch largest;
  largest.work = {UINT64_MAX, UINT64_MAX};
  largest.epoch = {kLargest, kLargest, 42949};
  largest.profile.binding = {kLargest,
                             kLargest,
                             42949,
                             std::numeric_limits<int64_t>::max(),
                             4294919999U,
                             4294919999U,
                             "a." + std::string(253, 'b')};
  for (uint32_t n = 0; n < kPrincipalMaximumGroups; ++n)
    largest.profile.supplementary_groups.push_back(0xfffffffeU - 63 + n);
  largest.profile.selinux_context = "u:r:" + std::string(248, 't') + ":s0";
  assert(largest.profile.binding.package_name.size() ==
             kPrincipalMaximumPackageName &&
         largest.profile.selinux_context.size() == kPrincipalMaximumContext);
  accepted(largest);
  assert(EncodePrincipalLaunch(largest, bytes, error) &&
         bytes.size() == 100 + 255 + 64 * 4 + 255);
}
uint64_t& identifier(PrincipalLaunch& launch, int field) {
  switch (field) {
    case 0:
      return launch.work.manager;
    case 1:
      return launch.work.serial;
    case 2:
      return launch.epoch.platform;
    case 3:
      return launch.epoch.generation;
    case 4:
      return launch.profile.binding.instance;
    default:
      return launch.profile.binding.generation;
  }
}
void identifiers() {
  for (int field = 0; field < 6; ++field) {
    for (uint64_t value : {uint64_t(1), kLargest}) {
      auto launch = typical();
      identifier(launch, field) = value;
      accepted(launch);
    }
    for (uint64_t value : {uint64_t(0), kLargest + 1, UINT64_MAX}) {
      auto launch = typical();
      identifier(launch, field) = value;
      if (field < 2 && value != 0) {
        accepted(launch);  // Work IDs retain their existing full uint64_t range.
      } else {
        // Work and epoch identifiers belong to the launch, not the profile.
        assert(ValidPrincipalProfile(launch.profile) == (field < 4));
        refused(launch);
      }
    }
  }
  // The epoch's user must be the principal's user.
  for (int32_t user : {-1, 10, INT32_MAX}) {
    auto launch = typical();
    launch.epoch.user = user;
    assert(ValidPrincipalProfile(launch.profile));
    refused(launch);
  }
  for (int64_t serial : {int64_t(0), std::numeric_limits<int64_t>::max()}) {
    auto launch = typical();
    launch.profile.binding.user_serial = serial;
    accepted(launch);
  }
  for (int64_t serial : {int64_t(-1), std::numeric_limits<int64_t>::min()}) {
    auto launch = typical();
    launch.profile.binding.user_serial = serial;
    profile_refused(launch);
  }
}
void identities() {
  using UserValue = std::pair<int32_t, uint32_t>;
  // Ordinary application UIDs, up to the last user whose UIDs fit 32 bits.
  const UserValue ordinary[] = {{0, 10000},           {0, 19999},
                                {10, 1010000},        {10, 1019999},
                                {42949, 4294910000U}, {42949, 4294919999U}};
  for (auto [user, uid] : ordinary) accepted(identity(user, uid, uid));
  // Root, system, shell, the static owner, below the application range, SDK
  // sandbox, cache and external GIDs, shared GIDs, overflow, app zygote and
  // isolated IDs, in the primary and a secondary user.
  for (uint32_t app : {0U, 1000U, 2000U, 7500U, 9999U, 20000U, 29999U, 30000U,
                       40000U, 50000U, 59999U, 65534U, 90000U, 98999U, 99000U,
                       99999U})
    for (int32_t user : {0, 10}) {
      const uint32_t uid = static_cast<uint32_t>(user) * 100000 + app;
      profile_refused(identity(user, uid, uid));
    }
  // Another user's ordinary UID.
  profile_refused(identity(0, 1010123, 1010123));
  profile_refused(identity(10, 10123, 10123));
  profile_refused(identity(11, 1010123, 1010123));
  // Users past 42949 wrap in 32 bits. User 128849 with app ID 19999 wraps to
  // user 0's application UID 18111. User 2^27 times 100000 wraps to zero, so
  // its app ID 10123 is user 0's UID 10123.
  const auto wrapped = [](int32_t user, uint32_t app) {
    return static_cast<uint32_t>(uint64_t(user) * 100000 + app);
  };
  assert(wrapped(128849, 19999) == 18111 && wrapped(1 << 27, 10123) == 10123);
  accepted(identity(0, 18111, 18111));
  const UserValue wrapping[] = {
      {42950, 10123}, {128849, 19999}, {1 << 27, 10123}, {INT32_MAX, 10123}};
  for (auto [user, app] : wrapping)
    profile_refused(identity(user, wrapped(user, app), wrapped(user, app)));
  profile_refused(identity(-1, 10123, 10123));
  profile_refused(identity(INT32_MIN, 10123, 10123));
  // The group is the UID. Nothing else is substituted.
  for (uint32_t gid : {0U, 3003U, 10122U, 10124U, 50123U, 1010123U})
    profile_refused(identity(0, 10123, gid));
}
void packages() {
  auto with = [](const std::string& package) {
    auto launch = typical();
    launch.profile.binding.package_name = package;
    return launch;
  };
  const std::string longest = "com." + std::string(251, 'x');
  assert(longest.size() == kPrincipalMaximumPackageName);
  const std::string valid[] = {"a.b",         "A.B",   "com.example.native",
                               "a.b.c.d.e.f", "a_.b_", "com.Example_1.App2",
                               longest};
  for (const auto& package : valid) accepted(with(package));
  const std::string invalid[] = {"",
                                 "android",
                                 "com",
                                 ".com.x",
                                 "com.x.",
                                 "com..x",
                                 "com.1x",
                                 "com._x",
                                 "1com.x",
                                 "_com.x",
                                 "com.x-y",
                                 "com.x y",
                                 "com.x\ty",
                                 "com.x\n",
                                 std::string("com.x\0y", 7),
                                 "com.x/y",
                                 "com.x:y",
                                 "com.\xc3\xa9t",
                                 longest + "x"};
  for (const auto& package : invalid) profile_refused(with(package));
}
void groups() {
  auto with = [](const std::vector<uint32_t>& groups) {
    auto launch = typical();
    launch.profile.supplementary_groups = groups;
    return launch;
  };
  std::vector<uint32_t> most;
  for (uint32_t group = 1; group <= kPrincipalMaximumGroups; ++group)
    most.push_back(group);
  // Complete and explicit. No list decides which groups are acceptable.
  const std::vector<uint32_t> valid[] = {
      {}, {1}, {1, 2}, {3003, 9997}, {1, 0xfffffffeU}, most};
  for (const auto& groups : valid) accepted(with(groups));
  auto too_many = most;
  too_many.push_back(kPrincipalMaximumGroups + 1);
  // Duplicated, unordered, zero and Linux's invalid ID are refused, never
  // repaired by sorting or removal.
  const std::vector<uint32_t> invalid[] = {
      too_many,     {0},         {0, 3003},     {3003, 3003},
      {9997, 3003}, {1, 3, 2},   {0xffffffffU}, {1, 0xffffffffU},
      {3003, 9997, 3003, 9997}};
  for (const auto& groups : invalid) profile_refused(with(groups));
}
void contexts() {
  auto with = [](const std::string& context) {
    auto launch = typical();
    launch.profile.selinux_context = context;
    return launch;
  };
  const std::string longest = "u:r:" + std::string(248, 't') + ":s0";
  assert(longest.size() == kPrincipalMaximumContext);
  const std::string valid[] = {
      "u:r:t:s0",
      "u:r:untrusted_app_32:s0:c512,c768",
      "u:r:t:s0:c0",
      "u:r:t:s0:c0,c1",  // A run of two.
      "u:r:t:s0:c0.c2",  // A longer run.
      "u:r:t:s0:c0.c1023",
      "u:r:t:s0:c3,c4,c6",
      "u:r:t:s0:c255,c256,c512,c768",
      "u:r:t:s0-s1:c0.c1023",  // Two different levels.
      "u:r:t:s0-s0:c1",
      // Syntax only: the trusted factory owns the exact role and type.
      "u:object_r:t:s0",
      "U:R:T:s0",
      longest};
  for (const auto& context : valid) accepted(with(context));
  const std::string invalid[] = {
      // Fields.
      "", "u:r:t", "u:r:t:", ":r:t:s0", "u::t:s0", "u:r::s0", "u:r:t-x:s0",
      "u:r:t.x:s0", "u:r:1t:s0", "u:r:_t:s0",
      // Whitespace, control, NUL and non-ASCII bytes.
      "u:r:t:s0 ", " u:r:t:s0", "u :r:t:s0", "u:r:t:s0\n", "u:r:t:s0\t",
      "u:r:t:s0\r", std::string("u:r:t:s0\0", 9), std::string("u:r:t\0:s0", 9),
      "u:r:t:s0\x7f", "u:r:t:s0\x01", "u:r:t\x1b:s0", "u:r:t\xc3\xa9:s0",
      // Levels and numbers.
      "u:r:t:x0", "u:r:t:S0", "u:r:t:s", "u:r:t:s00", "u:r:t:s01",
      "u:r:t:s-1", "u:r:t:s+1", "u:r:t:s1234567890", "u:r:t:s0:c1234567890",
      // Category syntax.
      "u:r:t:s0:", "u:r:t:s0:c", "u:r:t:s0:C1", "u:r:t:s0:c1,", "u:r:t:s0:,c1",
      "u:r:t:s0:c01", "u:r:t:s0:c1:c2", "u:r:t:s0:c1.", "u:r:t:s0:c1.c",
      "u:r:t:s0:c1..c3",
      // Order, repetition and spellings the kernel does not print.
      "u:r:t:s0:c2,c1", "u:r:t:s0:c1,c1", "u:r:t:s0:c1.c3,c2",
      "u:r:t:s0:c3.c1", "u:r:t:s0:c1.c1", "u:r:t:s0:c1.c2",
      "u:r:t:s0:c1,c2,c3", "u:r:t:s0:c1.c3,c4", "u:r:t:s0:c1,c2.c4",
      "u:r:t:s0:c1.c3,c4.c6",
      // Ranges.
      "u:r:t:s0-s0", "u:r:t:s0:c1-s0:c1", "u:r:t:s0-", "u:r:t:-s0",
      "u:r:t:s0-s1-s2", "u:r:t:s0:c1-",
      // Well formed, but one byte over the bound.
      "u:r:" + std::string(249, 't') + ":s0"};
  for (const auto& context : invalid) profile_refused(with(context));
}
void framing() {
  const auto launch = typical();
  Bytes bytes;
  int error = 0;
  assert(EncodePrincipalLaunch(launch, bytes, error));
  // Every truncation, with the size field left alone or made to match.
  for (size_t size = 0; size < bytes.size(); ++size) {
    Bytes prefix(bytes.begin(), bytes.begin() + size);
    decode_refused(prefix, EPROTO);
    if (size < 12) continue;
    patch(prefix, 8, size, 4);
    decode_refused(prefix, EPROTO);
  }
  // Trailing bytes, with the size field left alone or made to match.
  for (uint8_t extra : {0x00, 0x01, 0xff}) {
    auto trailing = bytes;
    trailing.push_back(extra);
    decode_refused(trailing, EPROTO);
    patch(trailing, 8, trailing.size(), 4);
    decode_refused(trailing, EPROTO);
  }
  // Magic, including a launch description's, version, size and reserved.
  struct Field {
    size_t at;
    uint32_t value;
  };
  const auto size = static_cast<uint32_t>(bytes.size());
  const Field header[] = {{0, 0},        {0, 0x41584c44}, {4, 0},
                          {4, 2},        {4, UINT32_MAX}, {8, 0},
                          {8, size - 1}, {8, size + 1},   {8, UINT32_MAX},
                          {12, 1},       {12, 0x80000000}};
  for (auto [at, value] : header) {
    auto changed = bytes;
    patch(changed, at, value, 4);
    decode_refused(changed, EPROTO);
  }
  // The transport bound applies before parsing.
  auto oversized = bytes;
  oversized.resize(kPrincipalLaunchMaximumBytes + 1);
  decode_refused(oversized, EMSGSIZE);
  auto padded = bytes;
  padded.resize(kPrincipalLaunchMaximumBytes);
  patch(padded, 8, padded.size(), 4);
  decode_refused(padded, EPROTO);
  // The fixed order leaves nothing to duplicate or reorder. A repeated
  // context is trailing data, a repeated group list is not ascending and
  // swapped strings fail their own syntax.
  auto repeated = bytes;
  put(repeated, launch.profile.selinux_context);
  patch(repeated, 8, repeated.size(), 4);
  decode_refused(repeated, EPROTO);
  auto doubled = launch;
  doubled.profile.supplementary_groups = {3003, 9997, 3003, 9997};
  decode_refused(reference(doubled), EPROTO);
  auto swapped = launch;
  std::swap(swapped.profile.binding.package_name,
            swapped.profile.selinux_context);
  decode_refused(reference(swapped), EPROTO);
  // A length or count cannot borrow bytes from a neighbouring field.
  for (auto [at, value] : {Field{kPackageLength, 17}, Field{kPackageLength, 19},
                           Field{kGroupCount, 1}, Field{kGroupCount, 3},
                           Field{kGroupCount, UINT32_MAX},
                           Field{kContextLength, 39}, Field{kContextLength, 41},
                           Field{kContextLength, UINT32_MAX}}) {
    auto changed = bytes;
    patch(changed, at, value, 4);
    decode_refused(changed, EPROTO);
  }
  // One encoding per value: any single bit change that still decodes is a
  // different launch that encodes back to exactly the changed bytes.
  size_t different = 0;
  for (size_t at = 0; at < bytes.size(); ++at)
    for (unsigned bit = 0; bit < 8; ++bit) {
      auto changed = bytes;
      changed[at] ^= static_cast<uint8_t>(1U << bit);
      PrincipalLaunch decoded;
      if (!DecodePrincipalLaunch(changed, decoded, error)) {
        assert(error == EPROTO);
        continue;
      }
      Bytes again;
      assert(!(decoded == launch));
      assert(EncodePrincipalLaunch(decoded, again, error) && again == changed);
      ++different;
    }
  assert(different > 0);
}
void sealed() {
  const auto launch = typical();
  Bytes bytes;
  int error = 0;
  assert(EncodePrincipalLaunch(launch, bytes, error));
  const size_t baseline = open_descriptors();
  const int fd = SealPrincipalLaunch(launch, error);
  assert(fd >= 0 && !error && open_descriptors() == baseline + 1);
  const int mode = fcntl(fd, F_GETFL);
  assert(mode >= 0 && (mode & O_ACCMODE) == O_RDONLY && !(mode & O_PATH));
  assert(fcntl(fd, F_GETFD) & FD_CLOEXEC);
  assert((fcntl(fd, F_GET_SEALS) & kSeals) == kSeals);
  struct stat info{};
  assert(!fstat(fd, &info) && S_ISREG(info.st_mode) &&
         info.st_size == static_cast<off_t>(bytes.size()));
  const off_t size = info.st_size;
  Bytes stored(bytes.size() + 1);
  assert(pread(fd, stored.data(), stored.size(), 0) == size);
  stored.pop_back();
  assert(stored == bytes);
  // Nothing stays mapped. The control shows that a mapped memfd is visible.
  assert(!mapped("andrix-principal-launch"));
  const int control = object(bytes, 0, O_RDWR);
  void* mapping =
      mmap(nullptr, bytes.size(), PROT_READ, MAP_SHARED, control, 0);
  assert(mapping != MAP_FAILED && mapped("principal-test"));
  assert(!munmap(mapping, bytes.size()) && !close(control));
  assert(!mapped("principal-test"));
  // Reading borrows: it repeats, keeps the offset and leaves the fd open.
  assert(lseek(fd, 17, SEEK_SET) == 17);
  for (int round = 0; round < 2; ++round) {
    auto profile = sentinel().profile;
    assert(ReadPrincipalLaunch(fd, launch.work, launch.epoch, profile, error) &&
           !error && profile == launch.profile);
  }
  assert(lseek(fd, 0, SEEK_CUR) == 17 && fcntl(fd, F_GETFD) >= 0);
  // No write, growth, shrinkage or seal change, through this descriptor or a
  // writable reopening of the same object.
  assert(pwrite(fd, "x", 1, 0) == -1 && errno == EBADF);
  assert(ftruncate(fd, 0) == -1);
  const int writable = open(("/proc/self/fd/" + std::to_string(fd)).c_str(),
                            O_RDWR | O_CLOEXEC);
  assert(writable >= 0);
  assert(pwrite(writable, "x", 1, 0) == -1 && errno == EPERM);
  assert(pwrite(writable, "x", 1, size) == -1 && errno == EPERM);
  assert(ftruncate(writable, size + 1) == -1 && errno == EPERM);
  assert(ftruncate(writable, size - 1) == -1 && errno == EPERM);
  assert(ftruncate(writable, 0) == -1 && errno == EPERM);
  assert(fallocate(writable, 0, 0, size + 4096) == -1 && errno == EPERM);
  assert(fallocate(writable, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
                   1) == -1 &&
         errno == EPERM);
  assert(mmap(nullptr, static_cast<size_t>(size), PROT_READ | PROT_WRITE,
              MAP_SHARED, writable, 0) == MAP_FAILED &&
         errno == EPERM);
  assert(fcntl(writable, F_ADD_SEALS, F_SEAL_WRITE) == -1 && errno == EPERM);
  assert(!close(writable));
  auto profile = sentinel().profile;
  assert(ReadPrincipalLaunch(fd, launch.work, launch.epoch, profile, error) &&
         profile == launch.profile);
  assert(!fstat(fd, &info) && info.st_size == size);
  assert(!close(fd) && open_descriptors() == baseline);
}
void bindings() {
  const auto launch = typical();
  int error = 0;
  const int fd = SealPrincipalLaunch(launch, error);
  assert(fd >= 0);
  // Another work, platform incarnation, generation or user.
  for (WorkIdentity work : {WorkIdentity{11, 2}, WorkIdentity{12, 1},
                            WorkIdentity{kLargest + 1, 1}})
    read_refused(fd, ESTALE, work, launch.epoch);
  for (AuthorityEpoch epoch : {AuthorityEpoch{92, 8, 0},
                               AuthorityEpoch{91, 9, 0},
                               AuthorityEpoch{91, 8, 10}})
    read_refused(fd, ESTALE, launch.work, epoch);
  // Invalid expectations.
  for (WorkIdentity work : {WorkIdentity{0, 1}, WorkIdentity{11, 0}})
    read_refused(fd, EINVAL, work, launch.epoch);
  for (AuthorityEpoch epoch :
       {AuthorityEpoch{0, 8, 0}, AuthorityEpoch{91, 0, 0},
        AuthorityEpoch{91, kLargest + 1, 0}, AuthorityEpoch{91, 8, -1}})
    read_refused(fd, EINVAL, launch.work, epoch);
  assert(!close(fd));
  // A secondary user's record for the same work is foreign to the primary
  // user's epoch.
  auto secondary = identity(10, 1010123, 1010123);
  secondary.profile.binding.user_serial = 14;
  const int other = SealPrincipalLaunch(secondary, error);
  assert(other >= 0);
  read_refused(other, ESTALE, secondary.work, launch.epoch);
  auto profile = sentinel().profile;
  assert(ReadPrincipalLaunch(other, secondary.work, secondary.epoch, profile,
                             error) &&
         profile == secondary.profile);
  assert(!close(other));
}
void objects() {
  const auto launch = typical();
  Bytes bytes;
  int error = 0;
  assert(EncodePrincipalLaunch(launch, bytes, error));
  // Control: the helper's completely sealed read-only object is accepted.
  int fd = object(bytes, kSeals);
  auto profile = sentinel().profile;
  assert(ReadPrincipalLaunch(fd, launch.work, launch.epoch, profile, error) &&
         profile == launch.profile);
  assert(!close(fd));
  // Each required seal.
  for (int missing :
       {F_SEAL_WRITE, F_SEAL_GROW, F_SEAL_SHRINK, F_SEAL_SEAL, kSeals}) {
    fd = object(bytes, kSeals & ~missing);
    read_refused(fd, EINVAL);
    assert(!close(fd));
  }
  // Write access, or no read access, even when completely sealed.
  for (int flags : {O_RDWR, O_WRONLY}) {
    fd = object(bytes, kSeals, flags);
    read_refused(fd, EACCES);
    assert(!close(fd));
  }
  fd = object(bytes, kSeals, O_PATH);
  read_refused(fd, EBADF);
  assert(!close(fd));
  // Not descriptors.
  const int closed = object(bytes, kSeals);
  assert(!close(closed));
  for (int invalid : {-1, INT_MIN, closed, 1 << 20})
    read_refused(invalid, EBADF);
  // The valid record in other objects. Refusal consumes nothing from a pipe.
  int channel[2];
  assert(!pipe2(channel, O_CLOEXEC));
  assert(write(channel[1], bytes.data(), bytes.size()) ==
         static_cast<ssize_t>(bytes.size()));
  read_refused(channel[0], EINVAL);
  Bytes queued(bytes.size());
  assert(read(channel[0], queued.data(), queued.size()) ==
             static_cast<ssize_t>(queued.size()) &&
         queued == bytes);
  assert(!close(channel[0]) && !close(channel[1]));
  char path[] = "/tmp/andrix-principal-XXXXXX";
  const int file = mkostemp(path, O_CLOEXEC);
  assert(file >= 0 && !unlink(path));
  assert(pwrite(file, bytes.data(), bytes.size(), 0) ==
         static_cast<ssize_t>(bytes.size()));
  fd = open(("/proc/self/fd/" + std::to_string(file)).c_str(),
            O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  read_refused(fd, EINVAL);
  assert(!close(fd) && !close(file));
  for (const char* other : {"/", "/dev/null"}) {
    fd = open(other, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    read_refused(fd, EINVAL);
    assert(!close(fd));
  }
  int sockets[2];
  assert(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets));
  read_refused(sockets[0], EACCES);
  assert(!close(sockets[0]) && !close(sockets[1]));
  // Completely sealed objects whose bytes are not exactly one valid record.
  auto truncated = bytes;
  truncated.pop_back();
  auto trailing = bytes;
  trailing.push_back(0);
  patch(trailing, 8, trailing.size(), 4);
  auto reserved = bytes;
  patch(reserved, 12, 1, 4);
  auto version = bytes;
  patch(version, 4, 2, 4);
  auto foreign = bytes;
  patch(foreign, 0, 0x41584c44, 4);  // A launch description's magic.
  const Bytes malformed[] = {{},       truncated, trailing, reserved,
                             version,  foreign,   reference(identity(0, 0, 0))};
  for (const auto& content : malformed) {
    fd = object(content, kSeals);
    read_refused(fd, EPROTO);
    assert(!close(fd));
  }
  auto oversized = bytes;
  oversized.resize(kPrincipalLaunchMaximumBytes + 1);
  fd = object(oversized, kSeals);
  read_refused(fd, EMSGSIZE);
  assert(!close(fd));
  // The size is refused before anything is allocated or read: this sparse
  // object is far larger than memory.
  fd = object(bytes, 0, O_RDWR);
  assert(!ftruncate(fd, off_t(1) << 40) && !fcntl(fd, F_ADD_SEALS, kSeals));
  const int huge = open(("/proc/self/fd/" + std::to_string(fd)).c_str(),
                        O_RDONLY | O_CLOEXEC);
  assert(huge >= 0 && !close(fd));
  read_refused(huge, EMSGSIZE);
  assert(!close(huge));
}
}  // namespace
int main() {
  const size_t baseline = open_descriptors();
  round_trips();
  identifiers();
  identities();
  packages();
  groups();
  contexts();
  framing();
  sealed();
  bindings();
  objects();
  assert(open_descriptors() == baseline);
}
