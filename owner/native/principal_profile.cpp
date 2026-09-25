// SPDX-License-Identifier: Apache-2.0
#include "principal_profile.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <limits>
#include <string_view>
#include <utility>

namespace andrix {
namespace {
// Local versioned record, not a public API. Version 1 is little endian, with
// these fields in this order and no padding:
//   header   u32 magic, u32 version, u32 total size, u32 reserved (zero)
//   launch   u64 work manager, u64 work serial, u64 epoch platform,
//            u64 epoch generation, u32 epoch user
//   binding  u64 instance, u64 generation, u32 user, u64 user serial,
//            u32 uid, u32 gid, u32 package length, package bytes
//   profile  u32 group count, that many u32 groups, u32 context length,
//            context bytes
constexpr uint32_t kMagic = 0x4158504c;  // "AXPL"
constexpr uint32_t kVersion = 1;
constexpr size_t kSizeOffset = 8;
// Header, launch and fixed binding fields, and the three length words.
constexpr size_t kMinimumBytes = 16 + 36 + 36 + 3 * 4;
static_assert(kMinimumBytes + kPrincipalMaximumPackageName +
                  4 * kPrincipalMaximumGroups + kPrincipalMaximumContext <=
              kPrincipalLaunchMaximumBytes);
constexpr int kSeals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
constexpr unsigned kMemfdOptions =
    0x0001U | 0x0002U;  // CLOEXEC | ALLOW_SEALING.
// Android's multiuser UID layout and ordinary application ID range.
constexpr uint32_t kUserOffset = 100000;
constexpr uint32_t kFirstApplication = 10000, kLastApplication = 19999;
constexpr uint32_t kInvalidId = 0xffffffffU;  // (gid_t)-1 names no group.

bool fail(int& error, int code) {
  error = code;
  return false;
}
bool positive(uint64_t value) {
  return value &&
         value <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
}
bool valid(WorkIdentity work) {
  // Existing WorkRegistry identities use the full uint64_t range, including
  // random manager incarnations with the high bit set. They are not Java IDs.
  return work.manager != 0 && work.serial != 0;
}
bool valid(AuthorityEpoch epoch) {
  return positive(epoch.platform) && positive(epoch.generation) &&
         epoch.user >= 0;
}
bool valid(const PrincipalLaunch& launch) {
  return valid(launch.work) && valid(launch.epoch) &&
         launch.epoch.user == launch.profile.binding.user &&
         ValidPrincipalProfile(launch.profile);
}
// Dividing, as Android's multiuser_get_user_id does, means no user number can
// wrap into another user's UIDs.
bool application(int32_t user, uint32_t uid) {
  const uint32_t app = uid % kUserOffset;
  return user >= 0 && uid / kUserOffset == static_cast<uint32_t>(user) &&
         app >= kFirstApplication && app <= kLastApplication;
}
bool letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool digit(char c) { return c >= '0' && c <= '9'; }
// An ASCII letter, then ASCII letters, digits or underscores.
bool name(std::string_view text) {
  if (text.empty() || !letter(text.front())) return false;
  for (char c : text.substr(1))
    if (!letter(c) && !digit(c) && c != '_') return false;
  return true;
}
bool valid_package(std::string_view text) {
  if (text.size() > kPrincipalMaximumPackageName) return false;
  for (size_t begin = 0, segments = 1;; ++segments) {
    const size_t end = text.find('.', begin);
    if (!name(text.substr(begin, end - begin))) return false;
    if (end == std::string_view::npos) return segments >= 2;
    begin = end + 1;
  }
}
bool valid_groups(const std::vector<uint32_t>& groups) {
  if (groups.size() > kPrincipalMaximumGroups) return false;
  uint32_t previous = 0;  // Zero is never valid, so it orders the first.
  for (uint32_t group : groups) {
    if (group <= previous || group == kInvalidId) return false;
    previous = group;
  }
  return true;
}
// The MLS range as the kernel prints it with Android's level names: one level,
// or two different levels joined by '-'. A level is sN, optionally followed by
// ':' and ascending categories. The kernel spells a run of two adjacent
// categories cA,cB and a longer run cA.cB, so each set has one spelling.
class Range {
 public:
  explicit Range(std::string_view text) : text_(text) {}
  bool valid() {
    const std::string_view low = level();
    if (low.empty()) return false;
    if (take('-')) {
      const std::string_view high = level();
      if (high.empty() || high == low) return false;
    }
    return at_ == text_.size();
  }

 private:
  bool take(char c) {
    if (at_ == text_.size() || text_[at_] != c) return false;
    ++at_;
    return true;
  }
  // Decimal without sign or redundant leading zero, at most nine digits.
  bool number(uint32_t& value) {
    const size_t begin = at_;
    value = 0;
    while (at_ < text_.size() && at_ - begin < 9 && digit(text_[at_]))
      value = value * 10 + static_cast<uint32_t>(text_[at_++] - '0');
    const size_t digits = at_ - begin;
    return digits && (digits == 1 || text_[begin] != '0') &&
           (at_ == text_.size() || !digit(text_[at_]));
  }
  // The level's text, or empty when it is malformed.
  std::string_view level() {
    const size_t begin = at_;
    uint32_t value = 0;
    if (!take('s') || !number(value)) return {};
    if (take(':')) {
      bool first = true, pairable = false;
      uint32_t end = 0;
      do {
        uint32_t low = 0, high = 0;
        if (!take('c') || !number(low)) return {};
        high = low;
        const bool run = take('.');
        if (run && (!take('c') || !number(high) || high < low + 2)) return {};
        const bool adjacent = !first && low == end + 1;
        if ((!first && low <= end) || (adjacent && (run || !pairable)))
          return {};
        pairable = !run && !adjacent;
        end = high;
        first = false;
      } while (take(','));
    }
    return text_.substr(begin, at_ - begin);
  }
  std::string_view text_;
  size_t at_ = 0;
};
bool valid_context(std::string_view text) {
  if (text.size() > kPrincipalMaximumContext) return false;
  size_t begin = 0;
  for (int field = 0; field < 3; ++field) {  // User, role and type.
    const size_t end = text.find(':', begin);
    if (end == std::string_view::npos || !name(text.substr(begin, end - begin)))
      return false;
    begin = end + 1;
  }
  return Range(text.substr(begin)).valid();
}
void u32(std::vector<uint8_t>& out, uint32_t value) {
  for (unsigned n = 0; n < 4; ++n)
    out.push_back(static_cast<uint8_t>(value >> (8 * n)));
}
void u64(std::vector<uint8_t>& out, uint64_t value) {
  for (unsigned n = 0; n < 8; ++n)
    out.push_back(static_cast<uint8_t>(value >> (8 * n)));
}
void text(std::vector<uint8_t>& out, const std::string& value) {
  u32(out, static_cast<uint32_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}
class Reader {
 public:
  explicit Reader(std::span<const uint8_t> bytes) : bytes_(bytes) {}
  uint32_t u32() { return static_cast<uint32_t>(number(4)); }
  uint64_t u64() { return number(8); }
  std::string text() {
    const uint32_t size = u32();
    if (size > bytes_.size()) good_ = false;
    if (!good_) return {};
    std::string value(bytes_.begin(), bytes_.begin() + size);
    bytes_ = bytes_.subspan(size);
    return value;
  }
  std::vector<uint32_t> groups() {
    const uint32_t count = u32();
    if (count > bytes_.size() / 4) good_ = false;
    std::vector<uint32_t> values;
    if (!good_) return values;
    values.reserve(count);
    for (uint32_t n = 0; n < count; ++n) values.push_back(u32());
    return values;
  }
  // Every read fitted and no byte remains.
  bool complete() const { return good_ && bytes_.empty(); }

 private:
  uint64_t number(size_t size) {
    if (bytes_.size() < size) good_ = false;
    if (!good_) return 0;
    uint64_t value = 0;
    for (size_t n = 0; n < size; ++n) value |= uint64_t(bytes_[n]) << (8 * n);
    bytes_ = bytes_.subspan(size);
    return value;
  }
  std::span<const uint8_t> bytes_;
  bool good_ = true;
};
class Descriptor {
 public:
  explicit Descriptor(int fd) : fd_(fd) {}
  ~Descriptor() {
    if (fd_ >= 0) close(fd_);
  }
  Descriptor(const Descriptor&) = delete;
  Descriptor& operator=(const Descriptor&) = delete;
  int get() const { return fd_; }
  int release() { return std::exchange(fd_, -1); }

 private:
  int fd_;
};
// Reads a borrowed descriptor's complete immutable bytes without moving its
// offset or consuming a stream.
bool read_sealed(int fd, std::vector<uint8_t>& result, int& error) {
  if (fd < 0) return fail(error, EBADF);
  const int mode = fcntl(fd, F_GETFL);
  if (mode < 0) return fail(error, errno);
  if (mode & O_PATH) return fail(error, EBADF);
  if ((mode & O_ACCMODE) != O_RDONLY) return fail(error, EACCES);
  // Seals first: once they are complete, the size and bytes below are final.
  const int seals = fcntl(fd, F_GET_SEALS);
  if (seals < 0) return fail(error, errno);
  if ((seals & kSeals) != kSeals) return fail(error, EINVAL);
  struct stat info{};
  if (fstat(fd, &info)) return fail(error, errno);
  if (!S_ISREG(info.st_mode)) return fail(error, EINVAL);
  if (static_cast<uint64_t>(info.st_size) > kPrincipalLaunchMaximumBytes)
    return fail(error, EMSGSIZE);
  std::vector<uint8_t> bytes(static_cast<size_t>(info.st_size));
  size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count =
        pread(fd, bytes.data() + offset, bytes.size() - offset,
              static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return fail(error, count < 0 ? errno : EIO);
    offset += static_cast<size_t>(count);
  }
  result = std::move(bytes);
  return true;
}
}  // namespace

bool ValidPrincipalProfile(const PrincipalProfile& profile) {
  const auto& binding = profile.binding;
  return positive(binding.instance) && positive(binding.generation) &&
         binding.user >= 0 && binding.user_serial >= 0 &&
         application(binding.user, binding.uid) && binding.gid == binding.uid &&
         valid_package(binding.package_name) &&
         valid_groups(profile.supplementary_groups) &&
         valid_context(profile.selinux_context);
}
bool EncodePrincipalLaunch(const PrincipalLaunch& launch,
                           std::vector<uint8_t>& result, int& error) {
  error = 0;
  if (!valid(launch)) return fail(error, EINVAL);
  const auto& profile = launch.profile;
  const auto& binding = profile.binding;
  std::vector<uint8_t> out;
  u32(out, kMagic);
  u32(out, kVersion);
  u32(out, 0);  // Total size, set below.
  u32(out, 0);  // Reserved.
  u64(out, launch.work.manager);
  u64(out, launch.work.serial);
  u64(out, launch.epoch.platform);
  u64(out, launch.epoch.generation);
  u32(out, static_cast<uint32_t>(launch.epoch.user));
  u64(out, binding.instance);
  u64(out, binding.generation);
  u32(out, static_cast<uint32_t>(binding.user));
  u64(out, static_cast<uint64_t>(binding.user_serial));
  u32(out, binding.uid);
  u32(out, binding.gid);
  text(out, binding.package_name);
  u32(out, static_cast<uint32_t>(profile.supplementary_groups.size()));
  for (uint32_t group : profile.supplementary_groups) u32(out, group);
  text(out, profile.selinux_context);
  const auto size = static_cast<uint32_t>(out.size());
  for (unsigned n = 0; n < 4; ++n)
    out[kSizeOffset + n] = static_cast<uint8_t>(size >> (8 * n));
  result = std::move(out);
  return true;
}
bool DecodePrincipalLaunch(std::span<const uint8_t> bytes,
                           PrincipalLaunch& result, int& error) {
  error = 0;
  if (bytes.size() > kPrincipalLaunchMaximumBytes)
    return fail(error, EMSGSIZE);
  Reader in(bytes);
  const uint32_t magic = in.u32(), version = in.u32(), size = in.u32(),
                 reserved = in.u32();
  if (magic != kMagic || version != kVersion || size != bytes.size() ||
      reserved)
    return fail(error, EPROTO);
  PrincipalLaunch launch;
  launch.work.manager = in.u64();
  launch.work.serial = in.u64();
  launch.epoch.platform = in.u64();
  launch.epoch.generation = in.u64();
  launch.epoch.user = static_cast<int32_t>(in.u32());
  auto& binding = launch.profile.binding;
  binding.instance = in.u64();
  binding.generation = in.u64();
  binding.user = static_cast<int32_t>(in.u32());
  binding.user_serial = static_cast<int64_t>(in.u64());
  binding.uid = in.u32();
  binding.gid = in.u32();
  binding.package_name = in.text();
  launch.profile.supplementary_groups = in.groups();
  launch.profile.selinux_context = in.text();
  if (!in.complete() || !valid(launch)) return fail(error, EPROTO);
  result = std::move(launch);
  return true;
}
int SealPrincipalLaunch(const PrincipalLaunch& launch, int& error) {
  std::vector<uint8_t> bytes;
  if (!EncodePrincipalLaunch(launch, bytes, error)) return -1;
  auto refuse = [&](int code) {
    error = code;
    return -1;
  };
  Descriptor memfd(static_cast<int>(
      syscall(SYS_memfd_create, "andrix-principal-launch", kMemfdOptions)));
  if (memfd.get() < 0) return refuse(errno);
  size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count =
        pwrite(memfd.get(), bytes.data() + offset, bytes.size() - offset,
               static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return refuse(count < 0 ? errno : EIO);
    offset += static_cast<size_t>(count);
  }
  if (fcntl(memfd.get(), F_ADD_SEALS, kSeals)) return refuse(errno);
  // SCM_RIGHTS and exec keep the open access mode. Reopen this still held
  // memfd read-only through our own descriptor number, never a caller path,
  // and check that the result is the same object.
  const std::string path = "/proc/self/fd/" + std::to_string(memfd.get());
  Descriptor readonly(open(path.c_str(), O_RDONLY | O_CLOEXEC));
  struct stat written{}, reopened{};
  if (readonly.get() < 0 || fstat(memfd.get(), &written) ||
      fstat(readonly.get(), &reopened))
    return refuse(errno);
  if (written.st_dev != reopened.st_dev || written.st_ino != reopened.st_ino)
    return refuse(ESTALE);
  // Hand out only what the reader accepts: mode, seals, size and exact bytes.
  std::vector<uint8_t> sealed;
  if (!read_sealed(readonly.get(), sealed, error)) return -1;
  if (sealed != bytes) return refuse(EIO);
  error = 0;
  return readonly.release();
}
bool ReadPrincipalLaunch(int borrowed_fd, WorkIdentity expected_work,
                         AuthorityEpoch expected_epoch,
                         PrincipalProfile& result, int& error) {
  error = 0;
  if (!valid(expected_work) || !valid(expected_epoch))
    return fail(error, EINVAL);
  std::vector<uint8_t> bytes;
  PrincipalLaunch launch;
  if (!read_sealed(borrowed_fd, bytes, error) ||
      !DecodePrincipalLaunch(bytes, launch, error))
    return false;
  if (launch.work != expected_work || launch.epoch != expected_epoch)
    return fail(error, ESTALE);
  result = std::move(launch.profile);
  return true;
}
}  // namespace andrix
