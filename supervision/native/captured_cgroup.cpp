// SPDX-License-Identifier: Apache-2.0
#include "captured_cgroup.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <utility>
#include <vector>

namespace andrix::supervision {
namespace {
class Fd {
 public:
  explicit Fd(int value = -1) : value_(value) {}
  ~Fd() {
    if (value_ >= 0) close(value_);
  }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept : value_(other.release()) {}
  Fd& operator=(Fd&& other) noexcept {
    if (this != &other) {
      if (value_ >= 0) close(value_);
      value_ = other.release();
    }
    return *this;
  }
  int get() const { return value_; }
  int release() {
    int result = value_;
    value_ = -1;
    return result;
  }

 private:
  int value_;
};

Failure fail(GroupError code, int error, const char* operation) {
  return {code, error, operation};
}
Fd duplicate(int fd) { return Fd(fcntl(fd, F_DUPFD_CLOEXEC, 0)); }
Fd beneath(int directory, const char* name, int flags) {
  open_how how{};
  how.flags = static_cast<uint64_t>(flags | O_CLOEXEC | O_NOFOLLOW);
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
                RESOLVE_NO_XDEV;
  return Fd(static_cast<int>(
      syscall(SYS_openat2, directory, name, &how, sizeof(how))));
}
bool directory_identity(int fd, GroupIdentity& identity, Failure& failure) {
  struct stat info{};
  struct statfs filesystem{};
  if (fd < 0 || fstat(fd, &info) || fstatfs(fd, &filesystem)) {
    failure = fail(GroupError::Io, fd < 0 ? EBADF : errno, "inspect directory");
    return false;
  }
  if (!S_ISDIR(info.st_mode) || filesystem.f_type != CGROUP2_SUPER_MAGIC) {
    failure =
        fail(GroupError::WrongFilesystem, ENODEV, "require cgroup2 directory");
    return false;
  }
  identity = {static_cast<uint64_t>(info.st_dev),
              static_cast<uint64_t>(info.st_ino)};
  return true;
}
bool transfer_identity(int fd, size_t index, GroupIdentity& identity,
                       Failure& failure) {
  struct stat info{};
  struct statfs filesystem{};
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fstat(fd, &info) || fstatfs(fd, &filesystem)) {
    failure = fail(GroupError::Io, errno, "inspect transferred descriptor");
    return false;
  }
  if (filesystem.f_type != CGROUP2_SUPER_MAGIC || (flags & O_PATH) ||
      (index < 2 ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode)) ||
      (flags & O_ACCMODE) != (index == 2 ? O_WRONLY : O_RDONLY)) {
    failure = fail(GroupError::WrongFilesystem, EINVAL,
                   "transferred descriptor type/mode");
    return false;
  }
  identity = {static_cast<uint64_t>(info.st_dev),
              static_cast<uint64_t>(info.st_ino)};
  return true;
}
bool named_identity(int parent, const std::string& name, GroupIdentity expected,
                    Failure& failure) {
  struct stat info{};
  if (fstatat(parent, name.c_str(), &info, AT_SYMLINK_NOFOLLOW)) {
    failure =
        fail(GroupError::IdentityChanged, errno, "captured entry missing");
    return false;
  }
  if (!S_ISDIR(info.st_mode) ||
      expected.device != static_cast<uint64_t>(info.st_dev) ||
      expected.inode != static_cast<uint64_t>(info.st_ino)) {
    failure =
        fail(GroupError::IdentityChanged, ESTALE, "captured entry replaced");
    return false;
  }
  return true;
}
bool valid_name(std::string_view name) {
  return !name.empty() && name.size() <= 255 && name != "." && name != ".." &&
         name.find('/') == std::string_view::npos &&
         name.find('\0') == std::string_view::npos;
}
bool valid_limits(const CleanupLimits& limits) {
  // Implementation bounds, not policy defaults or limits on owner filesystem
  // trees.
  return limits.max_depth <= 64 && limits.max_directory_visits > 0 &&
         limits.max_entry_visits > 0 && limits.max_total_steps > 0 &&
         limits.max_steps_per_call > 0 && limits.max_steps_per_call <= 1024;
}
PopulationResult parse_population(std::string_view text) {
  if (text.empty() || text.size() >= 4096)
    return {GroupPopulation::Unknown, EOVERFLOW};
  GroupPopulation result = GroupPopulation::Unknown;
  size_t start = 0;
  while (start < text.size()) {
    const auto end = text.find('\n', start);
    if (end == std::string_view::npos)
      return {GroupPopulation::Unknown, EPROTO};
    const auto line = text.substr(start, end - start);
    start = end + 1;
    const auto split = line.find(' ');
    if (split == 0 || split == std::string_view::npos ||
        split + 1 == line.size() || line.find('\0') != std::string_view::npos)
      return {GroupPopulation::Unknown, EPROTO};
    if (line.substr(0, split) != "populated") continue;
    if (result != GroupPopulation::Unknown)
      return {GroupPopulation::Unknown, EPROTO};
    if (line == "populated 0")
      result = GroupPopulation::Empty;
    else if (line == "populated 1")
      result = GroupPopulation::Populated;
    else
      return {GroupPopulation::Unknown, EPROTO};
  }
  return {result, result == GroupPopulation::Unknown ? EPROTO : 0};
}
PopulationResult read_population(int fd) {
  char bytes[4096];
  const ssize_t size = pread(fd, bytes, sizeof(bytes), 0);
  if (size < 0) {
    const int error = errno;
    return {
        error == ENODEV ? GroupPopulation::Removed : GroupPopulation::Unknown,
        error};
  }
  if (size == 0 || size == static_cast<ssize_t>(sizeof(bytes)))
    return {GroupPopulation::Unknown, EOVERFLOW};
  return parse_population(std::string_view(bytes, static_cast<size_t>(size)));
}
struct DirCloser {
  void operator()(DIR* value) const {
    if (value) closedir(value);
  }
};
using Directory = std::unique_ptr<DIR, DirCloser>;
struct Node {
  Directory stream;
  std::string name;
  GroupIdentity identity;
  bool end = false;
};
}  // namespace

struct CapturedCgroup::Impl {
  Fd parent, root, kill, events;
  std::string name;
  GroupIdentity identity;
  CleanupLimits limits;
  std::atomic<bool> cursor_active{false}, removed{false};
  std::atomic<size_t> steps{0}, directories{0}, entries{0}, removals{0};
};
struct ReclamationCursor::Impl {
  std::vector<Node> stack;
  CursorState state = CursorState::Progress;
  Failure failure;
};

namespace detail {
PopulationResult ParsePopulation(std::string_view text) {
  return parse_population(text);
}
}  // namespace detail

CapturedCgroup::CapturedCgroup(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
CapturedCgroup::~CapturedCgroup() = default;
std::shared_ptr<CapturedCgroup> CapturedCgroup::Capture(int parent,
                                                        std::string_view name,
                                                        CleanupLimits limits,
                                                        Failure& failure) {
  failure = {};
  if (!valid_name(name) || !valid_limits(limits)) {
    failure = fail(GroupError::InvalidArgument, EINVAL, "capture inputs");
    return {};
  }
  auto impl = std::make_unique<Impl>();
  impl->parent = duplicate(parent);
  GroupIdentity parent_identity;
  if (!directory_identity(impl->parent.get(), parent_identity, failure))
    return {};
  impl->name = name;
  impl->limits = limits;
  impl->root =
      beneath(impl->parent.get(), impl->name.c_str(), O_RDONLY | O_DIRECTORY);
  if (impl->root.get() < 0) {
    failure = fail(GroupError::Io, errno, "open captured root");
    return {};
  }
  if (!directory_identity(impl->root.get(), impl->identity, failure)) return {};
  if (impl->identity.device != parent_identity.device ||
      impl->identity == parent_identity) {
    failure = fail(GroupError::WrongFilesystem, EXDEV, "root boundary");
    return {};
  }
  impl->kill = beneath(impl->root.get(), "cgroup.kill", O_WRONLY);
  if (impl->kill.get() < 0) {
    failure = fail(GroupError::Io, errno, "capture kill control");
    return {};
  }
  impl->events = beneath(impl->root.get(), "cgroup.events", O_RDONLY);
  if (impl->events.get() < 0) {
    failure = fail(GroupError::Io, errno, "capture events");
    return {};
  }
  const auto population = read_population(impl->events.get());
  if (population.state != GroupPopulation::Empty &&
      population.state != GroupPopulation::Populated) {
    failure = fail(GroupError::UnknownPopulation, population.error,
                   "initial population");
    return {};
  }
  if (!named_identity(impl->parent.get(), impl->name, impl->identity, failure))
    return {};
  return std::shared_ptr<CapturedCgroup>(new CapturedCgroup(std::move(impl)));
}
GroupIdentity CapturedCgroup::identity() const { return impl_->identity; }
CgroupTransfer::~CgroupTransfer() {
  for (int fd : descriptors)
    if (fd >= 0) close(fd);
}
std::unique_ptr<CgroupTransfer> CapturedCgroup::Export(Failure& failure) const {
  failure = {};
  if (impl_->cursor_active.load()) {
    failure = fail(GroupError::Busy, EBUSY, "transfer while cursor owned");
    return {};
  }
  auto transfer = std::make_unique<CgroupTransfer>();
  transfer->name = impl_->name;
  transfer->limits = impl_->limits;
  transfer->stats = stats();
  const std::array<int, 4> source{impl_->parent.get(), impl_->root.get(),
                                  impl_->kill.get(), impl_->events.get()};
  for (size_t n = 0; n < source.size(); ++n) {
    transfer->descriptors[n] = duplicate(source[n]).release();
    if (!transfer_identity(transfer->descriptors[n], n, transfer->identities[n],
                           failure))
      return {};
  }
  return transfer;
}
std::shared_ptr<CapturedCgroup> CapturedCgroup::Adopt(
    std::unique_ptr<CgroupTransfer> transfer, Failure& failure) {
  failure = {};
  if (!transfer || !valid_name(transfer->name) ||
      !valid_limits(transfer->limits) ||
      transfer->stats.steps > transfer->limits.max_total_steps ||
      transfer->stats.directory_visits >
          transfer->limits.max_directory_visits ||
      transfer->stats.entry_visits > transfer->limits.max_entry_visits ||
      transfer->stats.removed_directories > transfer->stats.directory_visits) {
    failure = fail(GroupError::InvalidArgument, EINVAL, "transfer metadata");
    return {};
  }
  for (size_t n = 0; n < transfer->descriptors.size(); ++n) {
    GroupIdentity actual;
    if (!transfer_identity(transfer->descriptors[n], n, actual, failure))
      return {};
    if (actual != transfer->identities[n] ||
        actual.device != transfer->identities[1].device ||
        (n != 1 && actual == transfer->identities[1])) {
      failure = fail(GroupError::IdentityChanged, ESTALE,
                     "transferred object changed");
      return {};
    }
    if (fcntl(transfer->descriptors[n], F_SETFD, FD_CLOEXEC)) {
      failure = fail(GroupError::Io, errno, "protect transferred descriptor");
      return {};
    }
  }
  auto impl = std::make_unique<Impl>();
  impl->parent = Fd(std::exchange(transfer->descriptors[0], -1));
  impl->root = Fd(std::exchange(transfer->descriptors[1], -1));
  impl->kill = Fd(std::exchange(transfer->descriptors[2], -1));
  impl->events = Fd(std::exchange(transfer->descriptors[3], -1));
  impl->identity = transfer->identities[1];
  impl->name = std::move(transfer->name);
  impl->limits = transfer->limits;
  impl->steps = transfer->stats.steps;
  impl->directories = transfer->stats.directory_visits;
  impl->entries = transfer->stats.entry_visits;
  impl->removals = transfer->stats.removed_directories;
  return std::shared_ptr<CapturedCgroup>(new CapturedCgroup(std::move(impl)));
}
Failure CapturedCgroup::ConfirmRemoved() {
  if (impl_->removed.load()) return {};
  if (impl_->cursor_active.load())
    return fail(GroupError::Busy, EBUSY,
                "removal confirmation while cursor owned");
  auto population = ObservePopulation();
  if (population.state != GroupPopulation::Removed ||
      population.error != ENODEV)
    return fail(GroupError::UnknownPopulation, population.error,
                "captured core not removed");
  struct stat info{};
  if (fstatat(impl_->parent.get(), impl_->name.c_str(), &info,
              AT_SYMLINK_NOFOLLOW) == 0)
    return fail(GroupError::IdentityChanged, ESTALE,
                "retired name unexpectedly present");
  if (errno != ENOENT)
    return fail(GroupError::Io, errno, "confirm retired parent entry");
  impl_->removed = true;
  return {};
}
PopulationResult CapturedCgroup::ObservePopulation() const {
  if (impl_->removed.load()) return {GroupPopulation::Removed, 0};
  return read_population(impl_->events.get());
}
Failure CapturedCgroup::Kill() const {
  if (impl_->removed.load())
    return fail(GroupError::Removed, ENODEV, "retired captured root");
  const ssize_t result = pwrite(impl_->kill.get(), "1", 1, 0);
  if (result == 1) return {};
  const int error = result < 0 ? errno : EIO;
  return fail(error == ENODEV ? GroupError::Removed : GroupError::Io, error,
              "captured group kill");
}
bool CapturedCgroup::removed() const { return impl_->removed.load(); }
CleanupStats CapturedCgroup::stats() const {
  return {impl_->steps.load(), impl_->directories.load(), impl_->entries.load(),
          impl_->removals.load()};
}
std::unique_ptr<ReclamationCursor> CapturedCgroup::BeginReclaim(
    Failure& failure) {
  failure = {};
  if (impl_->removed.load()) {
    failure = fail(GroupError::Removed, ENODEV, "retired root");
    return {};
  }
  bool inactive = false;
  if (!impl_->cursor_active.compare_exchange_strong(inactive, true)) {
    failure = fail(GroupError::Busy, EBUSY, "cursor already owned");
    return {};
  }
  const auto population = ObservePopulation();
  if (population.state != GroupPopulation::Empty) {
    failure = fail(population.state == GroupPopulation::Populated
                       ? GroupError::Populated
                   : population.state == GroupPopulation::Removed
                       ? GroupError::Removed
                       : GroupError::UnknownPopulation,
                   population.error, "fresh quiescence");
    impl_->cursor_active = false;
    return {};
  }
  if (impl_->directories.load() >= impl_->limits.max_directory_visits) {
    failure = fail(GroupError::Limit, E2BIG, "directory visit budget");
    impl_->cursor_active = false;
    return {};
  }
  // openat2(".") creates a new directory description, not dup's shared offset.
  auto root = beneath(impl_->root.get(), ".", O_RDONLY | O_DIRECTORY);
  GroupIdentity id;
  if (root.get() < 0 || !directory_identity(root.get(), id, failure) ||
      id != impl_->identity) {
    if (failure.code == GroupError::None)
      failure = fail(GroupError::IdentityChanged,
                     root.get() < 0 ? errno : ESTALE, "cursor root");
    impl_->cursor_active = false;
    return {};
  }
  Directory directory(fdopendir(root.get()));
  if (!directory) {
    failure = fail(GroupError::Io, errno, "root directory stream");
    impl_->cursor_active = false;
    return {};
  }
  root.release();
  auto cursor = std::make_unique<ReclamationCursor::Impl>();
  cursor->stack.reserve(impl_->limits.max_depth + 1);
  cursor->stack.push_back({std::move(directory), impl_->name, id, false});
  ++impl_->directories;
  return std::unique_ptr<ReclamationCursor>(
      new ReclamationCursor(shared_from_this(), std::move(cursor)));
}
ReclamationCursor::ReclamationCursor(std::shared_ptr<CapturedCgroup> scope,
                                     std::unique_ptr<Impl> impl)
    : scope_(std::move(scope)), impl_(std::move(impl)) {}
ReclamationCursor::~ReclamationCursor() {
  // Close all traversal FDs before another cursor can acquire the root.
  impl_.reset();
  scope_->impl_->cursor_active = false;
}
CleanupStep ReclamationCursor::Step(size_t budget) {
  if (impl_->state != CursorState::Progress)
    return {impl_->state, 0, impl_->failure};
  size_t used = 0;
  auto& root = *scope_->impl_;
  auto blocked = [&](Failure failure) {
    impl_->state = CursorState::Blocked;
    impl_->failure = failure;
    return CleanupStep{CursorState::Blocked, used, failure};
  };
  if (budget == 0 || budget > root.limits.max_steps_per_call)
    return blocked(fail(GroupError::InvalidArgument, EINVAL, "step quantum"));
  while (used < budget) {
    if (root.steps.load() >= root.limits.max_total_steps)
      return blocked(
          fail(GroupError::Limit, E2BIG, "total cleanup work budget"));
    ++used;
    ++root.steps;
    Node& node = impl_->stack.back();
    const int current = dirfd(node.stream.get());
    if (!node.end) {
      errno = 0;
      dirent* entry = readdir(node.stream.get());
      if (!entry) {
        if (errno)
          return blocked(fail(GroupError::Io, errno, "read group directory"));
        node.end = true;
        continue;
      }
      if (root.entries.load() >= root.limits.max_entry_visits)
        return blocked(fail(GroupError::Limit, E2BIG, "entry visit budget"));
      ++root.entries;
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
      struct stat info{};
      if (fstatat(current, entry->d_name, &info, AT_SYMLINK_NOFOLLOW))
        return blocked(fail(GroupError::Io, errno, "inspect child entry"));
      if (static_cast<uint64_t>(info.st_dev) != root.identity.device ||
          (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode)))
        return blocked(fail(GroupError::WrongFilesystem, EXDEV,
                            "unexpected child object"));
      if (!S_ISDIR(info.st_mode)) continue;
      if (impl_->stack.size() > root.limits.max_depth ||
          root.directories.load() >= root.limits.max_directory_visits)
        return blocked(
            fail(GroupError::Limit, E2BIG, "directory depth/visit budget"));
      const std::string name(entry->d_name);
      auto child = beneath(current, name.c_str(), O_RDONLY | O_DIRECTORY);
      if (child.get() < 0)
        return blocked(fail(GroupError::Io, errno, "open child directory"));
      GroupIdentity id;
      Failure failure;
      if (!directory_identity(child.get(), id, failure))
        return blocked(failure);
      if (id != GroupIdentity{static_cast<uint64_t>(info.st_dev),
                              static_cast<uint64_t>(info.st_ino)})
        return blocked(fail(GroupError::IdentityChanged, ESTALE,
                            "child changed during open"));
      Directory directory(fdopendir(child.get()));
      if (!directory)
        return blocked(fail(GroupError::Io, errno, "child directory stream"));
      child.release();
      impl_->stack.push_back({std::move(directory), name, id, false});
      ++root.directories;
      continue;
    }
    const int parent =
        impl_->stack.size() == 1
            ? root.parent.get()
            : dirfd(impl_->stack[impl_->stack.size() - 2].stream.get());
    Failure failure;
    if (!named_identity(parent, node.name, node.identity, failure))
      return blocked(failure);
    if (unlinkat(parent, node.name.c_str(), AT_REMOVEDIR))
      return blocked(fail(GroupError::Io, errno, "remove captured directory"));
    ++root.removals;
    const bool final = impl_->stack.size() == 1;
    impl_->stack.pop_back();
    if (final) {
      root.removed = true;
      impl_->state = CursorState::Retired;
      return {CursorState::Retired, used, {}};
    }
  }
  return {CursorState::Progress, used, {}};
}
const char* population_name(GroupPopulation value) {
  switch (value) {
    case GroupPopulation::Unknown:
      return "unknown";
    case GroupPopulation::Populated:
      return "populated";
    case GroupPopulation::Empty:
      return "empty";
    case GroupPopulation::Removed:
      return "removed";
  }
  return "unknown";
}
const char* group_error_name(GroupError value) {
  switch (value) {
    case GroupError::None:
      return "none";
    case GroupError::InvalidArgument:
      return "invalid_argument";
    case GroupError::WrongFilesystem:
      return "wrong_filesystem";
    case GroupError::IdentityChanged:
      return "identity_changed";
    case GroupError::UnknownPopulation:
      return "unknown_population";
    case GroupError::Populated:
      return "populated";
    case GroupError::Removed:
      return "removed";
    case GroupError::Busy:
      return "busy";
    case GroupError::Limit:
      return "limit";
    case GroupError::Io:
      return "io";
  }
  return "io";
}
}  // namespace andrix::supervision
