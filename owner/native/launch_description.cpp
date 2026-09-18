// SPDX-License-Identifier: Apache-2.0
#include "launch_description.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <limits>
#include <utility>

namespace andrix {
namespace {
constexpr uint32_t kMagic =
    0x41584c44;  // Local versioned byte format, not a public API.
constexpr uint32_t kVersion = 1;
constexpr size_t kHeaderBytes = 24;
constexpr int kSeals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
constexpr unsigned kMemfdOptions =
    0x0001U | 0x0002U;  // CLOEXEC | ALLOW_SEALING.
bool fail(LaunchFailure& failure, LaunchError code, int error = 0) {
  failure = {code, error};
  return false;
}
bool valid_limits(LaunchLimits limits) {
  return limits.bytes >= kHeaderBytes && limits.bytes <= 1024 * 1024 &&
         limits.arguments > 0 && limits.arguments <= 4096 &&
         limits.environment <= 4096;
}
bool clean(const std::string& text) {
  return text.find('\0') == std::string::npos;
}
void integer(std::vector<uint8_t>& out, uint32_t value) {
  for (unsigned n = 0; n < 4; ++n)
    out.push_back(static_cast<uint8_t>(value >> (8 * n)));
}
bool string(std::vector<uint8_t>& out, const std::string& value, size_t bound) {
  if (out.size() > bound || bound - out.size() < 4 ||
      value.size() > bound - out.size() - 4)
    return false;
  integer(out, static_cast<uint32_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
  return true;
}
class Reader {
 public:
  explicit Reader(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}
  bool integer(uint32_t& value) {
    if (remaining() < 4) return false;
    value = 0;
    for (unsigned n = 0; n < 4; ++n)
      value |= uint32_t(bytes_[offset_++]) << (8 * n);
    return true;
  }
  bool string(std::string& value) {
    uint32_t size = 0;
    if (!integer(size) || size > remaining()) return false;
    const auto begin = bytes_.begin() + offset_, end = begin + size;
    if (std::find(begin, end, 0) != end) return false;
    value.assign(begin, end);
    offset_ += size;
    return true;
  }
  size_t remaining() const { return bytes_.size() - offset_; }

 private:
  const std::vector<uint8_t>& bytes_;
  size_t offset_ = 0;
};
}  // namespace
bool EncodeLaunch(const LaunchDescription& description, LaunchLimits limits,
                  std::vector<uint8_t>& result, LaunchFailure& failure) {
  failure = {};
  if (!valid_limits(limits) || description.executable.empty() ||
      description.directory.empty() || description.arguments.empty())
    return fail(failure, LaunchError::Invalid);
  if (description.arguments.size() > limits.arguments ||
      description.environment.size() > limits.environment)
    return fail(failure, LaunchError::Limit);
  size_t remaining = limits.bytes - kHeaderBytes;
  auto validate = [&](const std::string& value) {
    if (remaining < 4 || value.size() > remaining - 4)
      return fail(failure, LaunchError::Limit);
    remaining -= value.size() + 4;
    return clean(value) || fail(failure, LaunchError::Invalid);
  };
  if (!validate(description.executable) || !validate(description.directory))
    return false;
  for (const auto& value : description.arguments)
    if (!validate(value)) return false;
  for (const auto& value : description.environment)
    if (!validate(value)) return false;
  std::vector<uint8_t> encoded;
  encoded.reserve(std::min(limits.bytes, size_t(4096)));
  integer(encoded, kMagic);
  integer(encoded, kVersion);
  integer(encoded, 0);
  integer(encoded, static_cast<uint32_t>(description.arguments.size()));
  integer(encoded, static_cast<uint32_t>(description.environment.size()));
  integer(encoded, 0);
  if (!string(encoded, description.executable, limits.bytes) ||
      !string(encoded, description.directory, limits.bytes))
    return fail(failure, LaunchError::Limit);
  for (const auto& value : description.arguments)
    if (!string(encoded, value, limits.bytes))
      return fail(failure, LaunchError::Limit);
  for (const auto& value : description.environment)
    if (!string(encoded, value, limits.bytes))
      return fail(failure, LaunchError::Limit);
  const uint32_t size = static_cast<uint32_t>(encoded.size());
  for (unsigned n = 0; n < 4; ++n)
    encoded[8 + n] = static_cast<uint8_t>(size >> (8 * n));
  result = std::move(encoded);
  return true;
}
bool DecodeLaunch(const std::vector<uint8_t>& bytes, LaunchLimits limits,
                  LaunchDescription& result, LaunchFailure& failure) {
  failure = {};
  if (!valid_limits(limits)) return fail(failure, LaunchError::Invalid);
  if (bytes.size() > limits.bytes) return fail(failure, LaunchError::Limit);
  Reader reader(bytes);
  uint32_t magic, version, size, arguments, environment, reserved;
  if (!reader.integer(magic) || !reader.integer(version) ||
      !reader.integer(size) || !reader.integer(arguments) ||
      !reader.integer(environment) || !reader.integer(reserved) ||
      magic != kMagic || version != kVersion || size != bytes.size() ||
      reserved || !arguments)
    return fail(failure, LaunchError::Framing);
  if (arguments > limits.arguments || environment > limits.environment)
    return fail(failure, LaunchError::Limit);
  LaunchDescription decoded;
  if (!reader.string(decoded.executable) || !reader.string(decoded.directory) ||
      decoded.executable.empty() || decoded.directory.empty())
    return fail(failure, LaunchError::Framing);
  decoded.arguments.resize(arguments);
  decoded.environment.resize(environment);
  for (auto& value : decoded.arguments)
    if (!reader.string(value)) return fail(failure, LaunchError::Framing);
  for (auto& value : decoded.environment)
    if (!reader.string(value)) return fail(failure, LaunchError::Framing);
  if (reader.remaining()) return fail(failure, LaunchError::Framing);
  result = std::move(decoded);
  return true;
}
int SealLaunch(const LaunchDescription& description, LaunchLimits limits,
               LaunchFailure& failure) {
  std::vector<uint8_t> bytes;
  if (!EncodeLaunch(description, limits, bytes, failure)) return -1;
  int fd = static_cast<int>(
      syscall(SYS_memfd_create, "andrix-launch-description", kMemfdOptions));
  if (fd < 0) {
    fail(failure, LaunchError::Io, errno);
    return -1;
  }
  size_t offset = 0;
  while (offset < bytes.size()) {
    ssize_t count = pwrite(fd, bytes.data() + offset, bytes.size() - offset,
                           static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      int error = count < 0 ? errno : EIO;
      close(fd);
      fail(failure, LaunchError::Io, error);
      return -1;
    }
    offset += static_cast<size_t>(count);
  }
  if (fcntl(fd, F_ADD_SEALS, kSeals)) {
    const int error = errno;
    close(fd);
    fail(failure, LaunchError::Io, error);
    return -1;
  }
  // SCM_RIGHTS preserves open access mode. Reopen THIS owned, still-live memfd
  // read-only before crossing the owner MAC boundary, and verify object
  // identity. The path contains only our own held FD number, never caller
  // filesystem input.
  struct stat before{}, after{};
  const std::string path = "/proc/self/fd/" + std::to_string(fd);
  int readonly = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  auto reject = [&](int error) {
    if (readonly >= 0) close(readonly);
    close(fd);
    fail(failure, LaunchError::Io, error);
    return -1;
  };
  if (readonly < 0 || fstat(fd, &before) || fstat(readonly, &after))
    return reject(errno);
  if (before.st_dev != after.st_dev || before.st_ino != after.st_ino)
    return reject(ESTALE);
  const int observed_seals = fcntl(readonly, F_GET_SEALS);
  if (observed_seals < 0) return reject(errno);
  if ((observed_seals & kSeals) != kSeals) return reject(EINVAL);
  close(fd);
  return readonly;
}
bool ReadLaunch(int fd, LaunchLimits limits, LaunchDescription& result,
                LaunchFailure& failure) {
  failure = {};
  if (!valid_limits(limits)) return fail(failure, LaunchError::Invalid);
  struct stat info{};
  if (fd < 0 || fstat(fd, &info))
    return fail(failure, LaunchError::Io, fd < 0 ? EBADF : errno);
  if (!S_ISREG(info.st_mode) ||
      info.st_size < static_cast<off_t>(kHeaderBytes) ||
      static_cast<uint64_t>(info.st_size) > limits.bytes)
    return fail(failure, LaunchError::Limit);
  const int seals = fcntl(fd, F_GET_SEALS);
  if (seals < 0 || (seals & kSeals) != kSeals)
    return fail(failure, LaunchError::NotSealed, seals < 0 ? errno : 0);
  std::vector<uint8_t> bytes(static_cast<size_t>(info.st_size));
  size_t offset = 0;
  while (offset < bytes.size()) {
    ssize_t count = pread(fd, bytes.data() + offset, bytes.size() - offset,
                          static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0)
      return fail(failure, LaunchError::Io, count < 0 ? errno : EIO);
    offset += static_cast<size_t>(count);
  }
  return DecodeLaunch(bytes, limits, result, failure);
}
}  // namespace andrix
