// SPDX-License-Identifier: Apache-2.0
#include "principal_credentials.h"

#include <fcntl.h>
#include <linux/fscrypt.h>
#include <selinux/selinux.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <string_view>
#include <vector>

namespace andrix {
namespace {
bool empty_capabilities() {
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  std::array<char, 16384> bytes{};
  size_t size = 0;
  for (;;) {
    ssize_t count = read(fd, bytes.data() + size, bytes.size() - size);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) { close(fd); return false; }
    if (!count) break;
    size += static_cast<size_t>(count);
    if (size == bytes.size()) { close(fd); return false; }
  }
  close(fd);
  std::string_view text(bytes.data(), size);
  constexpr std::array<std::string_view, 5> names = {
      "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"};
  std::array<bool, 5> seen{};
  while (!text.empty()) {
    auto end = text.find('\n');
    if (end == std::string_view::npos) return false;
    auto line = text.substr(0, end);
    text.remove_prefix(end + 1);
    for (size_t index = 0; index < names.size(); ++index) {
      if (!line.starts_with(names[index])) continue;
      if (seen[index]) return false;
      seen[index] = true;
      auto value = line.substr(names[index].size());
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
      if (value.empty() || value.size() > 16) return false;
      uint64_t parsed_value = 1;
      auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                    parsed_value, 16);
      if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
          parsed_value != 0)
        return false;
    }
  }
  return std::all_of(seen.begin(), seen.end(), [](bool value) { return value; });
}
}  // namespace

std::string PrincipalManagerContext(const PrincipalProfile& profile) {
  if (!ValidPrincipalProfile(profile)) return {};
  constexpr std::string_view worker = "u:r:andrix_native:s0";
  std::string_view label(profile.selinux_context);
  if (!label.starts_with(worker) ||
      (label.size() != worker.size() && label[worker.size()] != ':'))
    return {};
  return "u:r:andrix_principal_manager:s0" +
         std::string(label.substr(worker.size()));
}

std::string CheckPrincipalCredentials(const PrincipalProfile& profile,
                                      PrincipalStage stage) {
  if (stage != PrincipalStage::Manager && stage != PrincipalStage::Payload)
    return "invalid principal credential stage";
  const auto manager = PrincipalManagerContext(profile);
  if (manager.empty()) return "ordinary native role not selected";
  if (security_getenforce() != 1) return "principal MAC enforcement unavailable";
  uid_t real, effective, saved;
  gid_t greal, geffective, gsaved;
  const auto& principal = profile.binding;
  if (getresuid(&real, &effective, &saved) ||
      getresgid(&greal, &geffective, &gsaved) ||
      real != principal.uid || effective != principal.uid || saved != principal.uid ||
      greal != principal.gid || geffective != principal.gid || saved == 0 ||
      gsaved != principal.gid)
    return "principal credential mismatch";
  int count = getgroups(0, nullptr);
  if (count < 0 || static_cast<size_t>(count) != profile.supplementary_groups.size())
    return "principal supplementary group count";
  std::vector<gid_t> groups(static_cast<size_t>(count));
  if (getgroups(count, groups.data()) != count) return "principal group observation";
  std::sort(groups.begin(), groups.end());
  for (size_t index = 0; index < groups.size(); ++index)
    if (groups[index] != profile.supplementary_groups[index])
      return "principal supplementary group mismatch";
  if (!empty_capabilities()) return "principal retained capabilities";
  char* context = nullptr;
  if (getcon(&context) || !context) return "principal MAC observation";
  const bool correct = std::string_view(context) ==
      (stage == PrincipalStage::Manager ? manager : profile.selinux_context);
  freecon(context);
  if (!correct) return "principal MAC mismatch";
  if (stage == PrincipalStage::Payload &&
      (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
       prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2))
    return "principal syscall profile missing";
  return {};
}

std::string CheckPrincipalHome(int fd, const PrincipalProfile& profile) {
  if (!ValidPrincipalProfile(profile)) return "invalid principal home binding";
  struct stat info{};
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || (flags & O_PATH) || (flags & O_ACCMODE) != O_RDONLY ||
      fstat(fd, &info) || !S_ISDIR(info.st_mode) ||
      info.st_uid != profile.binding.uid)
    return "principal home ownership or descriptor mode";
  constexpr std::string_view worker = "u:r:andrix_native";
  if (PrincipalManagerContext(profile).empty()) return "principal home role";
  const auto label = "u:object_r:andrix_native_home_file" +
                     profile.selinux_context.substr(worker.size());
  char* context = nullptr;
  if (fgetfilecon(fd, &context) < 0 || !context) return "principal home MAC observation";
  const bool correct = label == context;
  freecon(context);
  if (!correct) return "principal home MAC mismatch";
  fscrypt_get_policy_ex_arg policy{};
  policy.policy_size = sizeof(policy.policy);
  if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &policy) ||
      policy.policy.version != FSCRYPT_POLICY_V2 ||
      policy.policy_size != sizeof(fscrypt_policy_v2))
    return "principal home fscrypt policy";
  // This verifies storage shape only. DE can also use fscrypt v2. The trusted
  // account-home provider must establish the directory's CE storage identity;
  // neither this format check nor an open FD verifies its CE key identifier,
  // key availability or the user's current authority. Those are distinct
  // factory/admission inputs.
  return {};
}
}  // namespace andrix
