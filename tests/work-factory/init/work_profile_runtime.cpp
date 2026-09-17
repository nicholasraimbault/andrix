// SPDX-License-Identifier: Apache-2.0
// Linked into init ONLY for the explicitly selected comparison-B lab build.
#ifdef ANDRIX_FACTORY_INIT
#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <map>

#include "action.h"
#include "service_list.h"
#include "work_profile_experiment.h"

namespace android::init {
namespace {
bool Id(const std::string& text, uint64_t* result) {
  if (text.empty()) return false;
  uint64_t value = 0;
  for (char ch : text) {
    if (ch < '0' || ch > '9' ||
        value > ((uint64_t{1} << 62) - uint64_t(ch - '0')) / 10)
      return false;
    value = value * 10 + uint64_t(ch - '0');
  }
  if (!value || value > (uint64_t{1} << 62)) return false;
  *result = value;
  return true;
}
}  // namespace
Result<void> WorkProfileExperiment::ActivateForInit(const Service& service) {
  if (getpid() != 1 || getuid() != 0 || service.uid() != 7500 ||
      service.pid() <= 1 || !service.capabilities_.has_value() ||
      !service.capabilities_->none())
    return Error() << "init profile identity";
  const std::string path =
      "/sys/fs/cgroup/system/uid_7500/pid_" + std::to_string(service.pid());
  android::base::unique_fd group(
      open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  struct statfs fs{};
  struct stat owner{};
  if (group < 0 || fstatfs(group, &fs) || fs.f_type != CGROUP2_SUPER_MAGIC ||
      fstat(group, &owner) || (owner.st_uid != 0 && owner.st_uid != 1000))
    return Error() << "actual init cgroup";
  for (auto [name, value] : {std::pair{"memory.max", "268435456"},
                             {"memory.swap.max", "0"},
                             {"memory.oom.group", "1"}}) {
    android::base::unique_fd fd(
        openat(group.get(), name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd < 0 || !android::base::WriteStringToFd(value, fd.get()))
      return Error() << "init memory write " << name;
    fd.reset(openat(group.get(), name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    std::string actual;
    struct stat st{};
    if (fd < 0 || fstat(fd, &st) || (st.st_uid != 0 && st.st_uid != 1000) ||
        (st.st_mode & S_IWOTH) ||
        !android::base::ReadFdToString(fd.get(), &actual) ||
        actual != std::string(value) + "\n")
      return Error() << "init memory readback " << name;
  }
  return {};
}
Result<pid_t> WorkProfileExperiment::StartForInit(uint64_t manager,
                                                  uint64_t work) {
  if (getpid() != 1 || getuid() != 0 ||
      !android::base::GetBoolProperty("ro.debuggable", false) ||
      android::base::GetProperty("ro.andrix.factory_backend", "") != "init" ||
      !manager || !work)
    return Error() << "init lab selection";
  static WorkProfileExperiment factory(FixtureDefinition());
  // This bounded lab table is not a production reservation protocol. It keeps
  // queued duplicate property actions from creating a second instance.
  static std::map<std::pair<uint64_t, uint64_t>, std::string> tickets;
  auto& services = ServiceList::GetInstance();
  const auto key = std::pair{manager, work};
  if (auto found = tickets.find(key); found != tickets.end()) {
    auto service = services.FindService(found->second);
    if (!service || !service->IsRunning()) return Error() << "spent instance";
    return service->pid();
  }
  if (tickets.size() >= 16) return Error() << "finite fixture allocation limit";
  tickets.emplace(
      key,
      "");  // Consume failure too; never silently retry uncertain creation.
  auto result = factory.Create(services);
  if (!result.ok()) return result.error();
  Service* service = result->service;
  service->args_.push_back(std::to_string(manager));
  service->args_.push_back(std::to_string(work));
  service->flags_ |= SVC_ANDRIX_FACTORY_PROOF;
  tickets[key] = service->name();
  auto started = service->Start();
  if (!started.ok()) {
    // A forked service must remain registered until normal init reap/cleanup.
    if (service->pid() == 0) services.RemoveService(*service);
    return started.error();
  }
  return service->pid();
}
Result<void> do_andrix_factory_start(const BuiltinArguments& args) {
  const auto split = args[1].find(':');
  uint64_t manager = 0, work = 0;
  if (split == std::string::npos || !Id(args[1].substr(0, split), &manager) ||
      !Id(args[1].substr(split + 1), &work))
    return Error() << "bounded literal factory ticket";
  auto result = WorkProfileExperiment::StartForInit(manager, work);
  const std::string reply =
      args[1] + ":" + (result.ok() ? std::to_string(*result) : "0");
  if (!android::base::SetProperty("sys.andrix.factory.reply", reply))
    return Error() << "factory reply publication";
  if (!result.ok()) return result.error();
  return {};
}
}  // namespace android::init
#endif
