// SPDX-License-Identifier: Apache-2.0
// Fixed lab scope, never a generic privileged launcher. Init owns this lifetime/group.
#include "guards.h"
#include "platform_lifecycle.h"
#include "scope_gate.h"
#include "session_core.h"
#include "wire.h"

#include <aidl/dev/andrix/proof/scope/BnScopeProof.h>
#include <aidl/dev/andrix/proof/scope/ScopeState.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <android/binder_ibinder.h>
#include <android/binder_ibinder_platform.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <selinux/selinux.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>

using android::base::unique_fd;
using aidl::dev::andrix::proof::scope::ScopeState;
using ndk::ScopedAStatus;
using andrix::scope_proof::Gate;

namespace {
constexpr char kWorker[] = "/system_ext/bin/andrix-scope-worker-probe";
uint64_t millis() {
  timespec t{};
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) _exit(125);
  return uint64_t(t.tv_sec) * 1000 + uint64_t(t.tv_nsec) / 1000000;
}
[[noreturn]] void fail(const std::string& why) {
  LOG(ERROR) << "Scope proof refused: " << why;
  _exit(126);
}
bool protected_number(const std::string& path, uint64_t expected) {
  unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  struct stat st{};
  std::string value;
  if (fd < 0 || fstat(fd, &st) != 0 || (st.st_uid != 0 && st.st_uid != 1000) ||
      (st.st_gid != 0 && st.st_gid != 1000) || (st.st_mode & S_IWOTH) || access(path.c_str(), W_OK) == 0 ||
      !android::base::ReadFdToString(fd, &value)) return false;
  return value == std::to_string(expected) + "\n";
}
bool aggregate_ready() {
  const std::string parent = "/sys/fs/cgroup/system/uid_7500/";
  return protected_number(parent + "memory.max", andrix::kMemoryLimit) &&
      protected_number(parent + "memory.swap.max", 0) &&
      protected_number(parent + "memory.oom.group", 1);
}
void bootstrap() {
  if (!android::base::GetBoolProperty("ro.debuggable", false) || getppid() != 1 ||
      !andrix::check_identity().empty() || !aggregate_ready()) fail("trusted bootstrap/aggregate");
  std::string role;
  if (!android::base::ReadFileToString("/proc/self/attr/current", &role)) fail("guardian MAC observation");
  while (!role.empty() && (role.back() == '\n' || role.back() == '\0')) role.pop_back();
  if (role != "u:r:andrixd:s0") fail("guardian MAC role");
  for (auto [resource, count] : {std::pair{RLIMIT_NPROC, rlim_t(32)},
                                 {RLIMIT_NOFILE, rlim_t(128)}, {RLIMIT_CORE, rlim_t(0)},
                                 {RLIMIT_FSIZE, rlim_t(67108864)}}) {
    rlimit bound{};
    if (getrlimit(resource, &bound) != 0 || bound.rlim_cur != count || bound.rlim_max != count)
      fail("inherited bootstrap rlimit");
  }
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) fail("bootstrap subreaper");
}
void channel(int descriptors[2]) {
  // A passed FD does not bypass the backing object's MAC permissions. Give the
  // closed fixture channels their own label, not access to arbitrary coordinator pipes.
  if (setsockcreatecon("u:object_r:andrix_scope_probe_socket:s0") != 0) fail("channel label");
  const int result = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, descriptors);
  const int saved_errno = errno;
  const int reset = setsockcreatecon(nullptr);
  if (reset != 0) fail("channel label reset");
  if (result != 0) { errno = saved_errno; fail("bounded channel creation"); }
}
bool shell_identity() {
  const char* sid = AIBinder_getCallingSid();
  return sid && AIBinder_getCallingUid() == 2000 && strcmp(sid, "u:r:shell:s0") == 0;
}
bool shell_caller() {
  // Synchronous observation/admission requires a live identifiable caller.
  return shell_identity() && AIBinder_getCallingPid() > 1;
}
ScopedAStatus denied() { return ScopedAStatus::fromExceptionCode(EX_SECURITY); }
uint64_t identity() {
  uint64_t value = 0;
  if (getrandom(&value, sizeof(value), 0) != sizeof(value)) fail("identity entropy");
  return (value & ((uint64_t{1} << 62) - 1)) + 1;
}

class Guardian final : public aidl::dev::andrix::proof::scope::BnScopeProof {
 public:
  explicit Guardian(andrix::PlatformLifecycle& platform) : platform_(platform), gate_(identity()) {}
  ScopedAStatus observe(ScopeState* out) override {
    if (!shell_caller()) return denied();
    std::lock_guard lock(mutex_);
    out->scopeId = static_cast<int64_t>(gate_.id()); out->guardianPid = getpid();
    out->phase = gate_.phase(); out->entryPid = entry_; out->entryExited = entry_exited_;
    out->stopRequests = static_cast<int64_t>(stop_requests_.load()); out->pulses = pulses_;
    out->lastStopCallerPid = last_stop_pid_.load();
    out->descendants.clear();
    for (const auto& [pid, event] : descendants_) { (void)event; out->descendants.push_back(pid); }
    return ScopedAStatus::ok();
  }
  ScopedAStatus hold(int64_t id, bool* accepted) override {
    if (!shell_caller()) return denied();
    *accepted = false;
    std::lock_guard lock(mutex_);
    if (!platform_.ready() || !aggregate_ready() || !andrix::check_resource_bounds().empty() ||
        !gate_.hold(id)) return ScopedAStatus::ok();
    std::string error;
    unique_fd home(andrix::open_ce_home(&error));
    if (home < 0) fail(error);
    int input[2], output[2];
    channel(input);
    unique_fd input_read(input[0]), input_write(input[1]);
    channel(output);
    unique_fd output_read(output[0]), output_write(output[1]);
    if (fcntl(output_read, F_SETFL, O_NONBLOCK) != 0) fail("bounded observation");
    std::string parent = std::to_string(getpid());
    char* args[] = {const_cast<char*>(kWorker), parent.data(), nullptr};
    char path[] = "PATH=/system/bin"; char* env[] = {path, nullptr};
    pid_t coordinator = getpid();
    pid_t child = fork();
    if (child == 0) {
      // Multithreaded fork: syscalls/exec only. No owner data executed as coordinator.
      if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != coordinator ||
          dup2(input_read, 0) < 0 || dup2(output_write, 1) < 0) _exit(125);
      for (int fd = 3; fd < 128; ++fd) close(fd);
      execve(kWorker, args, env);
      _exit(127);
    }
    if (child < 0) fail("entry fork");
    entry_ = child; release_ = std::move(input_write); events_ = std::move(output_read);
    *accepted = true; // Held worker acknowledgement is still asynchronous.
    return ScopedAStatus::ok();
  }
  ScopedAStatus release(int64_t id, bool* accepted) override {
    if (!shell_caller()) return denied();
    *accepted = false;
    std::lock_guard lock(mutex_);
    if (!platform_.ready() || !aggregate_ready() || !gate_.release(id)) return ScopedAStatus::ok();
    char byte = 'R';
    if (release_ < 0 || write(release_, &byte, 1) != 1) fail("release gate failure");
    release_.reset(); *accepted = true;
    return ScopedAStatus::ok();
  }
  ScopedAStatus stop(int64_t id, bool crash) override {
    // Binder deliberately supplies PID 0 for oneway. The kernel UID/SID and
    // immutable scope target still apply; never substitute a supplied PID.
    if (!shell_identity()) return denied();
    last_stop_pid_.store(AIBinder_getCallingPid());
    ++stop_requests_;
    if (gate_.stop(id)) _exit(crash ? 77 : 0); // Never waits on admission/observation mutex.
    return ScopedAStatus::ok();
  }
  void tick() {
    if (platform_.failed()) _exit(0);
    std::lock_guard lock(mutex_);
    if (events_ >= 0) {
      std::array<char, 1024> data{};
      ssize_t n = read(events_, data.data(), data.size());
      if (n > 0) {
        bytes_.append(data.data(), n);
        while (bytes_.size() >= sizeof(andrix::scope_proof::Event)) {
          andrix::scope_proof::Event event{}; memcpy(&event, bytes_.data(), sizeof(event));
          bytes_.erase(0, sizeof(event));
          if (event.magic != andrix::scope_proof::kMagic || event.uid != 7500 || event.pid <= 1 ||
              event.binder_errno != EPERM || (event.cgroup_errno != EPERM && event.cgroup_errno != EACCES))
            fail("worker event/negative control");
          if (event.type == andrix::scope_proof::kHeld && event.pid == entry_) {
            if (!gate_.held()) fail("late/duplicate held event");
          } else if (event.type == andrix::scope_proof::kPulse && event.pid != entry_) {
            if (gate_.phase() != Gate::Released || event.session != event.pid || event.group != event.pid)
              fail("payload/session ordering");
            descendants_[event.pid] = event;
            if (descendants_.size() > 2) fail("descendant observation bound");
            ++pulses_;
          } else { fail("unknown worker event"); }
        }
      } else if (n < 0 && errno != EAGAIN && errno != EINTR) { fail("worker observation read"); }
    }
    int status;
    pid_t child;
    while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
      if (child == entry_) {
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || gate_.phase() != Gate::Released)
          fail("entry exit before released payload");
        entry_exited_ = true;
      }
    }
    if (entry_ > 1 && child < 0 && errno == ECHILD) _exit(0);
  }
 private:
  andrix::PlatformLifecycle& platform_;
  Gate gate_;
  std::atomic<uint64_t> stop_requests_{0};
  std::atomic<int32_t> last_stop_pid_{-1};
  std::mutex mutex_;
  unique_fd release_, events_;
  pid_t entry_ = 0;
  bool entry_exited_ = false;
  int64_t pulses_ = 0;
  std::map<pid_t, andrix::scope_proof::Event> descendants_;
  std::string bytes_;
};
} // namespace

int main(int argc, char** argv) {
  android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));
  if (argc != 2 || (strcmp(argv[1], "a") && strcmp(argv[1], "b")))
    fail("fixed scope label");
  bootstrap();
  const std::string slot = strcmp(argv[1], "b") == 0 ? "b" : "a";
  if (!android::base::SetProperty("sys.andrix.scope_probe." + slot + ".pid", std::to_string(getpid())))
    fail("bound publication");
  const uint64_t began = millis();
  std::string error;
  while (!(error = andrix::check_resource_bounds()).empty()) {
    if (millis() - began > 15000) fail("leaf admission: " + error);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  andrix::PlatformLifecycle platform;
  if (!platform.start()) fail("platform dependency");
  while (!platform.ready()) {
    if (platform.failed() || millis() - began > 20000) fail("platform admission");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ABinderProcess_setThreadPoolMaxThreadCount(2);
  ABinderProcess_startThreadPool();
  auto service = ndk::SharedRefBase::make<Guardian>(platform);
  auto binder = service->asBinder();
  AIBinder_setRequestingSid(binder.get(), true);
  const std::string name = "andrix.proof.scope." + slot;
  ndk::SpAIBinder old(AServiceManager_checkService(name.c_str()));
  if (old.get() && AIBinder_isAlive(old.get())) fail("live scope cannot be replaced");
  if (AServiceManager_addService(binder.get(), name.c_str()) != STATUS_OK) fail("scope service registration");
  LOG(INFO) << "Scope proof ready slot=" << argv[1] << " pid=" << getpid();
  while (millis() - began < 300000) {
    service->tick();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  _exit(0); // Finite fixture lifetime; init still owns the whole group.
}
