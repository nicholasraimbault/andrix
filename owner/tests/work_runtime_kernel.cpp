// SPDX-License-Identifier: Apache-2.0
// Actual Linux backend operations in an explicitly owned delegation. Android
// authority/profile facts are NOT established by this host bootstrap fixture.
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "work_catalog.h"
#include "work_runtime.h"
#include "worker_filter.h"

using namespace andrix;
namespace {
uint64_t now() {
  timespec t{};
  assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
  return uint64_t(t.tv_sec) * 1000 + t.tv_nsec / 1000000;
}
void until(auto condition, const char* label) {
  auto started = now();
  while (!condition()) {
    if (now() - started > 15000) {
      fprintf(stderr, "RUNTIME_PROBE_TIMEOUT %s\n", label);
      abort();
    }
    usleep(1000);
  }
}
void packet(int fd, LaunchPeer peer, WorkLaunchMessage& result) {
  until(
      [&] {
        int error = ReceiveWorkLaunch(fd, peer, result);
        assert(!error || error == EAGAIN || error == EINTR);
        return !error;
      },
      "private launch message");
}
void no_controls() {
  DIR* directory = opendir("/proc/self/fd");
  assert(directory);
  while (auto* item = readdir(directory)) {
    if (item->d_name[0] == '.') continue;
    int fd = atoi(item->d_name);
    assert(fd <= 2 || fd == dirfd(directory));
  }
  closedir(directory);
}
int bootstrap() {
  assert(ConfigureWorkLaunchSocket(3) == 0);
  WorkLaunchMessage request;
  packet(3, {getppid(), getuid(), getgid()}, request);
  assert(request.packet.operation == WorkLaunchOperation::Prepare);
  char membership[512]{};
  int current = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
  assert(current >= 0);
  auto count = read(current, membership, sizeof(membership) - 1);
  close(current);
  assert(count > 4);
  std::string path(membership, count);
  assert(path.starts_with("0::/"));
  path = "/sys/fs/cgroup" + path.substr(3);
  while (path.back() == '\n') path.pop_back();
  struct stat actual{};
  assert(stat(path.c_str(), &actual) == 0);
  assert(static_cast<uint64_t>(actual.st_dev) == request.packet.scope.device &&
         static_cast<uint64_t>(actual.st_ino) == request.packet.scope.inode);
  LaunchDescription launch;
  LaunchFailure failure;
  assert(ReadLaunch(
      request.descriptors[static_cast<size_t>(LaunchFd::Description)], {},
      launch, failure));
  int error;
  auto gate =
      WorkAdmission::Adopt(request.Take(LaunchFd::Gate), request.packet.work,
                           request.packet.epoch, error);
  assert(gate && install_worker_filter());
  auto staged = request.packet;
  staged.operation = WorkLaunchOperation::Staged;
  assert(SendWorkLaunch(3, staged) == 0);
  WorkLaunchMessage wake;
  packet(3, {getppid(), getuid(), getgid()}, wake);
  assert(wake.packet.operation == WorkLaunchOperation::Wake &&
         wake.packet.work == request.packet.work &&
         wake.packet.epoch == request.packet.epoch &&
         wake.packet.stdio_closed == request.packet.stdio_closed);
  if (gate->ClaimEntry(request.packet.work, request.packet.epoch, now()) !=
      EntryResult::Entered)
    return 126;
  gate.reset();
  for (int index = 0; index < 3; ++index) {
    if (request.packet.stdio_closed & (1U << index))
      assert(close(index) == 0);
    else
      assert(
          dup2(
              request.descriptors[static_cast<size_t>(LaunchFd::Input) + index],
              index) == index);
  }
  assert(syscall(SYS_close_range, 3, ~0U, 0) == 0);
  assert(chdir(launch.directory.c_str()) == 0);
  std::vector<char*> arguments, environment;
  for (auto& value : launch.arguments) arguments.push_back(value.data());
  arguments.push_back(nullptr);
  for (auto& value : launch.environment) environment.push_back(value.data());
  environment.push_back(nullptr);
  execve(launch.executable.c_str(), arguments.data(), environment.data());
  return 127;
}
int payload(const char* mode) {
  no_controls();
  assert(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 &&
         prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2);
  assert(getenv("WORK_FIXTURE") && !strcmp(getenv("WORK_FIXTURE"), "ordinary"));
  if (!strcmp(mode, "descendant")) {
    pid_t child = fork();
    assert(child >= 0);
    if (child) return 0;
    assert(setsid() >= 0);
  }
  dprintf(1, "LIVE %d\n", getpid());
  if (!strcmp(mode, "exit")) return 23;
  for (;;) pause();
}
struct Authority final : WorkRuntimeAuthority {
  AdmissionAuthority authority;
  std::mutex mutex;
  void refresh() {
    auto clock = now();
    assert(authority.Observe({700, 1, 0}, clock + 2000, clock) ==
           AdmissionResult::Accepted);
  }
  AdmissionResult Admit(const std::shared_ptr<WorkAdmission>& gate) override {
    std::lock_guard lock(mutex);
    refresh();
    return authority.Admit(gate, now());
  }
  AdmissionResult Prepared(
      const std::shared_ptr<WorkAdmission>& gate) override {
    std::lock_guard lock(mutex);
    refresh();
    return authority.Prepared(gate, now());
  }
  AdmissionResult Release(const std::shared_ptr<WorkAdmission>& gate) override {
    std::lock_guard lock(mutex);
    refresh();
    return authority.Release(gate, now());
  }
  AdmissionResult Retire(const std::shared_ptr<WorkAdmission>& gate) override {
    std::lock_guard lock(mutex);
    return authority.Retire(gate);
  }
};
struct Observer final : WorkRuntimeObserver {
  std::mutex mutex;
  std::condition_variable changed;
  WorkRuntimePoint point = WorkRuntimePoint::BeforeScope;
  uint64_t serial = 0;
  bool arrived = false, released = false;
  void Hold(WorkRuntimePoint next, uint64_t work) {
    std::lock_guard lock(mutex);
    point = next;
    serial = work;
    arrived = false;
    released = false;
  }
  void At(WorkRuntimePoint next, WorkIdentity work) override {
    std::unique_lock lock(mutex);
    if (next != point || work.serial != serial || released) return;
    arrived = true;
    changed.notify_all();
    changed.wait(lock, [&] { return released; });
  }
  bool Arrived() {
    std::lock_guard lock(mutex);
    return arrived;
  }
  void Release() {
    std::lock_guard lock(mutex);
    released = true;
    changed.notify_all();
  }
};
struct Running {
  WorkHandle work;
  int output = -1;
};
int manager(int aggregate, int parent, const char* executable) {
  assert(getuid() != 0 && prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
  struct stat identity{};
  assert(fstat(aggregate, &identity) == 0);
  WorkRuntimeConfig config;
  config.jobs = 4;
  config.aggregate = aggregate;
  config.work_namespace = parent;
  config.aggregate_identity = {static_cast<uint64_t>(identity.st_dev),
                               static_cast<uint64_t>(identity.st_ino)};
  config.launcher = executable;
  config.cleanup = {8, 64, 512, 4096, 32};
  config.operation_millis = 100;
  Observer observer;
  config.observer = &observer;
  auto authority = std::make_shared<Authority>();
  WorkCatalog catalog(88, {4, 4, 2, {}, UINT64_MAX, UINT64_MAX, UINT64_MAX});
  WorkRuntime runtime(config, authority);
  assert(runtime.valid());
  auto stream = catalog.OpenStream();
  uint64_t sequence = 0;
  auto begin = [&](const char* mode, bool submit = true) {
    auto reservation = catalog.Reserve(stream, ++sequence);
    assert(reservation.work);
    int pipefd[2];
    assert(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
    LaunchFailure failure;
    int description = SealLaunch({executable,
                                  {executable, "--payload", mode},
                                  {"WORK_FIXTURE=ordinary"},
                                  "/"},
                                 {}, failure);
    assert(description >= 0);
    auto input =
        catalog.Prepare(reservation.work, description, {-1, pipefd[1], -1});
    assert(input.result == WorkRegistryResult::Accepted);
    close(description);
    close(pipefd[1]);
    if (submit) {
      auto accepted = catalog.Start(reservation.work, input.identity);
      int error;
      assert(accepted.backend && runtime.Submit(accepted, error));
    }
    return Running{reservation.work, pipefd[0]};
  };
  auto marker = [&](Running& work) {
    std::string text;
    until(
        [&] {
          runtime.Poll();
          char bytes[128];
          auto count = read(work.output, bytes, sizeof(bytes));
          if (count > 0)
            text.append(bytes, count);
          else
            assert(count < 0 && (errno == EAGAIN || errno == EINTR));
          return text.find('\n') != std::string::npos;
        },
        "owner fixture marker");
    int pid = 0;
    assert(sscanf(text.c_str(), "LIVE %d", &pid) == 1 && pid > 1);
    return pid;
  };
  auto retired = [&](Running& work) {
    until(
        [&] {
          runtime.Poll();
          return work.work.Inspect().work.complete &&
                 runtime.Inspect(work.work.identity()).phase ==
                     WorkRuntimePhase::Missing;
        },
        "runtime retirement");
    char byte;
    assert(read(work.output, &byte, 1) == 0);
  };
  auto forget = [&](Running& work) {
    assert(catalog.Forget(work.work) == WorkRegistryResult::Accepted);
    close(work.output);
    work.work = {};
    catalog.Collect();
  };
  auto first = begin("descendant");
  pid_t descendant = marker(first);
  until(
      [&] {
        runtime.Poll();
        return first.work.Inspect().work.initial == WorkInitialState::Reaped;
      },
      "initial exit distinct from descendants");
  auto live = first.work.Inspect().work;
  assert(live.initial_exit == (WorkExit{WorkExitKind::Code, 0}) &&
         live.entry_gate_closed && !live.complete && !live.stop_sources);
  int descendant_fd = static_cast<int>(syscall(SYS_pidfd_open, descendant, 0));
  assert(descendant_fd >= 0);
  pollfd wait{descendant_fd, POLLIN, 0};
  assert(poll(&wait, 1, 100) == 0);  // Actual descendant remains live.
  observer.Hold(WorkRuntimePoint::BeforeScope, sequence + 1);
  auto late = begin("sleep");
  until([&] { return observer.Arrived(); }, "held creator");
  late.work.Stop();
  assert(late.work.Inspect().work.creator_pending);
  first.work.Stop();
  retired(first);
  int status;
  assert(waitpid(descendant, &status, 0) == descendant && WIFSIGNALED(status) &&
         WTERMSIG(status) == SIGKILL);
  close(descendant_fd);
  assert(late.work.Inspect().work.creator_pending &&
         !late.work.Inspect().work.entry_claimed);
  observer.Release();
  retired(late);
  assert(late.work.Inspect().work.initial == WorkInitialState::Absent);
  forget(first);
  forget(late);

  observer.Hold(WorkRuntimePoint::AfterPlacement, sequence + 1);
  auto bootstrap_held = begin("sleep");
  until([&] { return observer.Arrived(); }, "live placed bootstrap held");
  auto initial = runtime.Inspect(bootstrap_held.work.identity()).initial_pid;
  assert(initial > 1);
  int initial_fd = static_cast<int>(syscall(SYS_pidfd_open, initial, 0));
  assert(initial_fd >= 0);
  pollfd initial_wait{initial_fd, POLLIN, 0};
  assert(poll(&initial_wait, 1, 0) == 0);
  bootstrap_held.work.Stop();
  assert(poll(&initial_wait, 1, 5000) == 1);
  assert(bootstrap_held.work.Inspect().work.creator_pending);
  observer.Release();
  retired(bootstrap_held);
  assert(!bootstrap_held.work.Inspect().work.entry_claimed &&
         bootstrap_held.work.Inspect().work.initial_exit ==
             (WorkExit{WorkExitKind::Signal, SIGKILL}));
  close(initial_fd);
  forget(bootstrap_held);

  observer.Hold(WorkRuntimePoint::BeforeObserve, sequence + 1);
  auto held = begin("descendant");
  pid_t held_descendant = marker(held);
  until([&] { return observer.Arrived(); }, "held observation");
  held.work.Stop();
  until(
      [&] {
        runtime.Poll();
        return held.work.Inspect().work.blocked;
      },
      "observation timeout retains ticket");
  assert(held.work.Inspect().work.observation_pending &&
         !held.work.Inspect().work.complete);
  auto other = begin("sleep");
  marker(other);
  other.work.Stop();
  retired(other);
  assert(held.work.Inspect().work.observation_pending);
  observer.Release();
  retired(held);
  assert(waitpid(held_descendant, &status, 0) == held_descendant &&
         WIFSIGNALED(status));
  forget(held);
  forget(other);
  auto ordinary_exit = begin("exit");
  marker(ordinary_exit);
  retired(ordinary_exit);
  assert(ordinary_exit.work.Inspect().work.initial_exit ==
         (WorkExit{WorkExitKind::Code, 23}));
  forget(ordinary_exit);
  assert(runtime.drained());
  puts(
      "{\"live_bootstrap_stopped_before_late_handoff\":true,"
      "\"real_cgroup_runtime\":true,\"ordinary_initial_exit_preserves_"
      "descendant\":true,\"stop_during_held_creator\":true,\"independent_stop_"
      "during_held_observation\":true,\"late_observation_not_reclaimed_as_"
      "fresh\":true,\"stdio_EOF_with_metadata_retained\":true,\"Android_"
      "authority_profile_or_phone_qualified\":false}");
  return 0;
}
}  // namespace
int main(int argc, char** argv) {
  alarm(80);
  if (argc == 1) return bootstrap();
  if (argc == 3 && !strcmp(argv[1], "--payload")) return payload(argv[2]);
  assert(argc == 4 && !strcmp(argv[1], "--manager"));
  return manager(atoi(argv[2]), atoi(argv[3]), argv[0]);
}
