// SPDX-License-Identifier: Apache-2.0
// Finite two-slot qualification vehicle, not the product work registry/API.
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <signal.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "../delegated-supervision/android/probe-wire.h"
#include "captured_cgroup.h"
#include "guards.h"
#include "launch_description.h"
#include "platform_lifecycle.h"
#include "wire.h"
#include "work_launch_protocol.h"

using android::base::unique_fd;
using namespace andrix;
namespace proof = andrix::work_probe;
namespace scope = andrix::supervision;
namespace {
[[noreturn]] void die(const char* why) {
  LOG(ERROR) << "work launch vehicle: " << why << " errno=" << errno;
  _exit(125);
}
void need(bool value, const char* why) {
  if (!value) die(why);
}
uint64_t now() {
  timespec t{};
  need(!clock_gettime(CLOCK_MONOTONIC, &t), "clock");
  return uint64_t(t.tv_sec) * 1000 + uint64_t(t.tv_nsec) / 1000000;
}
uint64_t boot = 0, instance = 0, manager = 0;
PlatformLifecycle* platform = nullptr;
unique_fd aggregate, namespace_fd;
LaunchObjectIdentity aggregate_identity;
struct Work {
  std::mutex mutex;
  std::condition_variable changed;
  std::shared_ptr<WorkAdmission> gate;
  // Retained even if the single creator/cleanup lane reports Blocked. No
  // replacement worker or pathname rediscovery is offered by this vehicle.
  unique_fd root, initial;
  std::shared_ptr<scope::CapturedCgroup> obligation;
  proof::Snapshot state;
  std::vector<uint8_t> accepted;
  uint32_t flags = 0;
  bool continue_creation = false, release = false;
  std::string output;
};
std::array<std::shared_ptr<Work>, 2> works;
std::string read_at(int fd, const char* name) {
  unique_fd file(openat(fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (file < 0) return {};
  char bytes[4096];
  ssize_t n = read(file.get(), bytes, sizeof(bytes));
  if (n <= 0 || n == sizeof(bytes)) return {};
  std::string text(bytes, n);
  while (!text.empty() && text.back() == '\n') text.pop_back();
  return text;
}
bool write_at(int fd, const char* name, const std::string& value) {
  unique_fd file(openat(fd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  if (file < 0) return false;
  ssize_t count = write(file.get(), value.data(), value.size());
  if (count < 0) return false;
  if (count != static_cast<ssize_t>(value.size())) {
    errno = EIO;
    return false;
  }
  return true;
}
LaunchObjectIdentity object(int fd) {
  struct stat st{};
  need(!fstat(fd, &st), "captured object");
  return {static_cast<uint64_t>(st.st_dev), static_cast<uint64_t>(st.st_ino)};
}
void stop(const std::shared_ptr<Work>& work) {
  work->gate->Stop();
  {
    std::lock_guard lock(work->mutex);
    work->state.stopped = 1;
    if (!work->state.started) {
      work->state.no_process = 1;
      work->state.empty = 1;
      work->state.retired = 1;
    }
  }
  work->changed.notify_all();
}
void output(Work& work, int fd) {
  char bytes[1024];
  for (size_t n = 0; n < 4; ++n) {
    ssize_t count = recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT);
    if (count <= 0) break;
    std::lock_guard lock(work.mutex);
    work.state.output_bytes += count;
    work.output.append(bytes, count);
    if (work.output.size() >= proof::kOutput)
      work.output.erase(0, work.output.size() - (proof::kOutput - 1));
  }
}
void launch_error(Work& work, int error) {
  std::lock_guard lock(work.mutex);
  work.state.launch_error = error ? error : EIO;
}
int wait_packet(int fd, pid_t child, Work& work, WorkLaunchMessage& received,
                bool stopped_allowed = false, uint64_t timeout = 10000) {
  const uint64_t end = now() + timeout;
  for (;;) {
    int e = ReceiveWorkLaunch(fd, {child, 7500, 7500}, received);
    if (!e) return 0;
    if (e != EAGAIN && e != EINTR) return e;
    if (!stopped_allowed && work.gate->phase() == AdmissionPhase::Stopped)
      return ECANCELED;
    if (now() >= end) return ETIMEDOUT;
    pollfd p{fd, POLLIN, 0};
    if (poll(&p, 1, 20) < 0 && errno != EINTR) return errno;
  }
}
bool exact(const WorkLaunchPacket& a, const WorkLaunchPacket& b) {
  return a.work == b.work && a.epoch == b.epoch && a.aggregate == b.aggregate &&
         a.scope == b.scope && a.stdio_closed == b.stdio_closed;
}
void run_work(std::shared_ptr<Work> work) {
  const auto name = "work_" + std::to_string(work->gate->work().serial);
  unique_fd channel, parent_channel, description;
  unique_fd& root = work->root;
  unique_fd& pidfd = work->initial;
  std::array<unique_fd, 3> stream_parent, stream_child;
  std::shared_ptr<scope::CapturedCgroup> captured;
  pid_t child = 0;
  bool reaped = false, allocation_started = false;
  auto make_and_start = [&]() -> int {
    if (work->gate->phase() == AdmissionPhase::Stopped) return ECANCELED;
    allocation_started =
        true;  // Uncertain/failed creation retains the namespace obligation.
    if (mkdirat(namespace_fd.get(), name.c_str(), 0755)) return errno;
    root.reset(openat(namespace_fd.get(), name.c_str(),
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root < 0) return errno;
    scope::Failure failure;
    captured = scope::CapturedCgroup::Capture(namespace_fd.get(), name,
                                              {8, 64, 512, 4096, 32}, failure);
    if (!captured) return failure.error ? failure.error : EIO;
    work->obligation = captured;
    auto identity = object(root.get());
    {
      std::lock_guard lock(work->mutex);
      work->state.device = identity.device;
      work->state.inode = identity.inode;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair))
      return errno;
    parent_channel.reset(pair[0]);
    channel.reset(pair[1]);
    if (ConfigureWorkLaunchSocket(pair[0]) ||
        ConfigureWorkLaunchSocket(pair[1]))
      return EIO;
    if (setsockcreatecon("u:object_r:andrix_work_io:s0")) return errno;
    int stream_error = 0;
    for (size_t i = 0; i < 3; ++i) {
      if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair)) {
        stream_error = errno;
        break;
      }
      stream_parent[i].reset(pair[0]);
      stream_child[i].reset(pair[1]);
    }
    if (setsockcreatecon(nullptr)) return errno;
    if (stream_error) return stream_error;
    unique_fd null(open("/dev/null", O_RDWR | O_CLOEXEC)),
        saved_channel(fcntl(channel.get(), F_DUPFD_CLOEXEC, 64)),
        saved_null(null >= 0 ? fcntl(null.get(), F_DUPFD_CLOEXEC, 64) : -1);
    if (saved_channel < 0 || saved_null < 0) return errno;
    const int communication = saved_channel.get(), standard = saved_null.get();
    char path[] = "/system_ext/bin/andrix-work-launcher";
    char* arguments[] = {path, nullptr};
    char* environment[] = {nullptr};
    child = fork();
    if (!child) {
      // No allocator, mutex, logging, Binder or C++ destructor before fixed
      // exec.
      if (dup2(communication, 3) != 3 || dup2(standard, 0) != 0 ||
          dup2(standard, 1) != 1 || dup2(standard, 2) != 2 ||
          syscall(SYS_close_range, 4, ~0U, 0))
        _exit(125);
      execve(path, arguments, environment);
      _exit(127);
    }
    if (child < 0) {
      child = 0;
      return errno;
    }
    channel.reset();
    pidfd.reset(static_cast<int>(syscall(SYS_pidfd_open, child, 0)));
    if (pidfd < 0) return errno;
    // This thread is the sole reaper of this direct child. Its PID is still
    // owned and cannot be reused during placement. No waitpid(-1) exists here.
    if (!write_at(root.get(), "cgroup.procs", std::to_string(child)))
      return errno;
    {
      std::unique_lock lock(work->mutex);
      work->state.pid = child;
      if (work->flags & proof::HoldCreation)
        work->changed.wait(lock, [&] { return work->continue_creation; });
      work->state.creator_pending = 0;
    }
    if (work->gate->phase() == AdmissionPhase::Stopped) return ECANCELED;
    LaunchDescription launch;
    LaunchFailure data_failure;
    if (!DecodeLaunch(work->accepted, {}, launch, data_failure)) return EINVAL;
    description.reset(SealLaunch(launch, {}, data_failure));
    if (description < 0) return data_failure.error ? data_failure.error : EIO;
    int gate_error = 0;
    unique_fd gate_fd(work->gate->Export(gate_error));
    if (gate_fd < 0) return gate_error;
    auto epoch = work->gate->epoch();
    if (!epoch) return ESTALE;
    WorkLaunchPacket request;
    request.work = work->gate->work();
    request.epoch = *epoch;
    request.aggregate = aggregate_identity;
    request.scope = identity;
    int descriptors[] = {gate_fd.get(),         description.get(),
                         aggregate.get(),       root.get(),
                         stream_child[0].get(), stream_child[1].get(),
                         stream_child[2].get()};
    int error = SendWorkLaunch(parent_channel.get(), request, descriptors,
                               kLaunchFdCount);
    if (error) return error;
    for (auto& endpoint : stream_child) endpoint.reset();
    shutdown(stream_parent[0].get(), SHUT_WR);
    WorkLaunchMessage staged;
    error = wait_packet(parent_channel.get(), child, *work, staged);
    if (error) return error;
    if (staged.packet.operation != WorkLaunchOperation::Staged ||
        !exact(staged.packet, request))
      return staged.packet.error ? staged.packet.error : EPROTO;
    if (platform->prepare_work(work->gate) != AdmissionResult::Accepted)
      return ECANCELED;
    {
      std::unique_lock lock(work->mutex);
      work->state.staged = 1;
      work->changed.wait(lock, [&] {
        return work->release || work->gate->phase() == AdmissionPhase::Stopped;
      });
    }
    if (work->gate->phase() == AdmissionPhase::Stopped) return ECANCELED;
    if (work->flags & proof::QueueThenStop) {
      if (syscall(SYS_pidfd_send_signal, pidfd.get(), SIGSTOP, nullptr, 0))
        return errno;
      siginfo_t event{};
      if (waitid(P_PIDFD, pidfd.get(), &event, WSTOPPED | WEXITED | WNOWAIT) ||
          event.si_code != CLD_STOPPED)
        return ECHILD;
    }
    if (platform->release_work(work->gate) != AdmissionResult::Accepted)
      return ECANCELED;
    auto wake = request;
    wake.operation = WorkLaunchOperation::Wake;
    error = SendWorkLaunch(parent_channel.get(), wake);
    if (error) return error;
    if (work->flags & proof::QueueThenStop) {
      {
        std::unique_lock lock(work->mutex);
        work->state.queued = 1;
        work->changed.wait(lock, [&] {
          return work->gate->phase() == AdmissionPhase::Stopped;
        });
      }
      if (syscall(SYS_pidfd_send_signal, pidfd.get(), SIGCONT, nullptr, 0))
        return errno;
      WorkLaunchMessage refusal;
      error =
          wait_packet(parent_channel.get(), child, *work, refusal, true, 1000);
      if (!error && refusal.packet.operation == WorkLaunchOperation::Failed &&
          exact(refusal.packet, request) && refusal.packet.error == ECANCELED) {
        std::lock_guard lock(work->mutex);
        work->state.gate_refused = 1;
      }
      return ECANCELED;
    }
    return 0;
  };
  int error = make_and_start();
  if (error) {
    launch_error(*work, error);
    stop(work);
  }
  {
    std::lock_guard lock(work->mutex);
    work->state.creator_pending = 0;
  }
  // Creator has ceased. No new process, namespace mutation or release can occur
  // after this point. Kernel work below never runs in the control socket loop.
  if (!child) {
    reaped = true;
    std::lock_guard lock(work->mutex);
    work->state.no_process = 1;
  }
  uint64_t cleanup_deadline = 0;
  for (;;) {
    if (stream_parent[1] >= 0) output(*work, stream_parent[1].get());
    if (stream_parent[2] >= 0) output(*work, stream_parent[2].get());
    const bool stopped = work->gate->phase() == AdmissionPhase::Stopped;
    if (stopped) {
      if (!cleanup_deadline) cleanup_deadline = now() + 10000;
      if (captured) {
        auto failure = captured->Kill();
        if (failure.code != scope::GroupError::None) {
          std::lock_guard lock(work->mutex);
          work->state.cleanup_error = failure.error ? failure.error : EIO;
        }
      }
      if (!reaped && pidfd >= 0)
        syscall(SYS_pidfd_send_signal, pidfd.get(), SIGKILL, nullptr, 0);
    }
    if (!reaped) {
      int status = 0;
      pid_t done = waitpid(child, &status, WNOHANG);
      if (done == child) {
        reaped = true;
        std::lock_guard lock(work->mutex);
        work->state.reaped = 1;
        work->state.exit_code = WIFEXITED(status)     ? WEXITSTATUS(status)
                                : WIFSIGNALED(status) ? 128 + WTERMSIG(status)
                                                      : -1;
      } else if (done < 0) {
        std::lock_guard lock(work->mutex);
        work->state.blocked = 1;
        return;
      }
    }
    auto population =
        captured ? captured->ObservePopulation() : scope::PopulationResult{};
    if (reaped && captured &&
        population.state == scope::GroupPopulation::Empty) {
      stop(work);
      {
        std::lock_guard lock(work->mutex);
        work->state.empty = 1;
      }
      scope::Failure failure;
      auto cursor = captured->BeginReclaim(failure);
      if (cursor) {
        for (size_t n = 0; n < 128; ++n) {
          auto step = cursor->Step(32);
          if (step.state == scope::CursorState::Retired) {
            cursor.reset();
            work->obligation.reset();
            captured.reset();
            root.reset();
            pidfd.reset();
            parent_channel.reset();
            description.reset();
            for (auto& endpoint : stream_parent) endpoint.reset();
            for (auto& endpoint : stream_child) endpoint.reset();
            platform->retire_work(work->gate);
            std::lock_guard lock(work->mutex);
            work->state.retired = 1;
            return;
          }
          if (step.state == scope::CursorState::Blocked) break;
        }
      }
      std::lock_guard lock(work->mutex);
      work->state.blocked = 1;
      return;
    }
    if (reaped && !allocation_started) {
      platform->retire_work(work->gate);
      std::lock_guard lock(work->mutex);
      work->state.no_process = 1;
      work->state.empty = 1;
      work->state.retired = 1;
      return;
    }
    if ((allocation_started && !captured) ||
        (cleanup_deadline && now() >= cleanup_deadline)) {
      std::lock_guard lock(work->mutex);
      work->state.blocked = 1;
      return;
    }
    usleep(20000);
  }
}
proof::Snapshot snapshot(const std::shared_ptr<Work>& work, int error = 0) {
  std::lock_guard lock(work->mutex);
  auto state = work->state;
  state.error = error;
  state.committed = work->gate->entered();
  state.stopped = work->gate->phase() == AdmissionPhase::Stopped;
  state.authority_ready = platform->ready();
  state.authority_failed = platform->failed();
  state.output_size = static_cast<uint32_t>(work->output.size());
  memcpy(state.output, work->output.data(), work->output.size());
  return state;
}
int inherited(const char* key) {
  const char* text = getenv(key);
  if (!text) return -1;
  int fd = -1;
  auto p = std::from_chars(text, text + strlen(text), fd);
  return p.ec == std::errc{} && *p.ptr == 0 && fd >= 3 && fd < 128 ? fd : -1;
}
bool reference(const char* text) {
  if (!text) return false;
  const char* end = text + strlen(text);
  const char* dot = strchr(text, '.');
  if (!dot) return false;
  auto a = std::from_chars(text, dot, boot),
       b = std::from_chars(dot + 1, end, instance);
  return a.ec == std::errc{} && a.ptr == dot && b.ec == std::errc{} &&
         b.ptr == end && boot && instance;
}
bool peer(int fd) {
  ucred actual{};
  socklen_t size = sizeof(actual);
  char* context = nullptr;
  bool good = !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &actual, &size) &&
              size == sizeof(actual) && actual.uid == 2000 &&
              actual.gid == 2000 && actual.pid > 1 &&
              !getpeercon(fd, &context) && context &&
              std::string_view(context) == "u:r:shell:s0";
  if (context) freecon(context);
  return good;
}
}  // namespace
int main(int argc, char** argv) {
  android::base::InitLogging(argv,
                             android::base::LogdLogger(android::base::SYSTEM));
  need(argc == 1 && getppid() == 1, "fixed platform bootstrap");
  need(check_identity().empty(), "coordinator credentials");
  need(reference(getenv("ANDROID_DELEGATED_INSTANCE")), "service incarnation");
  aggregate.reset(inherited("ANDROID_DELEGATED_ROOT_FD"));
  unique_fd ready(inherited("ANDROID_DELEGATED_READY_FD"));
  need(aggregate >= 0 && ready >= 0, "generic handoff");
  fcntl(aggregate.get(), F_SETFD, FD_CLOEXEC);
  fcntl(ready.get(), F_SETFD, FD_CLOEXEC);
  struct stat st{};
  struct statfs fs{};
  need(!fstat(aggregate.get(), &st) && !fstatfs(aggregate.get(), &fs) &&
           fs.f_type == CGROUP2_SUPER_MAGIC && st.st_uid == 0 && st.st_gid == 0,
       "protected aggregate");
  aggregate_identity = object(aggregate.get());
  need(read_at(aggregate.get(), "memory.max") == "268435456" &&
           read_at(aggregate.get(), "memory.swap.max") == "0" &&
           read_at(aggregate.get(), "memory.oom.group") == "1",
       "aggregate bounds");
  namespace_fd.reset(openat(aggregate.get(), "work",
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  need(namespace_fd >= 0, "owned work namespace");
  need(getrandom(&manager, sizeof(manager), 0) == sizeof(manager) && manager,
       "manager incarnation");
  ABinderProcess_setThreadPoolMaxThreadCount(1);
  ABinderProcess_startThreadPool();
  platform = new PlatformLifecycle;
  need(platform->start(), "real platform observer");
  for (size_t i = 0; i < works.size(); ++i) {
    auto work = std::make_shared<Work>();
    int error = 0;
    work->gate = WorkAdmission::Reserve({manager, i + 1}, error);
    need(bool(work->gate), "unbound reservation allocation");
    work->state.boot = boot;
    work->state.instance = instance;
    work->state.manager = manager;
    work->state.serial = i + 1;
    works[i] = work;
    std::thread([work] {
      {
        std::unique_lock lock(work->mutex);
        work->changed.wait(lock, [&] { return work->state.started != 0; });
      }
      run_work(work);
    }).detach();
  }
  unique_fd listener(
      socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  need(listener >= 0, "listener");
  std::string name = "andrix.work-launch-proof." + std::to_string(boot) + "." +
                     std::to_string(instance);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  need(name.size() + 1 < sizeof(address.sun_path), "listener name");
  memcpy(address.sun_path + 1, name.data(), name.size());
  need(!bind(listener.get(), reinterpret_cast<sockaddr*>(&address),
             offsetof(sockaddr_un, sun_path) + name.size() + 1) &&
           !listen(listener.get(), 4),
       "listener binding");
  andrix::delegated_probe::ReadyMessage message;
  message.boot = boot;
  message.instance = instance;
  message.device = aggregate_identity.device;
  message.inode = aggregate_identity.inode;
  need(send(ready.get(), &message, sizeof(message), MSG_NOSIGNAL) ==
           sizeof(message),
       "actual init readiness");
  ready.reset();
  alarm(900);
  std::array<unique_fd, 4> clients;
  std::array<uint64_t, 4> client_deadlines{};
  for (;;) {
    if (platform->failed())
      for (auto& work : works) stop(work);
    pollfd waits[5]{};
    waits[0] = {listener.get(), POLLIN, 0};
    for (size_t i = 0; i < clients.size(); ++i) {
      if (clients[i] >= 0 && now() >= client_deadlines[i]) clients[i].reset();
      waits[i + 1] = {clients[i].get(), POLLIN, 0};
    }
    poll(waits, 5, 20);
    if (waits[0].revents & POLLIN) {
      unique_fd incoming(accept4(listener.get(), nullptr, nullptr,
                                 SOCK_CLOEXEC | SOCK_NONBLOCK));
      if (incoming >= 0 && peer(incoming.get()))
        for (size_t n = 0; n < clients.size(); ++n)
          if (clients[n] < 0) {
            clients[n] = std::move(incoming);
            client_deadlines[n] = now() + 3000;
            break;
          }
    }
    for (size_t i = 0; i < clients.size(); ++i) {
      if (clients[i] < 0 ||
          !(waits[i + 1].revents & (POLLIN | POLLHUP | POLLERR)))
        continue;
      std::array<uint8_t, sizeof(proof::Command) + proof::kBody> bytes{};
      ssize_t count = recv(clients[i].get(), bytes.data(), bytes.size(),
                           MSG_DONTWAIT | MSG_TRUNC);
      if (count < static_cast<ssize_t>(sizeof(proof::Command)) ||
          count > static_cast<ssize_t>(bytes.size())) {
        clients[i].reset();
        continue;
      }
      proof::Command command;
      memcpy(&command, bytes.data(), sizeof(command));
      if (command.magic != proof::kMagic || command.boot != boot ||
          command.instance != instance || command.slot >= works.size() ||
          command.reserved ||
          command.bytes != static_cast<size_t>(count) - sizeof(command) ||
          (command.manager && command.manager != manager) ||
          (!command.manager &&
           command.operation != proof::Operation::Inspect)) {
        clients[i].reset();
        continue;
      }
      auto work = works[command.slot];
      int error = 0;
      if (command.operation == proof::Operation::Start) {
        std::vector<uint8_t> payload(bytes.begin() + sizeof(command),
                                     bytes.begin() + count);
        LaunchDescription launch;
        LaunchFailure failure;
        if (command.flags & ~uint32_t(proof::HoldCreation | proof::HoldRelease |
                                      proof::QueueThenStop) ||
            !DecodeLaunch(payload, {}, launch, failure))
          error = EINVAL;
        else {
          std::lock_guard lock(work->mutex);
          if (work->state.started) {
            if (work->accepted != payload || work->flags != command.flags)
              error = EEXIST;
          } else if (platform->admit_work(work->gate) !=
                     AdmissionResult::Accepted)
            error = EACCES;
          else {
            auto epoch = work->gate->epoch();
            work->state.started = 1;
            work->state.creator_pending = 1;
            work->state.platform = epoch->platform;
            work->state.generation = epoch->generation;
            work->accepted = std::move(payload);
            work->flags = command.flags;
            work->continue_creation = !(command.flags & proof::HoldCreation);
            work->release = !(command.flags & proof::HoldRelease);
            work->changed.notify_all();
          }
        }
      } else if (command.bytes || command.flags)
        error = EINVAL;
      else if (command.operation == proof::Operation::Stop)
        stop(work);
      else if (command.operation == proof::Operation::Release ||
               command.operation == proof::Operation::ContinueCreation) {
        std::lock_guard lock(work->mutex);
        if (command.operation == proof::Operation::Release)
          work->release = true;
        else
          work->continue_creation = true;
        work->changed.notify_all();
      } else if (command.operation != proof::Operation::Inspect &&
                 command.operation != proof::Operation::ExitManager)
        error = EINVAL;
      auto state = snapshot(work, error);
      send(clients[i].get(), &state, sizeof(state),
           MSG_DONTWAIT | MSG_NOSIGNAL);
      clients[i].reset();
      // Selected, authenticated fault control. Actual init supervision owns
      // the still-live owner descendants, not a best-effort daemon destructor.
      if (!error && command.operation == proof::Operation::ExitManager)
        _exit(37);
    }
  }
}
