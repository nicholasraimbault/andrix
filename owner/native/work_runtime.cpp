// SPDX-License-Identifier: Apache-2.0
#include "work_runtime.h"

#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <limits>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace andrix {
namespace work_runtime_detail {
namespace group = supervision;
class Fd {
 public:
  explicit Fd(int fd = -1) : fd_(fd) {}
  ~Fd() { reset(); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  Fd& operator=(Fd&& other) noexcept {
    if (this != &other) reset(std::exchange(other.fd_, -1));
    return *this;
  }
  int get() const { return fd_; }
  void reset(int fd = -1) {
    int old = std::exchange(fd_, fd);
    if (old >= 0) close(old);
  }

 private:
  int fd_;
};
uint64_t now() {
  timespec value{};
  if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
  return uint64_t(value.tv_sec) * 1000 + uint64_t(value.tv_nsec) / 1000000;
}
void pause() {
  timespec delay{0, 20 * 1000 * 1000};
  while (nanosleep(&delay, &delay) && errno == EINTR) {
  }
}
bool directory(int fd, LaunchObjectIdentity& identity) {
  struct stat info{};
  struct statfs fs{};
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || (flags & O_PATH) || (flags & O_ACCMODE) != O_RDONLY ||
      fstat(fd, &info) || fstatfs(fd, &fs) || !S_ISDIR(info.st_mode) ||
      fs.f_type != CGROUP2_SUPER_MAGIC)
    return false;
  identity = {static_cast<uint64_t>(info.st_dev),
              static_cast<uint64_t>(info.st_ino)};
  return identity.device && identity.inode;
}
bool principal_identity(const PrincipalProfile& profile) {
  uid_t real, effective, saved;
  gid_t greal, geffective, gsaved;
  return !getresuid(&real, &effective, &saved) &&
         !getresgid(&greal, &geffective, &gsaved) &&
         real == profile.binding.uid && effective == real && saved == real &&
         greal == profile.binding.gid && geffective == greal && gsaved == greal;
}
struct Initial {
  explicit Initial(pid_t pid) : pid(pid) {}
  const pid_t pid;
  Fd pidfd;
  std::atomic<bool> placed{false};
};
struct State;
struct Job {
  explicit Job(WorkStartReply& reply)
      : backend(std::move(reply.backend)),
        stdio(std::move(reply.stdio_lease)) {}
  WorkBackend backend;
  WorkIoLease
      stdio;  // Creator only, released at handoff/failure, never history.
  std::mutex mutex;
  std::shared_ptr<group::CapturedCgroup> scope;
  std::shared_ptr<Initial> initial;
  std::optional<WorkObservation> observation;
  std::optional<WorkCleanup> cleanup;
  uint64_t issued = 0;
  std::atomic<WorkRuntimePhase> phase{WorkRuntimePhase::Admitting};
  std::atomic<bool> blocked{false}, kill_pending{false}, cease_killer{false},
      finished{false}, published{false}, joined{false}, retired{false};
  std::atomic<int> error{0}, kill_error{0};
  std::atomic<pid_t> diagnostic_pid{0};
  pthread_t lifecycle{}, killer{};
  bool lifecycle_started = false, killer_started = false, collecting = false;
};
struct State {
  State(WorkRuntimeConfig config,
        std::shared_ptr<WorkRuntimeAuthority> authority)
      : config(std::move(config)),
        authority(std::move(authority)),
        jobs(this->config.jobs) {}
  const WorkRuntimeConfig config;
  const std::shared_ptr<WorkRuntimeAuthority> authority;
  Fd aggregate, parent, home;
  bool valid = false;
  bool closed = false;
  mutable std::mutex mutex;
  std::vector<std::shared_ptr<Job>> jobs;
};
struct Invocation {
  std::shared_ptr<State> state;
  std::shared_ptr<Job> job;
};
void observe(const State& state, const Job& job, WorkRuntimePoint point) {
  if (state.config.observer)
    state.config.observer->At(point, job.backend.identity());
}
void* terminate(void* argument) {
  std::unique_ptr<Invocation> call(static_cast<Invocation*>(argument));
  auto job = call->job;
  while (!job->cease_killer.load()) {
    if (job->backend.termination_requested()) {
      // A requester can be descheduled between its metadata bit and gate Stop.
      // Close permission ourselves before sampling placement and signalling.
      job->backend.gate()->Stop();
      std::shared_ptr<Initial> initial;
      std::shared_ptr<group::CapturedCgroup> scope;
      {
        std::lock_guard lock(job->mutex);
        initial = job->initial;
        scope = job->scope;
      }
      job->kill_pending.store(true);
      // Use the initial pidfd only for the placement gap, while the bootstrap
      // is still trusted management code. Once placed, the retained scope is
      // the termination authority. Do not ask for direct signalling across the
      // owner MAC transition or widen policy to make that unnecessary path
      // work.
      if (initial && !initial->placed.load() && initial->pidfd.get() >= 0) {
        observe(*call->state, *job, WorkRuntimePoint::BeforeInitialSignal);
        if (syscall(SYS_pidfd_send_signal, initial->pidfd.get(), SIGKILL,
                    nullptr, 0) &&
            errno != ESRCH)
          job->kill_error.store(errno);
      }
      if (scope) {
        auto result = scope->Kill();
        if (result.code != group::GroupError::None &&
            result.code != group::GroupError::Removed)
          job->kill_error.store(result.error ? result.error : EIO);
      }
      job->kill_pending.store(false);
    }
    pause();
  }
  return nullptr;
}
bool same(const WorkLaunchPacket& left, const WorkLaunchPacket& right) {
  return left.work == right.work && left.epoch == right.epoch &&
         left.aggregate == right.aggregate && left.scope == right.scope &&
         left.stdio_closed == right.stdio_closed &&
         left.principal_profile == right.principal_profile;
}
int receive(int socket, pid_t child, const Job& job, uint64_t timeout,
            WorkLaunchMessage& reply) {
  const uint64_t issued = now();
  for (;;) {
    int error = ReceiveWorkLaunch(socket, {child, getuid(), getgid()}, reply);
    if (!error) return 0;
    if (error != EAGAIN && error != EINTR) return error;
    if (job.backend.gate()->phase() == AdmissionPhase::Stopped)
      return ECANCELED;
    uint64_t current = now();
    if (!current || current < issued || current - issued >= timeout)
      return ETIMEDOUT;
    pollfd wait{socket, POLLIN, 0};
    if (poll(&wait, 1, 20) < 0 && errno != EINTR) return errno;
  }
}
void stop_killer(Job& job) {
  job.cease_killer.store(true);
  if (job.killer_started) {
    if (pthread_join(job.killer, nullptr))
      _exit(125);  // No invented cessation.
    job.killer_started = false;
  }
}
void blocked(Job& job, int error) {
  job.error.store(error ? error : EIO);
  job.blocked.store(true);
  job.phase.store(WorkRuntimePhase::Blocked);
  // Captured controls and this occupied job stay in State. The termination
  // lane remains available for a later Stop. No replacement lifecycle worker.
}
void* supervise(void* argument) {
  std::unique_ptr<Invocation> call(static_cast<Invocation*>(argument));
  auto state = call->state;
  auto job = call->job;
  const auto gate = job->backend.gate();
  const auto admitted = state->authority->Admit(gate);
  const bool registered = admitted == AdmissionResult::Accepted;
  if (!job->backend.AdmissionFinished(admitted)) {
    job->stdio.Release();
    stop_killer(*job);
    const bool released = !registered || state->authority->Retire(gate) ==
                                             AdmissionResult::Accepted;
    if (released && job->backend.Inspect().complete) {
      job->phase.store(WorkRuntimePhase::Retired);
      job->retired.store(true);
    } else {
      blocked(*job, EPROTO);  // Refusal is not a misordered-admission repair.
    }
    job->finished.store(true);
    return nullptr;
  }
  job->phase.store(WorkRuntimePhase::Creating);
  Fd root, channel, parent_channel, description, principal;
  std::shared_ptr<group::CapturedCgroup> scope;
  std::shared_ptr<Initial> initial;
  bool allocation_started = false;
  auto create = [&]() -> int {
    if (job->backend.termination_requested()) return ECANCELED;
    LaunchDescription decoded;
    LaunchFailure failure;
    if (!DecodeLaunch(job->backend.description(), {}, decoded, failure))
      return EINVAL;
    description.reset(SealLaunch(decoded, {}, failure));
    if (description.get() < 0) return failure.error ? failure.error : EIO;
    const auto epoch = gate->epoch();
    if (!epoch) return ESTALE;
    if (state->config.principal) {
      int profile_error = 0;
      principal.reset(SealPrincipalLaunch(
          {gate->work(), *epoch, *state->config.principal}, profile_error));
      if (principal.get() < 0) return profile_error ? profile_error : EINVAL;
    }
    observe(*state, *job, WorkRuntimePoint::BeforeScope);
    if (job->backend.termination_requested()) return ECANCELED;
    const std::string name =
        "work_" + std::to_string(job->backend.identity().serial);
    allocation_started = true;
    if (mkdirat(state->parent.get(), name.c_str(), 0755)) return errno;
    root.reset(openat(state->parent.get(), name.c_str(),
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root.get() < 0) return errno;
    group::Failure capture_error;
    scope = group::CapturedCgroup::Capture(
        state->parent.get(), name, state->config.cleanup, capture_error);
    if (!scope) return capture_error.error ? capture_error.error : EIO;
    const auto identity = scope->identity();
    if (!job->backend.CaptureScope({identity.device, identity.inode}))
      return EPROTO;
    {
      std::lock_guard lock(job->mutex);
      job->scope = scope;
    }
    observe(*state, *job, WorkRuntimePoint::AfterScope);
    if (job->backend.termination_requested()) return ECANCELED;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair))
      return errno;
    parent_channel.reset(pair[0]);
    channel.reset(pair[1]);
    int error = ConfigureWorkLaunchSocket(parent_channel.get());
    if (!error) error = ConfigureWorkLaunchSocket(channel.get());
    if (error) return error;
    Fd null(open("/dev/null", O_RDWR | O_CLOEXEC));
    Fd saved_channel(fcntl(channel.get(), F_DUPFD_CLOEXEC, 64));
    Fd saved_null(null.get() >= 0 ? fcntl(null.get(), F_DUPFD_CLOEXEC, 64)
                                  : -1);
    if (saved_channel.get() < 0 || saved_null.get() < 0) return errno;
    const int communication = saved_channel.get(), standard = saved_null.get();
    const char* path = state->config.launcher.c_str();
    char* arguments[] = {const_cast<char*>(path), nullptr};
    char* environment[] = {nullptr};
    pid_t child = fork();
    if (!child) {
      // No allocator, locks, logging, Binder or destructors before fixed exec.
      if (dup2(communication, 3) != 3 || dup2(standard, 0) != 0 ||
          dup2(standard, 1) != 1 || dup2(standard, 2) != 2 ||
          syscall(SYS_close_range, 4, ~0U, 0))
        _exit(125);
      execve(path, arguments, environment);
      _exit(127);
    }
    if (child < 0) return errno;
    // Sole direct-child wait ownership is established immediately. Its numeric
    // PID cannot be reused before this lane finishes placement and reaps it.
    initial = std::make_shared<Initial>(child);
    job->diagnostic_pid.store(child);
    if (!job->backend.InitialCreated()) return EPROTO;
    channel.reset();
    initial->pidfd.reset(static_cast<int>(syscall(SYS_pidfd_open, child, 0)));
    if (initial->pidfd.get() < 0) return errno;
    {
      std::lock_guard lock(job->mutex);
      job->initial = initial;  // Immutable pidfd from here, never replaced.
    }
    observe(*state, *job, WorkRuntimePoint::BeforePlacement);
    if (job->backend.termination_requested()) return ECANCELED;
    Fd placement(
        openat(root.get(), "cgroup.procs", O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (placement.get() < 0) return errno;
    const std::string pid = std::to_string(child);
    ssize_t placed = write(placement.get(), pid.data(), pid.size());
    if (placed != static_cast<ssize_t>(pid.size()))
      return placed < 0 ? errno : EIO;
    // Publish completion before any staging/release/entry can occur.
    initial->placed.store(true);
    observe(*state, *job, WorkRuntimePoint::AfterPlacement);
    if (job->backend.termination_requested() ||
        gate->phase() == AdmissionPhase::Stopped)
      return ECANCELED;
    int gate_error = 0;
    Fd exported(gate->Export(gate_error));
    if (exported.get() < 0) return gate_error;
    WorkLaunchPacket request;
    request.work = gate->work();
    request.epoch = *epoch;
    request.aggregate = state->config.aggregate_identity;
    request.scope = {identity.device, identity.inode};
    request.principal_profile = state->config.principal ? 1 : 0;
    std::array<int, kLaunchFdCount> descriptors{exported.get(),
                                                description.get(),
                                                state->aggregate.get(),
                                                root.get(),
                                                -1,
                                                -1,
                                                -1,
                                                principal.get(),
                                                state->home.get()};
    for (size_t standard_index = 0; standard_index < 3; ++standard_index) {
      int fd = job->stdio.descriptor(standard_index);
      descriptors[static_cast<size_t>(LaunchFd::Input) + standard_index] = fd;
      if (fd < 0) request.stdio_closed |= 1U << standard_index;
    }
    error = SendWorkLaunch(parent_channel.get(), request, descriptors.data(),
                           descriptors.size());
    if (error) return error;
    job->stdio
        .Release();  // SCM_RIGHTS owns the handoff, no metadata writer leak.
    description.reset();
    principal.reset();
    WorkLaunchMessage staged;
    error = receive(parent_channel.get(), child, *job,
                    state->config.handshake_millis, staged);
    if (error) return error;
    if (staged.packet.operation != WorkLaunchOperation::Staged ||
        !same(staged.packet, request))
      return staged.packet.error > 0 ? staged.packet.error : EPROTO;
    if (state->authority->Prepared(gate) != AdmissionResult::Accepted ||
        state->authority->Release(gate) != AdmissionResult::Accepted)
      return ECANCELED;
    request.operation = WorkLaunchOperation::Wake;
    return SendWorkLaunch(parent_channel.get(), request);
  };
  int error = create();
  job->stdio.Release();
  description.reset();
  principal.reset();
  channel.reset();
  parent_channel.reset();
  if (error) {
    job->error.store(error);
    job->backend.Abort(error);
  }
  const auto initial_fact =
      initial ? WorkResourceFact::Captured : WorkResourceFact::Absent;
  const auto scope_fact = scope                ? WorkResourceFact::Captured
                          : allocation_started ? WorkResourceFact::Unknown
                                               : WorkResourceFact::Absent;
  if (!job->backend.CreatorFinished(initial_fact, scope_fact, error)) {
    blocked(*job, EPROTO);
    job->finished.store(true);
    return nullptr;
  }
  bool reaped = !initial;
  job->phase.store(WorkRuntimePhase::Supervising);
  for (;;) {
    if (!reaped) {
      int status = 0;
      pid_t observed = waitpid(initial->pid, &status, WNOHANG);
      if (observed == initial->pid) {
        WorkExit exit;
        if (WIFEXITED(status))
          exit = {WorkExitKind::Code, WEXITSTATUS(status)};
        else if (WIFSIGNALED(status))
          exit = {WorkExitKind::Signal, WTERMSIG(status)};
        else {
          blocked(*job, ECHILD);
          job->finished.store(true);
          return nullptr;
        }
        if (!job->backend.InitialExited(exit) ||
            !job->backend.InitialReaped()) {
          blocked(*job, EPROTO);
          job->finished.store(true);
          return nullptr;
        }
        reaped = true;
      } else if (observed < 0 && errno != EINTR) {
        blocked(*job, errno);
        job->finished.store(true);
        return nullptr;
      }
    }
    if (reaped && !scope) {
      if (allocation_started) {
        blocked(*job, error);
        job->finished.store(true);
        return nullptr;
      }
      stop_killer(*job);
      if (state->authority->Retire(gate) != AdmissionResult::Accepted) {
        blocked(*job, EPROTO);
        job->finished.store(true);
        return nullptr;
      }
      initial.reset();
      root.reset();
      job->blocked.store(false);
      job->phase.store(WorkRuntimePhase::Retired);
      job->retired.store(true);
      job->finished.store(true);
      return nullptr;
    }
    if (reaped && scope) {
      auto ticket = job->backend.Observe();
      if (!ticket) {
        blocked(*job, EPROTO);
        job->finished.store(true);
        return nullptr;
      }
      {
        std::lock_guard lock(job->mutex);
        job->observation = ticket;
        job->issued = now();
      }
      job->phase.store(WorkRuntimePhase::Observing);
      observe(*state, *job, WorkRuntimePoint::BeforeObserve);
      auto population = scope->ObservePopulation();
      const auto known = population.state == group::GroupPopulation::Empty
                             ? WorkPopulation::Empty
                         : population.state == group::GroupPopulation::Populated
                             ? WorkPopulation::Populated
                             : WorkPopulation::Unknown;
      bool current = ticket->Finish(known);
      if (current && known != WorkPopulation::Unknown)
        job->blocked.store(false);
      {
        std::lock_guard lock(job->mutex);
        job->observation.reset();
      }
      if (known == WorkPopulation::Unknown) {
        blocked(*job, population.error ? population.error : EIO);
        job->finished.store(true);
        return nullptr;
      }
      if (current && known == WorkPopulation::Empty) {
        stop_killer(
            *job);  // No outstanding kill/control references at reclamation.
        auto cleanup = job->backend.Reclaim();
        if (!cleanup) {
          blocked(*job, EPROTO);
          job->finished.store(true);
          return nullptr;
        }
        {
          std::lock_guard lock(job->mutex);
          job->cleanup = cleanup;
          job->issued = now();
        }
        job->phase.store(WorkRuntimePhase::Reclaiming);
        observe(*state, *job, WorkRuntimePoint::BeforeReclaim);
        group::Failure failure;
        auto cursor = scope->BeginReclaim(failure);
        if (cursor) {
          for (;;) {
            auto step = cursor->Step(state->config.cleanup.max_steps_per_call);
            if (step.state == group::CursorState::Retired) {
              cursor.reset();
              {
                std::lock_guard lock(job->mutex);
                job->scope.reset();
                job->initial.reset();
              }
              scope.reset();
              initial.reset();
              root.reset();
              const bool admission_retired =
                  state->authority->Retire(gate) == AdmissionResult::Accepted;
              if (!cleanup->Finish(WorkCleanupResult::Reclaimed)) {
                blocked(*job, EPROTO);
                job->finished.store(true);
                return nullptr;
              }
              {
                std::lock_guard lock(job->mutex);
                job->cleanup.reset();
              }
              if (!admission_retired) {
                blocked(*job, EPROTO);
                job->finished.store(true);
                return nullptr;
              }
              job->blocked.store(false);
              job->phase.store(WorkRuntimePhase::Retired);
              job->retired.store(true);
              job->finished.store(true);
              return nullptr;
            }
            if (step.state == group::CursorState::Blocked) {
              failure = step.failure;
              break;
            }
          }
        }
        cleanup->Finish(WorkCleanupResult::Failed,
                        failure.error ? failure.error : EIO);
        {
          std::lock_guard lock(job->mutex);
          job->cleanup.reset();
        }
        blocked(*job, failure.error);
        job->finished.store(true);
        return nullptr;
      }
      job->phase.store(WorkRuntimePhase::Supervising);
    }
    pause();
  }
}
}  // namespace work_runtime_detail

WorkRuntime::WorkRuntime(WorkRuntimeConfig config,
                         std::shared_ptr<WorkRuntimeAuthority> authority) {
  using namespace work_runtime_detail;
  if (!config.jobs || config.jobs > WorkRegistry::kMaximumRecords ||
      !authority || config.launcher.empty() ||
      (config.principal &&
       (!ValidPrincipalProfile(*config.principal) || config.principal_home < 0 ||
        !authority->AcceptsPrincipal(*config.principal) ||
        !principal_identity(*config.principal))) ||
      (!config.principal && config.principal_home != -1) ||
      !config.handshake_millis ||
      config.handshake_millis > 60000 || !config.operation_millis ||
      config.operation_millis > 60000 || config.cleanup.max_depth > 64 ||
      !config.cleanup.max_directory_visits ||
      !config.cleanup.max_entry_visits || !config.cleanup.max_total_steps ||
      !config.cleanup.max_steps_per_call ||
      config.cleanup.max_steps_per_call > 1024 ||
      config.cleanup.directory_retirement !=
          supervision::DirectoryRetirement::Unchanged) {
    config.jobs = 0;
  }
  state_ = std::make_shared<State>(std::move(config), std::move(authority));
  if (state_->jobs.empty()) return;
  if (state_->config.principal) {
    state_->home.reset(fcntl(state_->config.principal_home, F_DUPFD_CLOEXEC, 3));
    struct stat info{};
    const int flags = fcntl(state_->home.get(), F_GETFL);
    const auto& principal = state_->config.principal->binding;
    if (state_->home.get() < 0 || flags < 0 || (flags & O_PATH) ||
        (flags & O_ACCMODE) != O_RDONLY || fstat(state_->home.get(), &info) ||
        !S_ISDIR(info.st_mode) || info.st_uid != principal.uid)
      return;
  }
  state_->aggregate.reset(fcntl(state_->config.aggregate, F_DUPFD_CLOEXEC, 3));
  state_->parent.reset(
      fcntl(state_->config.work_namespace, F_DUPFD_CLOEXEC, 3));
  LaunchObjectIdentity aggregate, parent, declared_identity;
  Fd declared(openat(state_->aggregate.get(), "work",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  state_->valid = directory(state_->aggregate.get(), aggregate) &&
                  directory(state_->parent.get(), parent) &&
                  directory(declared.get(), declared_identity) &&
                  parent == declared_identity &&
                  aggregate == state_->config.aggregate_identity &&
                  aggregate.device == parent.device && aggregate != parent;
}
WorkRuntime::~WorkRuntime() {
  // Caller has ceased Submit/Poll before destruction. This is a teardown lane,
  // not a timeout/cancellation mechanism or a reusable environment boundary.
  StopAll();
  for (auto& job : state_->jobs) {
    if (!job) continue;
    if (job->lifecycle_started && !job->joined.load() &&
        pthread_join(job->lifecycle, nullptr))
      _exit(125);
    work_runtime_detail::stop_killer(*job);
  }
}
bool WorkRuntime::valid() const { return state_->valid; }
bool WorkRuntime::Submit(WorkStartReply& accepted, int& error) {
  using namespace work_runtime_detail;
  error = 0;
  if (!accepted.backend || !accepted.stdio_lease.available() ||
      accepted.stdio_lease.binding() != accepted.backend.stdio() ||
      accepted.result != WorkRegistryResult::Accepted) {
    error = EINVAL;
    return false;
  }
  Poll();
  size_t slot = 0;
  std::shared_ptr<Job> job;
  {
    std::lock_guard lock(state_->mutex);
    if (!state_->valid || state_->closed) {
      error = ESHUTDOWN;
      return false;
    }
    slot = state_->jobs.size();
    for (size_t index = 0; index < state_->jobs.size(); ++index) {
      const auto& existing = state_->jobs[index];
      if (existing &&
          existing->backend.identity() == accepted.backend.identity()) {
        error = EALREADY;
        return false;
      }
      if (!existing && slot == state_->jobs.size()) slot = index;
    }
    if (slot == state_->jobs.size()) {
      error = ENOSPC;
      return false;
    }
    job = std::make_shared<Job>(accepted);
    state_->jobs[slot] = job;  // Capacity before creating either actual thread.
  }
  auto* kill_call = new Invocation{state_, job};
  error = pthread_create(&job->killer, nullptr, terminate, kill_call);
  if (!error) {
    job->killer_started = true;
    auto* create_call = new Invocation{state_, job};
    error = pthread_create(&job->lifecycle, nullptr, supervise, create_call);
    if (error) {
      delete create_call;
      stop_killer(*job);
    } else
      job->lifecycle_started = true;
  } else
    delete kill_call;
  if (error) {
    std::lock_guard lock(state_->mutex);
    accepted.backend = std::move(job->backend);
    accepted.stdio_lease = std::move(job->stdio);
    state_->jobs[slot].reset();
    return false;
  }
  job->published.store(
      true);  // Thread handles are initialized before Poll can join.
  return true;
}
WorkRuntimeSnapshot WorkRuntime::Inspect(WorkIdentity work) const {
  std::shared_ptr<work_runtime_detail::Job> found;
  {
    std::lock_guard lock(state_->mutex);
    for (const auto& job : state_->jobs)
      if (job && job->backend.identity() == work) {
        found = job;
        break;
      }
  }
  if (!found) return {work};
  return {work,
          found->phase.load(),
          found->kill_pending.load(),
          found->blocked.load(),
          found->joined.load(),
          found->error.load(),
          found->kill_error.load(),
          found->diagnostic_pid.load()};
}
void WorkRuntime::Poll() {
  using namespace work_runtime_detail;
  std::vector<std::shared_ptr<Job>> jobs;
  {
    std::lock_guard lock(state_->mutex);
    jobs = state_->jobs;
  }
  const uint64_t current = now();
  for (const auto& job : jobs) {
    if (!job) continue;
    std::optional<WorkObservation> observation;
    std::optional<WorkCleanup> cleanup;
    {
      std::lock_guard lock(job->mutex);
      if ((job->observation || job->cleanup) &&
          (!current || current < job->issued ||
           current - job->issued >= state_->config.operation_millis)) {
        observation = job->observation;
        cleanup = job->cleanup;
      }
    }
    const bool timed_out = (observation && observation->TimedOut()) ||
                           (cleanup && cleanup->TimedOut());
    if (timed_out) job->blocked.store(true);
  }
  // Keep slots occupied until actual thread exit, not just a return intention.
  // Blocked workers can be joined but keep their controls/identity in the
  // table.
  std::vector<std::pair<size_t, std::shared_ptr<Job>>> joins;
  {
    std::lock_guard lock(state_->mutex);
    for (size_t index = 0; index < state_->jobs.size(); ++index) {
      auto& job = state_->jobs[index];
      if (job && job->published.load() && job->finished.load() &&
          !job->joined.load() && !job->collecting) {
        job->collecting = true;
        joins.emplace_back(index, job);
      }
    }
  }
  for (const auto& [index, job] : joins) {
    if (pthread_join(job->lifecycle, nullptr)) _exit(125);
    std::lock_guard lock(state_->mutex);
    job->joined.store(true);
    job->collecting = false;
    if (job->retired.load() && state_->jobs[index] == job)
      state_->jobs[index].reset();
  }
}
void WorkRuntime::StopAll() {
  std::vector<WorkBackend> backends;
  {
    std::lock_guard lock(state_->mutex);
    state_->closed = true;
    for (const auto& job : state_->jobs)
      if (job) backends.push_back(job->backend);
  }
  for (const auto& backend : backends) backend.Abort(ECANCELED);
}
bool WorkRuntime::drained() const {
  std::lock_guard lock(state_->mutex);
  for (const auto& job : state_->jobs)
    if (job) return false;  // Slots leave only after actual lifecycle join.
  return true;
}
}  // namespace andrix
