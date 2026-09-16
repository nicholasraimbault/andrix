// SPDX-License-Identifier: Apache-2.0
#include "guards.h"
#include "session_core.h"
#include "terminal_protocol.h"
#include "terminal_process.h"
#ifdef ANDRIX_OWNER_LIFECYCLE
#include "platform_lifecycle.h"
#endif
#ifdef ANDRIX_OWNER_KEEP
#ifndef ANDRIX_OWNER_LIFECYCLE
#error Keep requires Android lifecycle observation
#endif
#include <aidl/dev/andrix/lifecycle/BnKeptWork.h>
#endif

#include <aidl/dev/andrix/session/BnOwnerSession.h>
#include <android/binder_ibinder_platform.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include <fcntl.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <thread>

using android::base::unique_fd;
using ndk::ScopedAStatus;
using aidl::dev::andrix::session::Attachment;

namespace andrix {
namespace {

uint64_t now_ms() {
  timespec ts{};
  if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) _exit(125);
  return uint64_t(ts.tv_sec) * 1000 + uint64_t(ts.tv_nsec) / 1000000;
}

uint64_t active_ms() {
  timespec ts{};
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) _exit(125);
  return uint64_t(ts.tv_sec) * 1000 + uint64_t(ts.tv_nsec) / 1000000;
}

uint64_t epoch_seed() {
  uint64_t value = 0;
  ssize_t size;
  do { size = getrandom(&value, sizeof(value), 0); } while (size < 0 && errno == EINTR);
  if (size != static_cast<ssize_t>(sizeof(value))) _exit(125);
  // Fresh per-coordinator epoch, positive Java long and room for monotonic IDs.
  return (value & ((uint64_t{1} << 62) - 1)) + 1;
}

bool caller_allowed() {
  const char* sid = AIBinder_getCallingSid();
  return sid && AIBinder_getCallingPid() > 1 && authorized_console(AIBinder_getCallingUid(), sid);
}

ScopedAStatus denied() {
  return ScopedAStatus::fromExceptionCodeWithMessage(EX_SECURITY, "not the primary Andrix console");
}

ScopedAStatus bad_state(const std::string& text) {
  return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_STATE, text.c_str());
}

#ifdef ANDRIX_OWNER_KEEP
// A supplied old Binder handle cannot target a replacement daemon. This token
// exists for one native process/work ID; Stop needs no possibly-stalled main lock.
class KeptWorkToken final : public aidl::dev::andrix::lifecycle::BnKeptWork {
 public:
  explicit KeptWorkToken(uint64_t work) : work_(work) { }
  ScopedAStatus stop(int64_t work, int64_t registration) override {
    const char* sid = AIBinder_getCallingSid();
    if (!sid || AIBinder_getCallingUid() != 1000 ||
        std::strcmp(sid, "u:r:system_server:s0") != 0 ||
        work <= 0 || uint64_t(work) != work_ || registration <= 0) return denied();
    _exit(0); // Android init, not a guessed process group, owns complete cleanup.
  }
 private:
  const uint64_t work_;
};
#endif

class OwnerSession final : public aidl::dev::andrix::session::BnOwnerSession {
  struct ControllerCookie { OwnerSession* owner; uint64_t registration; };
 public:
  OwnerSession() : work_id_(epoch_seed()), session_id_(work_id_), gate_(work_id_),
      death_(AIBinder_DeathRecipient_new([](void* value) {
        auto* cookie = static_cast<ControllerCookie*>(value);
        cookie->owner->controller_died(cookie->registration);
      })) {
    if (!death_) _exit(125);
    AIBinder_DeathRecipient_setOnUnlinked(death_, [](void* value) {
      auto* cookie = static_cast<ControllerCookie*>(value);
      if (cookie->owner->death_links_.fetch_sub(1) == 0) _exit(125);
      delete cookie; // Only here: pending death callbacks must finish first.
    });
#ifdef ANDRIX_OWNER_KEEP
    work_lifetime_ = ndk::SharedRefBase::make<KeptWorkToken>(work_id_);
    AIBinder_setRequestingSid(work_lifetime_->asBinder().get(), true);
#endif
  }

  bool start_lifecycle() {
#ifdef ANDRIX_OWNER_LIFECYCLE
    return platform_.start();
#else
    return true;
#endif
  }

  ScopedAStatus registerController(const ndk::SpAIBinder& lifetime) override {
    if (!caller_allowed()) return denied();
    if (!lifetime.get() || !AIBinder_isRemote(lifetime.get()))
      return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT, "missing console lifetime");
    std::lock_guard guard(mutex_);
    if (stopping_) return bad_state("session is ending");
    if (controller_.get()) {
      if (AIBinder_isAlive(controller_.get())) {
        if (controller_pid_ == AIBinder_getCallingPid() && controller_.get() == lifetime.get())
          return ScopedAStatus::ok();
        return bad_state("a different console lifetime is already registered");
      }
      const auto old = controller_;
      auto* cookie = controller_cookie_;
      clear_controller_locked();
      controller_lost_locked();
      // Unlink is not callback quiescence. onUnlinked owns cookie reclamation.
      AIBinder_unlinkToDeath(old.get(), death_, cookie);
      if (stopping_) return bad_state("plain session is ending with its console");
    }
    if (death_links_.load() >= 8 || controller_sequence_ == uint64_t{INT64_MAX})
      return bad_state("console lifetime retirement is full");
    const uint64_t registration = ++controller_sequence_;
    auto* cookie = new (std::nothrow) ControllerCookie{this, registration};
    if (!cookie) return bad_state("console lifetime allocation failed");
    death_links_.fetch_add(1);
    // lifetime/death/cookie are all non-null before transferring link ownership.
    if (AIBinder_linkToDeath(lifetime.get(), death_, cookie) != STATUS_OK)
      return bad_state("console is no longer alive");
    controller_ = lifetime;
    controller_cookie_ = cookie;
    controller_generation_ = registration;
    controller_pid_ = AIBinder_getCallingPid();
    return ScopedAStatus::ok();
  }

  ScopedAStatus attach(int32_t rows, int32_t columns, bool ui_eligible,
                       bool user_unlocked, int64_t previous_session, int64_t next_output,
                       Attachment* result) override {
    if (!caller_allowed()) return denied();
    if (!valid_dimensions(rows, columns) || previous_session < 0 || next_output < 0)
      return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT, "invalid PTY dimensions");
    std::lock_guard guard(mutex_);
    if (starting_keep_) return bad_state("kept work is being prepared");
    return attach_locked(rows, columns, ui_eligible, user_unlocked, previous_session, next_output, result);
  }

  ScopedAStatus startKept(int32_t rows, int32_t columns, bool ui_eligible,
                         bool user_unlocked, Attachment* result) override {
    if (!caller_allowed()) return denied();
#ifndef ANDRIX_OWNER_KEEP
    (void)rows; (void)columns; (void)ui_eligible; (void)user_unlocked; (void)result;
    return bad_state("Keep is not enabled in this image");
#else
    if (!valid_dimensions(rows, columns) || !ui_eligible || !user_unlocked)
      return bad_state("start kept work only while foreground and unlocked");
    std::unique_lock guard(mutex_);
    if (!controller_matches()) return denied();
    if (stopping_ || starting_keep_) return bad_state("session is ending or being prepared");
    if (home_ >= 0 || terminal_.has_process()) return bad_state("End existing work before starting a new kept terminal");
    if (!lifecycle_ready_locked()) return bad_state("Android lifecycle observation unavailable");
    std::string error = check_resource_bounds();
    if (!error.empty()) return bad_state(error);
    unique_fd checked_home(open_ce_home(&error));
    if (checked_home < 0) return bad_state(error);
    const uint64_t controller_generation = controller_generation_;
    starting_keep_ = true;
    auto lifetime = work_lifetime_->asBinder();
    guard.unlock();
    const bool granted = platform_.retain(lifetime, work_id_);
    guard.lock();
    starting_keep_ = false;
    if (!granted || stopping_ || !controller_matches() ||
        controller_generation_ != controller_generation || !lifecycle_ready_locked()) {
      stopping_ = true; revoke_locked();
      return bad_state("Keep notification or platform grant unavailable");
    }
    // This compatibility entry selects two independent decisions: a confirmed
    // retention grant and a replaceable tmux presentation. Neither implies the
    // other in the process model; no new lifetime policy is exposed here.
    if (!terminal_.select_role(TerminalProcessRole::PresentationClient)) {
      stopping_ = true; revoke_locked();
      return bad_state("terminal role is already fixed for this work");
    }
    kept_ = true;
    auto status = attach_locked(rows, columns, ui_eligible, user_unlocked, 0, 0, result);
    if (!status.isOk()) { stopping_ = true; revoke_locked(); }
    return status;
#endif
  }

  ScopedAStatus stopKeptWork() override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    if (!controller_matches()) return denied();
    if (!kept_) return bad_state("not kept work");
    stopping_ = true; revoke_locked();
    return ScopedAStatus::ok();
  }

  ScopedAStatus attach_locked(int32_t rows, int32_t columns, bool ui_eligible,
                             bool user_unlocked, int64_t previous_session, int64_t next_output,
                             Attachment* result) {
    if (!controller_matches()) return denied();
    if (stopping_) return bad_state("session is ending");
    if (!lifecycle_ready_locked()) return bad_state("Android lifecycle observation unavailable");
    if (uint64_t(previous_session) == session_id_ &&
        uint64_t(next_output) > output_.delivered_end())
      return bad_state("output offset was never delivered");
    if (previous_session == 0 && next_output != 0)
      return bad_state("missing native session for output offset");
    if (terminal_.replaceable() && terminal_.has_process() &&
        (master_ < 0 || uint64_t(previous_session) != session_id_)) {
      revoke_locked();
      return bad_state("kept presentation is retiring; Attach again");
    }
    // Same live presentation may replace only its stream with the same parser
    // checkpoint. A retired/lost presentation always gets a fresh PTY and ID.
    revoke_stream_locked();
    const bool fresh_presentation = terminal_.replaceable() && !terminal_.has_process();
    if (!user_unlocked) {
      stopping_ = home_ >= 0;
      return bad_state("Android user is not unlocked");
    }
    std::string error;
    auto bounds = check_resource_bounds();
    if (!bounds.empty()) return bad_state(bounds);
    unique_fd home(open_ce_home(&error));
    if (home < 0 || !ui_eligible || !user_unlocked)
      return bad_state(error.empty() ? "console is locked or not foreground" : error);
    if (home_ >= 0) {
      struct stat previous{}, current{};
      if (fstat(home_, &previous) != 0 || fstat(home, &current) != 0 ||
          previous.st_dev != current.st_dev || previous.st_ino != current.st_ino) {
        stopping_ = true;
        return bad_state("home changed while session was running");
      }
    }
    int pair[2] = {-1, -1};
    if (setsockcreatecon("u:object_r:andrix_console_socket:s0") != 0)
      return bad_state("cannot label attachment stream");
    const int created = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair);
    // sockcreate state is thread-local; clear it even on socketpair failure.
    if (setsockcreatecon(nullptr) != 0) _exit(125);
    unique_fd server(pair[0]);
    ndk::ScopedFileDescriptor client(pair[1]);
    if (created != 0) return bad_state("cannot create attachment stream");
    if (fcntl(server, F_SETFL, O_NONBLOCK) != 0) return bad_state("nonblocking attachment setup");
    uint64_t generation = gate_.attach(now_ms(), true, true, true);
    if (!generation || generation > uint64_t(std::numeric_limits<int64_t>::max()))
      return bad_state("attachment generation exhausted");
    if (!terminal_.has_process()) {
      if (terminal_.replaceable()) {
        if (session_id_ == uint64_t{INT64_MAX}) { stopping_ = true; return bad_state("presentation ID exhausted"); }
        ++session_id_;
        output_.clear_for_new_presentation();
        output_cursor_ = 0;
      }
      if (!start_terminal_locked(rows, columns, home.release(), &error)) {
        gate_.revoke();
        return bad_state(error);
      }
    }
    // A replacement socket replays bytes until the controller confirms they were
    // parsed. A different daemon/session cannot inherit an old parser checkpoint.
    const bool same_presentation = !fresh_presentation && uint64_t(previous_session) == session_id_;
    const uint64_t resume = same_presentation ? uint64_t(next_output) : 0;
    if (same_presentation && !output_.acknowledge(resume)) _exit(125);
    output_cursor_ = std::max(resume, output_.begin());
    bridge_ = std::move(server);
    result->generation = generation;
    result->sessionId = session_id_;
    result->firstOutputOffset = output_cursor_;
    result->stream = std::move(client);
    result->kept = kept_;
    return ScopedAStatus::ok();
  }

  ScopedAStatus renew(int64_t generation, bool ui_eligible, bool user_unlocked,
                      bool* result) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    std::string error;
    if (!controller_matches()) return denied();
    const bool policy_ready = home_ >= 0 && ce_policy_valid(home_, &error);
    if (!user_unlocked) stopping_ = true;
    *result = generation > 0 && !stopping_ && lifecycle_ready_locked() &&
              gate_.renew(generation, now_ms(), ui_eligible,
                                                       user_unlocked && policy_ready);
    if (!gate_.live(now_ms())) revoke_locked();
    return ScopedAStatus::ok();
  }

  ScopedAStatus acknowledgeOutput(int64_t generation, int64_t next_output, bool* result) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    if (!controller_matches()) return denied();
    *result = false;
    if (generation <= 0 || uint64_t(generation) != gate_.generation() ||
        !gate_.live(now_ms()) || !lifecycle_ready_locked() || next_output < 0)
      return ScopedAStatus::ok();
    *result = output_.acknowledge(next_output);
    return ScopedAStatus::ok();
  }

  ScopedAStatus resize(int64_t generation, int32_t rows, int32_t columns) override {
    if (!caller_allowed()) return denied();
    if (!valid_dimensions(rows, columns))
      return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT, "invalid PTY dimensions");
    std::lock_guard guard(mutex_);
    if (!controller_matches()) return denied();
    if (generation <= 0 || uint64_t(generation) != gate_.generation() || !gate_.live(now_ms()) ||
        !lifecycle_ready_locked())
      return bad_state("attachment is no longer active");
    winsize size{static_cast<unsigned short>(rows), static_cast<unsigned short>(columns), 0, 0};
    if (ioctl(master_, TIOCSWINSZ, &size) != 0) return bad_state("PTY resize failed");
    return ScopedAStatus::ok();
  }

  ScopedAStatus detach(int64_t generation) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    if (!controller_matches()) return denied();
    if (generation > 0 && gate_.detach(generation)) revoke_locked();
    return ScopedAStatus::ok();
  }

  ScopedAStatus endSession(int64_t generation) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    if (!controller_matches()) return denied();
    if (generation <= 0 || uint64_t(generation) != gate_.generation() || !gate_.live(now_ms()))
      return bad_state("attachment is no longer active");
    revoke_locked();
    stopping_ = true;
    return ScopedAStatus::ok();
  }

  ScopedAStatus status(std::string* result) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    if (!controller_matches()) return denied();
    bool active = gate_.live(now_ms()) && lifecycle_ready_locked();
    if (!active) revoke_locked();
    *result = "uid=" + std::to_string(getuid()) + " child=" + std::to_string(terminal_.pid()) +
              " attached=" + (active ? "true" : "false") +
              " kept=" + (kept_ ? "true" : "false") +
              " output_buffered=" + std::to_string(output_.size()) +
              " output_dropped=" + std::to_string(output_.dropped()) +
              " output_ack=" + std::to_string(output_.acknowledged()) +
              " memory_limit=" + std::to_string(kMemoryLimit);
    return ScopedAStatus::ok();
  }

  [[noreturn]] void run() {
    uint64_t checked_at = 0;
    for (;;) {
      {
        std::lock_guard guard(mutex_);
        if (!gate_.live(now_ms())) revoke_locked();
#ifdef ANDRIX_OWNER_LIFECYCLE
        if (platform_.failed()) { stopping_ = true; revoke_locked(); }
#endif
        if (stopping_) {
          // The daemon never grants itself cgroup-control access or kills a guessed
          // process group. Exiting lets Android init kill/reap its entire owned
          // cgroup, including descendants which called setsid(). No auto shell restart.
          LOG(INFO) << "Ending owner session; init owns complete cgroup cleanup";
          _exit(0);
        }
        if (home_ >= 0 && now_ms() - checked_at >= 500) {
          std::string error;
          checked_at = now_ms();
          if (!ce_policy_valid(home_, &error)) {
            LOG(ERROR) << error;
            stopping_ = true;
            revoke_locked();
          }
        }
        int status = 0;
        pid_t reaped;
        do {
          reaped = waitpid(-1, &status, WNOHANG);
          if (reaped > 0 && terminal_exited_locked(reaped, WIFEXITED(status),
                                                   WIFEXITED(status) ? WEXITSTATUS(status) : 0))
            LOG(INFO) << "Owner presentation exited, wait status " << status;
        } while (reaped > 0);
        // A presentation client may exit while other owned work remains. An
        // empty subreaper scope still ends work, never silently creating a new
        // backend on reattachment. This is not a retained-work permission check.
        if (terminal_.replaceable() && home_ >= 0 && !starting_keep_ && reaped < 0 && errno == ECHILD)
          stopping_ = true;
        if (terminal_.retiring() && terminal_.retirement_expired(active_ms()))
          stopping_ = true; // Hung client: init ends this group, not an external PID/PGID kill.
        transfer_locked();
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

 private:
  bool lifecycle_ready_locked() {
#ifdef ANDRIX_OWNER_LIFECYCLE
    if (platform_.failed()) { stopping_ = true; revoke_locked(); return false; }
    return platform_.ready();
#else
    return true;
#endif
  }

  bool controller_matches() const {
    return controller_.get() && controller_generation_ != 0 &&
        controller_pid_ == AIBinder_getCallingPid() && AIBinder_isAlive(controller_.get());
  }

  void clear_controller_locked() {
    controller_.set(nullptr); controller_pid_ = 0; controller_generation_ = 0;
    controller_cookie_ = nullptr;
  }

  void controller_died(uint64_t registration) {
    std::lock_guard guard(mutex_);
    if (controller_generation_ != registration) return;
    clear_controller_locked();
    controller_lost_locked();
  }

  void controller_lost_locked() {
    // Consent and OS lifecycle are independent of Console only for explicit kept
    // work. Plain sessions preserve the original process-death cleanup.
    if (!kept_) stopping_ = true;
    revoke_locked();
  }

  void revoke_locked() {
    revoke_stream_locked();
    if (terminal_.replaceable() && master_ >= 0) {
      // Close this presentation's PTY, not the workload. The selected client
      // retires; other owned work keeps its own descriptors in the init cgroup.
      master_.reset();
      terminal_.retire(active_ms());
    }
  }

  void revoke_stream_locked() {
    gate_.revoke();
    if (bridge_ >= 0) shutdown(bridge_, SHUT_RDWR);
    bridge_.reset();
    input_.clear();
    frame_.clear();
    frame_sent_ = 0;
    frame_end_ = 0;
  }

  bool terminal_exited_locked(pid_t pid, bool exited, int exit_code) {
    const auto outcome = terminal_.reaped(pid, exited, exit_code);
    if (outcome == TerminalExit::NotTracked) return false;
    master_.reset();
    if (outcome == TerminalExit::EndWork) stopping_ = true;
    revoke_locked();
    return true;
  }

  bool start_terminal_locked(int rows, int columns, int home_fd, std::string* error) {
    unique_fd home(home_fd);
    unique_fd master(posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK));
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
      *error = "cannot allocate PTY";
      return false;
    }
    std::array<char, 128> name{};
    if (ptsname_r(master, name.data(), name.size()) != 0) {
      *error = "cannot locate PTY slave";
      return false;
    }
    unique_fd slave(open(name.data(), O_RDWR | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW));
    winsize size{static_cast<unsigned short>(rows), static_cast<unsigned short>(columns), 0, 0};
    if (slave < 0 || ioctl(master, TIOCSWINSZ, &size) != 0) {
      *error = "cannot prepare PTY slave";
      return false;
    }
    const pid_t parent = getpid();
    const int slave_fd = slave.get();
    char executable[] = "/system_ext/bin/andrix-session-runner";
    char new_mode[] = "--tmux-new", attach_mode[] = "--tmux-attach";
    std::string work = std::to_string(work_id_); // Construct before multithreaded fork.
    const bool client = terminal_.replaceable();
    char* arguments[] = {executable, client ? (terminal_.ever_started() ? attach_mode : new_mode) : nullptr,
                         client ? work.data() : nullptr, nullptr};
    // Runner will construct the shell environment after entering the owner domain.
    char path[] = "PATH=/system/bin";
    char* environment[] = {path, nullptr};
    pid_t child = fork();
    if (child == 0) {
      // Only async-signal-safe operations/syscalls until exec. No allocator, log,
      // mutex, Binder or C++ object destruction on this multithreaded fork path.
      if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent ||
          dup2(slave_fd, 0) < 0 || dup2(slave_fd, 1) < 0 || dup2(slave_fd, 2) < 0) _exit(125);
      for (int fd = 3; fd < static_cast<int>(kDescriptorLimit); ++fd) close(fd);
      execve(executable, arguments, environment);
      constexpr char message[] = "andrix runner exec failed\r\n";
      write(2, message, sizeof(message) - 1);
      _exit(127);
    }
    if (child < 0) {
      *error = "fork failed within owner process bound";
      return false;
    }
    home_ = std::move(home);
    master_ = std::move(master);
    if (!terminal_.started(child)) _exit(125); // Impossible bookkeeping drift ends the whole scope.
    return true;
  }

  void transfer_locked() {
    if (!lifecycle_ready_locked()) { revoke_locked(); return; }
    std::array<char, 4096> buffer{};
    if (master_ >= 0) {
      // One bounded read each turn; an output flood must not monopolize Binder or
      // prevent lease expiry. EIO is a normal PTY close; waitpid handles lifecycle.
      ssize_t n = read(master_, buffer.data(), buffer.size());
      if (n > 0 && !output_.append({buffer.data(), static_cast<size_t>(n)})) stopping_ = true;
      if (n < 0 && errno != EAGAIN && errno != EINTR && errno != EIO) stopping_ = true;
    }
    if (bridge_ < 0 || !gate_.live(now_ms())) {
      revoke_locked();
      return;
    }
    if (input_.size() < 4096) {
      ssize_t n = recv(bridge_, buffer.data(), 4096 - input_.size(), MSG_DONTWAIT);
      if (n > 0) input_.append(buffer.data(), n);
      if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
        revoke_locked();
        return;
      }
    }
    if (!input_.empty() && master_ >= 0 && gate_.live(now_ms())) {
      ssize_t n = write(master_, input_.data(), input_.size());
      if (n > 0) input_.erase(0, n);
      if (n < 0 && errno != EAGAIN && errno != EINTR) revoke_locked();
    }
    if (bridge_ >= 0) {
      if (frame_.empty()) {
        auto pending = output_.read(output_cursor_);
        if (!pending.valid) { stopping_ = true; revoke_locked(); return; }
        // A skipped prefix remains visible as an absolute offset jump. Never
        // silently reset/rebase the terminal parser after journal overflow.
        output_cursor_ = pending.offset;
        if (!pending.bytes.empty()) {
          frame_ = terminal::encode_frame(session_id_, pending.offset, pending.bytes);
          if (frame_.empty()) { stopping_ = true; revoke_locked(); return; }
          frame_end_ = pending.offset + pending.bytes.size();
          frame_sent_ = 0;
        }
      }
      if (!frame_.empty()) {
        ssize_t n = send(bridge_, frame_.data() + frame_sent_, frame_.size() - frame_sent_,
                         MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) {
          frame_sent_ += n;
          if (frame_sent_ == frame_.size()) {
            if (!output_.delivered(frame_end_)) _exit(125);
            output_cursor_ = frame_end_;
            frame_.clear();
            frame_sent_ = 0;
          }
        }
        if (n < 0 && errno != EAGAIN && errno != EINTR) revoke_locked();
      }
    }
  }

  std::mutex mutex_;
#ifdef ANDRIX_OWNER_LIFECYCLE
  PlatformLifecycle platform_;
#endif
  const uint64_t work_id_;
  uint64_t session_id_;
  AttachmentGate gate_;
  terminal::OutputJournal output_;
  uint64_t output_cursor_ = 0;
  std::string frame_;
  size_t frame_sent_ = 0;
  uint64_t frame_end_ = 0;
  std::string input_;
  unique_fd home_;
  unique_fd master_;
  unique_fd bridge_;
  TerminalProcessState terminal_;
  // Work policy/admission, deliberately separate from terminal process role.
  bool stopping_ = false, kept_ = false, starting_keep_ = false;
#ifdef ANDRIX_OWNER_KEEP
  std::shared_ptr<KeptWorkToken> work_lifetime_;
#endif
  ndk::SpAIBinder controller_;
  pid_t controller_pid_ = 0;
  uint64_t controller_sequence_ = 0, controller_generation_ = 0;
  ControllerCookie* controller_cookie_ = nullptr;
  std::atomic<unsigned> death_links_{0};
  AIBinder_DeathRecipient* death_; // process-lifetime recipient; per-link cookies retire via onUnlinked
};

}  // namespace
}  // namespace andrix

int main(int argc, char**) {
  android::base::InitLogging(nullptr, android::base::LogdLogger(android::base::SYSTEM));
  if (argc != 1) return 125;
  const auto identity = andrix::check_identity();
  if (!identity.empty()) {
    LOG(ERROR) << identity;
    return 125;
  }
  if (!android::base::SetProperty("sys.andrix.owner.pid", std::to_string(getpid())) ||
      !android::base::SetProperty("sys.andrix.owner.apply", "true")) {
    LOG(ERROR) << "Cannot request init-owned resource setup";
    return 125;
  }
  std::string bounds;
  const auto deadline = andrix::now_ms() + 20000;
  do {
    bounds = andrix::check_resource_bounds();
    if (bounds.empty()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  } while (andrix::now_ms() < deadline);
  if (!bounds.empty()) {
    LOG(ERROR) << "Refusing owner service without bounds: " << bounds;
    return 125;
  }
  if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) return 125;
  signal(SIGPIPE, SIG_IGN);
  auto service = ndk::SharedRefBase::make<andrix::OwnerSession>();
  auto binder = service->asBinder();
  AIBinder_setRequestingSid(binder.get(), true);
  ABinderProcess_setThreadPoolMaxThreadCount(2);
  ABinderProcess_startThreadPool();
  if (!service->start_lifecycle()) {
    LOG(ERROR) << "Android lifecycle service unavailable; no owner work admitted";
    return 125;
  }
  if (AServiceManager_addService(binder.get(), andrix::kServiceName.data()) != STATUS_OK) return 125;
  LOG(INFO) << "Bounded owner service ready; no session until authenticated foreground attachment";
  service->run();
}
