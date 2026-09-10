// SPDX-License-Identifier: Apache-2.0
#include "guards.h"
#include "session_core.h"

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
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <limits>
#include <mutex>
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
  return sid && authorized_console(AIBinder_getCallingUid(), sid);
}

ScopedAStatus denied() {
  return ScopedAStatus::fromExceptionCodeWithMessage(EX_SECURITY, "not the primary Andrix console");
}

ScopedAStatus bad_state(const std::string& text) {
  return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_STATE, text.c_str());
}

class OwnerSession final : public aidl::dev::andrix::session::BnOwnerSession {
 public:
  OwnerSession() : gate_(epoch_seed()) {}

  ScopedAStatus attach(int32_t rows, int32_t columns, bool ui_eligible,
                       bool user_unlocked, Attachment* result) override {
    if (!caller_allowed()) return denied();
    if (!valid_dimensions(rows, columns))
      return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT, "invalid PTY dimensions");
    std::lock_guard guard(mutex_);
    if (stopping_) return bad_state("session is ending");
    revoke_locked();
    std::string error;
    auto bounds = check_resource_bounds();
    if (!bounds.empty()) return bad_state(bounds);
    unique_fd home(open_ce_home(&error));
    if (home < 0 || !ui_eligible || !user_unlocked)
      return bad_state(error.empty() ? "console is locked or not foreground" : error);
    if (child_ == 0 && !start_shell_locked(rows, columns, home.release(), &error))
      return bad_state(error);
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
    bridge_ = std::move(server);
    result->generation = generation;
    result->stream = std::move(client);
    return ScopedAStatus::ok();
  }

  ScopedAStatus renew(int64_t generation, bool ui_eligible, bool user_unlocked,
                      bool* result) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    std::string error;
    const bool key_ready = home_ >= 0 && ce_key_present(home_, &error);
    *result = generation > 0 && gate_.renew(generation, now_ms(), ui_eligible,
                                           user_unlocked && key_ready);
    if (!gate_.live(now_ms())) revoke_locked();
    return ScopedAStatus::ok();
  }

  ScopedAStatus resize(int64_t generation, int32_t rows, int32_t columns) override {
    if (!caller_allowed()) return denied();
    if (!valid_dimensions(rows, columns))
      return ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT, "invalid PTY dimensions");
    std::lock_guard guard(mutex_);
    if (generation <= 0 || uint64_t(generation) != gate_.generation() || !gate_.live(now_ms()))
      return bad_state("attachment is no longer active");
    winsize size{static_cast<unsigned short>(rows), static_cast<unsigned short>(columns), 0, 0};
    if (ioctl(master_, TIOCSWINSZ, &size) != 0) return bad_state("PTY resize failed");
    return ScopedAStatus::ok();
  }

  ScopedAStatus detach(int64_t generation) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    if (generation > 0 && gate_.detach(generation)) revoke_locked();
    return ScopedAStatus::ok();
  }

  ScopedAStatus endSession(int64_t generation) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    if (generation <= 0 || uint64_t(generation) != gate_.generation() || !gate_.live(now_ms()))
      return bad_state("attachment is no longer active");
    revoke_locked();
    stopping_ = true;
    return ScopedAStatus::ok();
  }

  ScopedAStatus status(std::string* result) override {
    if (!caller_allowed()) return denied();
    std::lock_guard guard(mutex_);
    bool active = gate_.live(now_ms());
    if (!active) revoke_locked();
    *result = "uid=" + std::to_string(getuid()) + " child=" + std::to_string(child_) +
              " attached=" + (active ? "true" : "false") +
              " output_buffered=" + std::to_string(output_.size()) +
              " output_dropped=" + std::to_string(output_.dropped()) +
              " memory_limit=" + std::to_string(kMemoryLimit);
    return ScopedAStatus::ok();
  }

  [[noreturn]] void run() {
    uint64_t checked_at = 0;
    for (;;) {
      {
        std::lock_guard guard(mutex_);
        if (!gate_.live(now_ms())) revoke_locked();
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
          if (!ce_key_present(home_, &error)) {
            LOG(ERROR) << error;
            stopping_ = true;
            revoke_locked();
          }
        }
        int status = 0;
        pid_t reaped;
        do {
          reaped = waitpid(-1, &status, WNOHANG);
          if (reaped > 0 && reaped == child_) {
            LOG(INFO) << "Owner shell exited, wait status " << status;
            child_ = 0;
            stopping_ = true;
            revoke_locked();
          }
        } while (reaped > 0);
        transfer_locked();
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

 private:
  void revoke_locked() {
    gate_.revoke();
    if (bridge_ >= 0) shutdown(bridge_, SHUT_RDWR);
    bridge_.reset();
    input_.clear();
  }

  bool start_shell_locked(int rows, int columns, int home_fd, std::string* error) {
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
    char* arguments[] = {executable, nullptr};
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
    child_ = child;
    return true;
  }

  void transfer_locked() {
    std::array<char, 4096> buffer{};
    if (master_ >= 0) {
      // One bounded read each turn; an output flood must not monopolize Binder or
      // prevent lease expiry. EIO is a normal PTY close; waitpid handles lifecycle.
      ssize_t n = read(master_, buffer.data(), buffer.size());
      if (n > 0) output_.append({buffer.data(), static_cast<size_t>(n)});
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
    if (bridge_ >= 0 && output_.size() != 0) {
      std::string bytes = output_.peek(4096);
      ssize_t n = send(bridge_, bytes.data(), bytes.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
      if (n > 0) output_.consume(n);
      if (n < 0 && errno != EAGAIN && errno != EINTR) revoke_locked();
    }
  }

  std::mutex mutex_;
  AttachmentGate gate_;
  OutputTail output_;
  std::string input_;
  unique_fd home_;
  unique_fd master_;
  unique_fd bridge_;
  pid_t child_ = 0;
  bool stopping_ = false;
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
  if (AServiceManager_addService(binder.get(), andrix::kServiceName.data()) != STATUS_OK) return 125;
  LOG(INFO) << "Bounded owner service ready; no session until authenticated foreground attachment";
  service->run();
}
