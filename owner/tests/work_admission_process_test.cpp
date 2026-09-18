// SPDX-License-Identifier: Apache-2.0
// Real separate processes and transferred gate FDs. No Android authority/MAC
// claim.
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "work_admission.h"

using namespace andrix;
namespace {
uint64_t now() {
  timespec value{};
  assert(!clock_gettime(CLOCK_MONOTONIC, &value));
  return uint64_t(value.tv_sec) * 1000 + uint64_t(value.tv_nsec) / 1000000;
}
struct Packet {
  uint64_t magic = 0x4144575049504331ULL;
  WorkIdentity work{};
  AuthorityEpoch epoch{};
  uint32_t command = 0;
  EntryResult entry = EntryResult::NotReleased;
};
void configure(int fd) {
  int yes = 1;
  assert(!setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &yes, sizeof(yes)));
}
void send_packet(int fd, const Packet& packet, int descriptor = -1) {
  iovec data{const_cast<Packet*>(&packet), sizeof(packet)};
  alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &data;
  message.msg_iovlen = 1;
  if (descriptor >= 0) {
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  }
  assert(sendmsg(fd, &message, MSG_NOSIGNAL) ==
         static_cast<ssize_t>(sizeof(packet)));
}
Packet receive(int fd, pid_t expected, int* received_fd = nullptr) {
  pollfd wait{fd, POLLIN, 0};
  assert(poll(&wait, 1, 5000) == 1);
  Packet packet{};
  iovec data{&packet, sizeof(packet)};
  alignas(cmsghdr) char
      control[CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &data;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  assert(recvmsg(fd, &message, MSG_CMSG_CLOEXEC) ==
         static_cast<ssize_t>(sizeof(packet)));
  assert(!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
         packet.magic == 0x4144575049504331ULL);
  bool credentials = false, rights = false;
  for (auto* header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    assert(header->cmsg_level == SOL_SOCKET);
    if (header->cmsg_type == SCM_CREDENTIALS) {
      assert(!credentials && header->cmsg_len == CMSG_LEN(sizeof(ucred)));
      ucred actual;
      memcpy(&actual, CMSG_DATA(header), sizeof(actual));
      assert(actual.pid == expected && actual.uid == getuid() &&
             actual.gid == getgid());
      credentials = true;
    } else {
      assert(header->cmsg_type == SCM_RIGHTS && received_fd && !rights &&
             header->cmsg_len == CMSG_LEN(sizeof(int)));
      memcpy(received_fd, CMSG_DATA(header), sizeof(int));
      rights = true;
    }
  }
  assert(credentials && rights == (received_fd != nullptr));
  return packet;
}
int launcher(pid_t parent) {
  assert(getppid() == parent);
  configure(3);
  int fd = -1;
  Packet request = receive(3, parent, &fd);
  assert(request.command == 1 && fd >= 0);
  int error = 0;
  auto gate = WorkAdmission::Adopt(fd, request.work, request.epoch, error);
  assert(gate && !error);
  request.command = 2;
  send_packet(3, request);
  auto wake = receive(3, parent);
  assert(wake.command == 3 && wake.work == request.work &&
         wake.epoch == request.epoch);
  request.command = 4;
  request.entry = gate->ClaimEntry(request.work, request.epoch, now());
  send_packet(3, request);
  auto end = receive(3, parent);
  assert(end.command == 5 || end.command == 6);
  if (end.command == 6) {
    // Gate closure is not physical termination or cleanup. Confirm this live
    // trusted process can still answer, then the test supervisor kills/reaps
    // it.
    send_packet(3, end);
    for (;;) pause();
  }
  return 0;
}
class Child {
 public:
  explicit Child(const Packet& request,
                 const std::shared_ptr<WorkAdmission>& gate) {
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair));
    configure(pair[0]);
    configure(pair[1]);
    const std::string parent = std::to_string(getpid());
    const char* arguments[] = {"work-admission-process", "--launcher",
                               parent.c_str(), nullptr};
    char* environment[] = {nullptr};
    pid_ = fork();
    assert(pid_ >= 0);
    if (!pid_) {
      close(pair[0]);
      assert(dup2(pair[1], 3) == 3);
      assert(fcntl(3, F_SETFD, 0) == 0);
      assert(syscall(SYS_close_range, 4, ~0U, 0) == 0);
      execve("/proc/self/exe", const_cast<char* const*>(arguments),
             environment);
      _exit(127);
    }
    close(pair[1]);
    socket_ = pair[0];
    pidfd_ = static_cast<int>(syscall(SYS_pidfd_open, pid_, 0));
    assert(pidfd_ >= 0);
    int error = 0;
    int descriptor = gate->Export(error);
    assert(descriptor >= 0 && !error);
    send_packet(socket_, request, descriptor);
    close(descriptor);
    assert(receive(socket_, pid_).command == 2);
  }
  ~Child() {
    if (pid_ > 0) {
      syscall(SYS_pidfd_send_signal, pidfd_, SIGKILL, nullptr, 0);
      int status;
      while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
      }
    }
    close(pidfd_);
    close(socket_);
  }
  void stop() {
    assert(!syscall(SYS_pidfd_send_signal, pidfd_, SIGSTOP, nullptr, 0));
    int status = 0;
    assert(waitpid(pid_, &status, WUNTRACED) == pid_ && WIFSTOPPED(status));
  }
  void resume() {
    assert(!syscall(SYS_pidfd_send_signal, pidfd_, SIGCONT, nullptr, 0));
  }
  void send(Packet packet, uint32_t command) {
    packet.command = command;
    send_packet(socket_, packet);
  }
  Packet read() { return receive(socket_, pid_); }
  bool dead() {
    pollfd wait{pidfd_, POLLIN, 0};
    return poll(&wait, 1, 0) == 1;
  }
  void finish(bool killed = false) {
    if (killed)
      assert(!syscall(SYS_pidfd_send_signal, pidfd_, SIGKILL, nullptr, 0));
    pollfd wait{pidfd_, POLLIN, 0};
    assert(poll(&wait, 1, 5000) == 1);
    int status = 0;
    assert(waitpid(pid_, &status, 0) == pid_);
    assert(killed ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL
                  : WIFEXITED(status) && WEXITSTATUS(status) == 0);
    pid_ = 0;
  }

 private:
  pid_t pid_ = 0;
  int pidfd_ = -1, socket_ = -1;
};
std::shared_ptr<WorkAdmission> make(AdmissionAuthority& authority,
                                    Packet& packet) {
  int error = 0;
  auto gate = WorkAdmission::Reserve(packet.work, error);
  assert(gate && !error);
  const uint64_t observed = now();
  assert(authority.Observe(packet.epoch, observed + 2000, observed) ==
         AdmissionResult::Accepted);
  assert(authority.Admit(gate, now()) == AdmissionResult::Accepted);
  return gate;
}
}  // namespace
int main(int argc, char** argv) {
  if (argc == 3 && !strcmp(argv[1], "--launcher"))
    return launcher(static_cast<pid_t>(std::strtol(argv[2], nullptr, 10)));
  assert(argc == 1);
  alarm(30);
  {
    AdmissionAuthority authority;
    Packet packet;
    packet.work = {91, 1};
    packet.epoch = {11, 7, 0};
    packet.command = 1;
    auto gate = make(authority, packet);
    Child child(packet, gate);
    child.stop();
    assert(authority.Prepared(gate, now()) == AdmissionResult::Accepted);
    assert(authority.Release(gate, now()) == AdmissionResult::Accepted);
    child.send(packet,
               3);  // Real queued wake while launcher cannot consume it.
    assert(gate->Stop());
    Packet other = packet;
    other.work.serial = 2;
    auto independent = make(authority, other);
    assert(authority.Prepared(independent, now()) == AdmissionResult::Accepted);
    assert(authority.Release(independent, now()) == AdmissionResult::Accepted);
    assert(independent->ClaimEntry(other.work, other.epoch, now()) ==
           EntryResult::Entered);
    child.resume();
    assert(child.read().entry == EntryResult::Stopped && !gate->entered());
    child.send(packet, 5);
    child.finish();
  }
  {
    AdmissionAuthority authority;
    Packet packet;
    packet.work = {91, 6};
    packet.epoch = {11, 7, 0};
    packet.command = 1;
    auto gate = make(authority, packet);
    Child child(packet, gate);
    child.stop();
    assert(authority.Prepared(gate, now()) == AdmissionResult::Accepted);
    assert(authority.Release(gate, now()) == AdmissionResult::Accepted);
    child.send(packet, 3);
    // The observer/parent does not run an expiry check during this delay. The
    // launcher must reject the original issue-time grant on its own wake.
    usleep(2100000);
    child.resume();
    assert(child.read().entry == EntryResult::Expired);
    assert(gate->phase() == AdmissionPhase::Stopped && !gate->entered());
    child.send(packet, 5);
    child.finish();
  }
  {
    AdmissionAuthority authority;
    Packet packet;
    packet.work = {91, 3};
    packet.epoch = {11, 7, 0};
    packet.command = 1;
    auto gate = make(authority, packet);
    Child child(packet, gate);
    assert(authority.Prepared(gate, now()) == AdmissionResult::Accepted);
    assert(authority.Release(gate, now()) == AdmissionResult::Accepted);
    child.send(packet, 3);
    assert(child.read().entry == EntryResult::Entered && gate->entered());
    gate->Stop();
    assert(!child.dead());
    child.send(packet, 6);
    assert(child.read().command == 6);
    child.finish(true);
  }
  {
    AdmissionAuthority old;
    Packet packet;
    packet.work = {91, 4};
    packet.epoch = {11, 7, 0};
    packet.command = 1;
    auto gate = make(old, packet);
    old.Revoke();
    AdmissionAuthority current;
    Packet next = packet;
    next.work.serial = 5;
    next.epoch.generation = 8;
    auto new_gate = make(current, next);
    assert(current.Release(gate, now()) == AdmissionResult::Foreign);
    Child late(packet, gate);
    late.send(packet, 3);
    assert(late.read().entry == EntryResult::Stopped);
    late.send(packet, 5);
    late.finish();
    assert(current.Prepared(new_gate, now()) == AdmissionResult::Accepted);
    assert(current.Release(new_gate, now()) == AdmissionResult::Accepted);
    assert(new_gate->ClaimEntry(next.work, next.epoch, now()) ==
           EntryResult::Entered);
  }
  puts(
      "{\"expired_queued_wake_denied_without_parent_progress\":true,\"queued_"
      "wake_after_Stop_denied\":true,\"independent_gate_progress\":true,"
      "\"entry_before_Stop_distinct_from_cleanup\":true,\"late_helper_old_"
      "epoch_denied\":true,\"new_explicit_epoch_request_accepted\":true,"
      "\"Android_authority_or_exec_profile_qualified\":false}");
}
