// SPDX-License-Identifier: Apache-2.0
// Fixed ordinary-principal staging entry. The platform must already have
// specialized a protected manager at the principal UID. No UID/group mutation,
// root launch API or caller-selected credentials are exposed here.
#include <android-base/unique_fd.h>
#include <android/log.h>
#include <fcntl.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <string>
#include <string_view>

#include "launch_description.h"
#include "principal_credentials.h"
#include "principal_profile.h"
#include "session_core.h"
#include "work_admission.h"
#include "work_launch_protocol.h"
#include "work_profile.h"
#include "worker_filter.h"

namespace {
using android::base::unique_fd;
using namespace andrix;
WorkLaunchPacket identity;
bool bound = false;
[[noreturn]] void fail(const char* reason, int error = EINVAL) {
  if (!error) error = EINVAL;
  // Staging stdio is deliberately null. Preserve the exact failed guard in
  // Android's existing coordinator log channel; no caller environment is
  // logged.
  __android_log_print(ANDROID_LOG_ERROR, "AndrixPrincipalStage", "%s (%d)", reason,
                      error);
  dprintf(2, "andrix principal staging refused: %s (%d)\n", reason, error);
  if (bound) {
    auto packet = identity;
    packet.operation = WorkLaunchOperation::Failed;
    packet.error = error;
    SendWorkLaunch(3, packet);
  }
  _exit(126);
}
uint64_t now() {
  timespec value{};
  if (clock_gettime(CLOCK_MONOTONIC, &value)) fail("monotonic clock", errno);
  return uint64_t(value.tv_sec) * 1000 + uint64_t(value.tv_nsec) / 1000000;
}
void receive(LaunchPeer peer, WorkLaunchMessage& message) {
  const uint64_t until = now() + 30000;
  for (;;) {
    int error = ReceiveWorkLaunch(3, peer, message);
    if (!error) return;
    if (error != EAGAIN && error != EINTR)
      fail("private launch message", error);
    if (now() >= until) fail("private launch deadline", ETIMEDOUT);
    pollfd wait{3, POLLIN, 0};
    int ready = poll(&wait, 1, 100);
    if (ready < 0 && errno != EINTR) fail("private launch poll", errno);
  }
}
bool same(const WorkLaunchPacket& a, const WorkLaunchPacket& b) {
  return a.work == b.work && a.epoch == b.epoch && a.aggregate == b.aggregate &&
         a.scope == b.scope && a.stdio_closed == b.stdio_closed &&
         a.principal_profile == b.principal_profile;
}
bool alias(int a, int b) {
  struct stat first{}, second{};
  if (fstat(a, &first) || fstat(b, &second)) fail("descriptor identity", errno);
  return first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}
}  // namespace
int main(int argc, char**) {
  using namespace andrix;
  if (argc != 1 || getppid() <= 1 || !ManagementDescriptorsClosed(3))
    fail("fixed bootstrap descriptor set");
  for (int fd = 0; fd <= 3; ++fd)
    if (fcntl(fd, F_GETFD) < 0) fail("missing declared bootstrap descriptor");
  if (ConfigureWorkLaunchSocket(3)) fail("credential channel");
  const pid_t parent = getppid();
  unique_fd parent_identity(
      static_cast<int>(syscall(SYS_pidfd_open, parent, 0)));
  if (parent_identity < 0 || getppid() != parent)
    fail("coordinator identity", errno);
  ucred creator{};
  socklen_t size = sizeof(creator);
  char* sid = nullptr;
  if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &creator, &size) ||
      size != sizeof(creator) || creator.pid != parent ||
      creator.uid != getuid() || creator.gid != getgid() ||
      getpeercon(3, &sid) || !sid)
    fail("coordinator endpoint identity");
  const std::string coordinator_context(sid);
  freecon(sid);
  WorkLaunchMessage request;
  receive({parent, getuid(), getgid()}, request);
  if (request.packet.operation != WorkLaunchOperation::Prepare ||
      request.count != ExpectedWorkLaunchFdCount(request.packet) ||
      request.packet.principal_profile != 1)
    fail("complete principal launch handoff");
  identity = request.packet;
  bound = true;
  PrincipalProfile principal;
  int profile_error = 0;
  if (!ReadPrincipalLaunch(request.descriptors[static_cast<size_t>(LaunchFd::Principal)],
                           identity.work, identity.epoch, principal, profile_error))
    fail("bound principal profile", profile_error);
  if (coordinator_context != PrincipalManagerContext(principal))
    fail("coordinator endpoint role");
  auto credential_error = CheckPrincipalCredentials(principal, PrincipalStage::Manager);
  if (!credential_error.empty()) fail(credential_error.c_str());
  auto home_error = CheckPrincipalHome(
      request.descriptors[static_cast<size_t>(LaunchFd::Home)], principal);
  if (!home_error.empty()) fail(home_error.c_str());
  for (size_t stream = static_cast<size_t>(LaunchFd::Input);
       stream <= static_cast<size_t>(LaunchFd::Error); ++stream) {
    if (identity.stdio_closed &
        (1U << (stream - static_cast<size_t>(LaunchFd::Input))))
      continue;
    for (size_t management = 0; management < kLaunchFdCount; ++management) {
      if (management >= static_cast<size_t>(LaunchFd::Input) &&
          management <= static_cast<size_t>(LaunchFd::Error)) continue;
      if (alias(request.descriptors[stream], request.descriptors[management]))
        fail("stream aliases management or profile object");
    }
    if (alias(request.descriptors[stream], 3) ||
        alias(request.descriptors[stream], parent_identity.get()))
      fail("stream aliases control handle");
    int flags = fcntl(request.descriptors[stream], F_GETFL);
    if (flags < 0 || (flags & O_PATH) ||
        (stream == static_cast<size_t>(LaunchFd::Input)
             ? (flags & O_ACCMODE) == O_WRONLY
             : (flags & O_ACCMODE) == O_RDONLY))
      fail("stream access mode");
  }
  if (setpriority(PRIO_PROCESS, 0, 10) || setsid() < 0)
    fail("staging scheduling/session", errno);
  auto profile = CheckCapturedWorkScope(
      request.descriptors[static_cast<size_t>(LaunchFd::Aggregate)],
      request.descriptors[static_cast<size_t>(LaunchFd::Scope)],
      identity.aggregate, identity.scope);
  if (!profile.empty()) fail(profile.c_str());
  profile = CheckWorkLimits();
  if (!profile.empty()) fail(profile.c_str());
  LaunchDescription description;
  LaunchFailure description_error;
  const int description_mode = fcntl(
      request.descriptors[static_cast<size_t>(LaunchFd::Description)], F_GETFL);
  if (description_mode < 0 || (description_mode & O_ACCMODE) != O_RDONLY ||
      (description_mode & O_PATH))
    fail("read-only ordinary launch descriptor");
  if (!ReadLaunch(
          request.descriptors[static_cast<size_t>(LaunchFd::Description)], {},
          description, description_error))
    fail("immutable ordinary launch data", description_error.error);
  int error = 0;
  auto gate = WorkAdmission::Adopt(request.Take(LaunchFd::Gate), identity.work,
                                   identity.epoch, error);
  if (!gate) fail("original admission gate", error);
  // Only this ordinary role is selected by PrincipalManagerContext above.
  // Actual MAC authorization remains platform policy, not these label bytes.
  if (setexeccon(principal.selinux_context.c_str()) || !install_principal_filter() ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
    fail("principal restrictions before transition");
  auto staged = identity;
  staged.operation = WorkLaunchOperation::Staged;
  if (SendWorkLaunch(3, staged)) fail("staging reply");
  WorkLaunchMessage wake;
  receive({parent, getuid(), getgid()}, wake);
  if (wake.packet.operation != WorkLaunchOperation::Wake ||
      !same(wake.packet, identity) || wake.count)
    fail("exact launch wake");
  pollfd parent_wait{parent_identity.get(), POLLIN, 0};
  if (poll(&parent_wait, 1, 0) != 0) fail("coordinator ended");
  if (gate->ClaimEntry(identity.work, identity.epoch, now()) !=
      EntryResult::Entered)
    fail("admission closed before entry", ECANCELED);
  // No owner environment, path evaluation or executable selection has run yet.
  gate.reset();
  parent_identity.reset();
  // Duplicate data roles first so installing the fixed entry descriptor layout
  // cannot overwrite another retained source FD. No management capability may
  // survive the MAC transition.
  unique_fd description_fd(fcntl(request.descriptors[static_cast<size_t>(LaunchFd::Description)],
                                  F_DUPFD_CLOEXEC, 64));
  unique_fd principal_fd(fcntl(request.descriptors[static_cast<size_t>(LaunchFd::Principal)],
                                F_DUPFD_CLOEXEC, 64));
  unique_fd home_fd(fcntl(request.descriptors[static_cast<size_t>(LaunchFd::Home)],
                           F_DUPFD_CLOEXEC, 64));
  if (description_fd < 0 || principal_fd < 0 || home_fd < 0) _exit(126);
  for (int stream = 0; stream < 3; ++stream) {
    if (identity.stdio_closed & (1U << stream)) {
      if (close(stream)) _exit(126);
    } else if (dup2(request.descriptors[static_cast<size_t>(LaunchFd::Input) + stream],
                    stream) != stream) _exit(126);
  }
  if (dup2(description_fd.get(), 3) != 3 || dup2(principal_fd.get(), 4) != 4 ||
      dup2(home_fd.get(), 5) != 5 || syscall(SYS_close_range, 6, ~0U, 0)) _exit(126);
  char entry[] = "/system_ext/bin/andrix-principal-entry";
  std::string closed = std::to_string(identity.stdio_closed);
  std::string manager = std::to_string(identity.work.manager);
  std::string serial = std::to_string(identity.work.serial);
  std::string platform = std::to_string(identity.epoch.platform);
  std::string generation = std::to_string(identity.epoch.generation);
  std::string user = std::to_string(identity.epoch.user);
  char* arguments[] = {entry, closed.data(), manager.data(), serial.data(),
                       platform.data(), generation.data(), user.data(), nullptr};
  char* environment[] = {nullptr};
  execve(entry, arguments, environment);
  _exit(126);
}
