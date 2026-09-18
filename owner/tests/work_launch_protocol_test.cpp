// SPDX-License-Identifier: Apache-2.0
#include "work_launch_protocol.h"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstring>

using namespace andrix;
namespace {
size_t descriptors() {
  DIR* dir = opendir("/proc/self/fd");
  assert(dir);
  size_t count = 0;
  while (auto* entry = readdir(dir))
    if (entry->d_name[0] != '.') ++count;
  closedir(dir);
  return count;
}
}  // namespace
int main() {
  int pair[2];
  assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair));
  assert(!ConfigureWorkLaunchSocket(pair[0]) &&
         !ConfigureWorkLaunchSocket(pair[1]));
  LaunchPeer peer{getpid(), getuid(), getgid()};
  WorkLaunchPacket request;
  request.work = {11, 1};
  request.epoch = {91, 8, 0};
  request.aggregate = {7, 10};
  request.scope = {7, 11};
  int file = open("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(file >= 0);
  int rights[kLaunchFdCount];
  for (int& fd : rights) fd = file;
  assert(!SendWorkLaunch(pair[0], request, rights, kLaunchFdCount));
  WorkLaunchMessage result;
  assert(!ReceiveWorkLaunch(pair[1], peer, result) &&
         result.count == kLaunchFdCount);
  for (int fd : result.descriptors)
    assert(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
  request.operation = WorkLaunchOperation::Wake;
  assert(!SendWorkLaunch(pair[0], request));
  assert(!ReceiveWorkLaunch(pair[1], peer, result) && !result.count);
  const size_t baseline = descriptors();
  assert(!SendWorkLaunch(pair[0], request, rights, kLaunchFdCount));
  assert(ReceiveWorkLaunch(pair[1], peer, result) == EPROTO &&
         result.count == 0 && descriptors() == baseline);
  request.operation = WorkLaunchOperation::Prepare;
  assert(!SendWorkLaunch(pair[0], request, rights, kLaunchFdCount));
  assert(ReceiveWorkLaunch(pair[1], {getpid() + 1, getuid(), getgid()},
                           result) != 0 &&
         !result.count && descriptors() == baseline);
  request.magic = 0;
  assert(!SendWorkLaunch(pair[0], request, rights, kLaunchFdCount));
  assert(ReceiveWorkLaunch(pair[1], peer, result) == EPROTO && !result.count &&
         descriptors() == baseline);
  // Kernel SCM_RIGHTS can accompany a zero-byte seqpacket. Refusal still owns
  // and closes every received descriptor rather than treating it as empty EOF.
  alignas(cmsghdr) char control[CMSG_SPACE(sizeof(rights))]{};
  msghdr message{};
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  auto* header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(rights));
  memcpy(CMSG_DATA(header), rights, sizeof(rights));
  assert(sendmsg(pair[0], &message, MSG_NOSIGNAL) == 0);
  assert(ReceiveWorkLaunch(pair[1], peer, result) == ECONNRESET &&
         !result.count && descriptors() == baseline);
  request.magic = 0x414e44584c41554eULL;
  request.operation = WorkLaunchOperation::Staged;
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    close(pair[0]);
    _exit(SendWorkLaunch(pair[1], request) ? 1 : 0);
  }
  close(pair[1]);
  pollfd wait{pair[0], POLLIN, 0};
  assert(poll(&wait, 1, 5000) == 1);
  assert(!ReceiveWorkLaunch(pair[0], {child, getuid(), getgid()}, result));
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  close(pair[0]);
  close(file);
}
