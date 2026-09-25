// SPDX-License-Identifier: Apache-2.0
#include "work_launch_protocol.h"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <bit>
#include <cassert>
#include <cerrno>
#include <cstring>

using namespace andrix;
namespace {
using Roles = std::array<int, kLaunchFdCount>;
constexpr size_t kFirstStandard = static_cast<size_t>(LaunchFd::Input);
constexpr size_t kExtraRights = kLaunchFdCount + 16;
size_t descriptors() {
  DIR* dir = opendir("/proc/self/fd");
  assert(dir);
  size_t count = 0;
  while (auto* entry = readdir(dir))
    if (entry->d_name[0] != '.') ++count;
  closedir(dir);
  return count;
}
void empty(const WorkLaunchMessage& message) {
  assert(message.count == 0);
  for (int fd : message.descriptors) assert(fd == -1);
}
void same_object(int received, int original) {
  assert(received >= 0);
  int flags = fcntl(received, F_GETFD);
  assert(flags >= 0 && (flags & FD_CLOEXEC));
  struct stat first{}, second{};
  assert(!fstat(received, &first) && !fstat(original, &second));
  assert(first.st_dev == second.st_dev && first.st_ino == second.st_ino);
}
// Bypass sender validation to exercise hostile wire framing and FD ownership.
void raw_send(int socket, const void* bytes, size_t size,
              const int* rights = nullptr, size_t count = 0) {
  assert(count <= kExtraRights);
  iovec body{const_cast<void*>(bytes), size};
  alignas(cmsghdr) char control[CMSG_SPACE(kExtraRights * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &body;
  message.msg_iovlen = 1;
  if (count) {
    message.msg_control = control;
    message.msg_controllen = CMSG_SPACE(count * sizeof(int));
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(header), rights, count * sizeof(int));
  }
  assert(sendmsg(socket, &message, MSG_DONTWAIT | MSG_NOSIGNAL) ==
         static_cast<ssize_t>(size));
}
WorkLaunchPacket request_packet() {
  WorkLaunchPacket request;
  assert(request.version == 3 && request.stdio_closed == 0);
  request.principal_profile = 1;
  request.work = {11, 1};
  request.epoch = {91, 8, 0};
  request.aggregate = {7, 10};
  request.scope = {7, 11};
  return request;
}
Roles fixed_roles(const Roles& originals, uint32_t mask) {
  auto result = originals;
  for (size_t standard = 0; standard < 3; ++standard)
    if (mask & (1U << standard)) result[kFirstStandard + standard] = -1;
  return result;
}
void masks(int sender, int receiver, LaunchPeer peer, const Roles& originals) {
  const size_t baseline = descriptors();
  for (uint32_t mask = 0; mask < 8; ++mask) {
    auto request = request_packet();
    request.stdio_closed = mask;
    const auto roles = fixed_roles(originals, mask);
    Roles compact{};
    size_t count = 0;
    for (int fd : roles)
      if (fd >= 0) compact[count++] = fd;
    assert(ExpectedWorkLaunchFdCount(request) == count);
    if (mask == 0) assert(count == 9);
    if (mask == 7) assert(count == 6);
    // Check both the actual sender and independently constructed compact wire
    // order. Receiver roles must retain identity even with holes in stdio.
    for (bool raw : {false, true}) {
      if (raw)
        raw_send(sender, &request, sizeof(request), compact.data(), count);
      else
        assert(!SendWorkLaunch(sender, request, roles.data(), roles.size()));
      WorkLaunchMessage result;
      assert(!ReceiveWorkLaunch(receiver, peer, result));
      assert(result.count == count && result.packet.stdio_closed == mask &&
             result.packet.version == 3 && result.packet.work == request.work &&
             result.packet.epoch == request.epoch &&
             result.packet.aggregate == request.aggregate &&
             result.packet.scope == request.scope);
      for (size_t role = 0; role < kLaunchFdCount; ++role) {
        if (roles[role] == -1)
          assert(result.descriptors[role] == -1);
        else
          same_object(result.descriptors[role], roles[role]);
      }
      assert(descriptors() == baseline + count);
      // Reusing a receipt closes even sparse standard roles on EAGAIN.
      const auto owned = result.descriptors;
      assert(ReceiveWorkLaunch(receiver, peer, result) == EAGAIN);
      empty(result);
      assert(descriptors() == baseline);
      for (int fd : owned)
        if (fd >= 0) assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    }
    for (auto operation :
         {WorkLaunchOperation::Staged, WorkLaunchOperation::Wake,
          WorkLaunchOperation::Failed}) {
      auto reply = request;
      reply.operation = operation;
      if (operation == WorkLaunchOperation::Failed) reply.error = ECANCELED;
      assert(ExpectedWorkLaunchFdCount(reply) == 0);
      assert(!SendWorkLaunch(sender, reply));
      WorkLaunchMessage result;
      assert(!ReceiveWorkLaunch(receiver, peer, result));
      empty(result);
      assert(result.packet.stdio_closed == mask &&
             result.packet.operation == operation &&
             result.packet.error == reply.error);
    }
  }
  assert(descriptors() == baseline);
  // Take uses a fixed role, not its compact position, and transfers ownership.
  int taken = -1;
  {
    auto request = request_packet();
    request.stdio_closed = 1;
    auto roles = fixed_roles(originals, request.stdio_closed);
    assert(!SendWorkLaunch(sender, request, roles.data(), roles.size()));
    WorkLaunchMessage result;
    assert(!ReceiveWorkLaunch(receiver, peer, result));
    assert(result.Take(LaunchFd::Input) == -1);
    taken = result.Take(LaunchFd::Error);
    same_object(taken, originals[static_cast<size_t>(LaunchFd::Error)]);
    assert(result.descriptors[static_cast<size_t>(LaunchFd::Error)] == -1 &&
           result.count == 8);
  }
  assert(descriptors() == baseline + 1);
  assert(!close(taken) && descriptors() == baseline);
}
void legacy_profile(int sender, int receiver, LaunchPeer peer, const Roles& originals) {
  const size_t baseline = descriptors();
  for (uint32_t mask = 0; mask < 8; ++mask) {
    auto request = request_packet();
    request.principal_profile = 0;
    request.stdio_closed = mask;
    auto roles = fixed_roles(originals, mask);
    roles[static_cast<size_t>(LaunchFd::Principal)] = -1;
    roles[static_cast<size_t>(LaunchFd::Home)] = -1;
    assert(ExpectedWorkLaunchFdCount(request) == size_t(7 - std::popcount(mask)));
    assert(!SendWorkLaunch(sender, request, roles.data(), roles.size()));
    {
      WorkLaunchMessage result;
      assert(!ReceiveWorkLaunch(receiver, peer, result));
      assert(result.packet.principal_profile == 0);
      assert(result.descriptors[static_cast<size_t>(LaunchFd::Principal)] == -1);
      assert(result.descriptors[static_cast<size_t>(LaunchFd::Home)] == -1);
      for (size_t role = 0; role < kLaunchFdCount; ++role)
        if (roles[role] >= 0) same_object(result.descriptors[role], roles[role]);
    }
    assert(descriptors() == baseline);
    for (auto role : {LaunchFd::Principal, LaunchFd::Home}) {
      auto bad = roles;
      bad[static_cast<size_t>(role)] = originals[static_cast<size_t>(role)];
      assert(SendWorkLaunch(sender, request, bad.data(), bad.size()) == EINVAL);
    }
    request.principal_profile = 1;
    assert(SendWorkLaunch(sender, request, roles.data(), roles.size()) == EINVAL);
  }
}
void sender_roles(int sender, int receiver, LaunchPeer peer,
                  const Roles& originals) {
  const size_t baseline = descriptors();
  for (uint32_t mask = 0; mask < 8; ++mask) {
    auto request = request_packet();
    request.stdio_closed = mask;
    const auto roles = fixed_roles(originals, mask);
    for (size_t count : {size_t(0), kLaunchFdCount - 1, kLaunchFdCount + 1})
      assert(SendWorkLaunch(sender, request, roles.data(), count) == EINVAL);
    assert(SendWorkLaunch(sender, request, nullptr, kLaunchFdCount) == EINVAL);
    if (mask)
      assert(SendWorkLaunch(sender, request, roles.data(),
                            ExpectedWorkLaunchFdCount(request)) == EINVAL);
    for (size_t role = 0; role < kLaunchFdCount; ++role) {
      auto malformed = roles;
      // Missing management/open roles, or an FD in an explicitly closed role.
      malformed[role] = roles[role] < 0 ? originals[role] : -1;
      assert(SendWorkLaunch(sender, request, malformed.data(),
                            malformed.size()) == EINVAL);
      malformed[role] = -2;
      assert(SendWorkLaunch(sender, request, malformed.data(),
                            malformed.size()) == EINVAL);
    }
    for (auto operation :
         {WorkLaunchOperation::Staged, WorkLaunchOperation::Wake,
          WorkLaunchOperation::Failed}) {
      request.operation = operation;
      assert(SendWorkLaunch(sender, request, originals.data(),
                            originals.size()) == EINVAL);
    }
  }
  WorkLaunchMessage result;
  assert(ReceiveWorkLaunch(receiver, peer, result) == EAGAIN);
  empty(result);
  assert(descriptors() == baseline);
  for (int fd : originals) assert(fcntl(fd, F_GETFD) >= 0);
}
void receiver_rejections(int sender, int receiver, LaunchPeer peer,
                         const Roles& originals) {
  const size_t baseline = descriptors();
  WorkLaunchMessage result;
  auto rejected = [&](int error = EPROTO) {
    assert(ReceiveWorkLaunch(receiver, peer, result) == error);
    empty(result);
    assert(descriptors() == baseline);
  };
  for (uint32_t mask = 0; mask < 8; ++mask) {
    auto request = request_packet();
    request.stdio_closed = mask;
    auto roles = fixed_roles(originals, mask);
    Roles compact{};
    size_t count = 0;
    for (int fd : roles)
      if (fd >= 0) compact[count++] = fd;
    raw_send(sender, &request, sizeof(request));
    rejected();
    // Each absent management or open standard role must fail, with every
    // remaining delivered descriptor closed, rather than shifting roles.
    for (size_t omitted = 0; omitted < count; ++omitted) {
      Roles missing{};
      size_t next = 0;
      for (size_t role = 0; role < count; ++role)
        if (role != omitted) missing[next++] = compact[role];
      raw_send(sender, &request, sizeof(request), missing.data(), next);
      rejected();
    }
    std::array<int, kLaunchFdCount + 1> extra{};
    for (size_t role = 0; role < count; ++role) extra[role] = compact[role];
    extra[count] = originals[0];
    raw_send(sender, &request, sizeof(request), extra.data(), count + 1);
    rejected();
    for (auto operation :
         {WorkLaunchOperation::Staged, WorkLaunchOperation::Wake,
          WorkLaunchOperation::Failed}) {
      request.operation = operation;
      raw_send(sender, &request, sizeof(request), originals.data(), 1);
      rejected();
    }
  }
  auto invalid_packet = [&](const WorkLaunchPacket& packet) {
    assert(SendWorkLaunch(sender, packet, originals.data(), originals.size()) ==
           EINVAL);
    raw_send(sender, &packet, sizeof(packet), originals.data(),
             originals.size());
    rejected();
  };
  for (uint32_t mask : {8U, 0x80000000U, 0xffffffffU}) {
    auto request = request_packet();
    request.stdio_closed = mask;
    invalid_packet(request);
    request.operation = WorkLaunchOperation::Wake;
    assert(SendWorkLaunch(sender, request) == EINVAL);
    raw_send(sender, &request, sizeof(request));
    rejected();
  }
  auto request = request_packet();
  request.version = 1;  // Same sized framing must not make v1 acceptable.
  invalid_packet(request);
  request = request_packet();
  request.magic = 0;
  invalid_packet(request);
  request = request_packet();
  request.reserved = 1;
  invalid_packet(request);
  request = request_packet();
  request.principal_profile = 2;
  invalid_packet(request);
  request = request_packet();
  request.error = EIO;
  invalid_packet(request);
  for (auto operation : {WorkLaunchOperation(0), WorkLaunchOperation(5)}) {
    request = request_packet();
    request.operation = operation;
    invalid_packet(request);
  }
  request = request_packet();
  request.work.manager = 0;
  invalid_packet(request);
  request = request_packet();
  request.work.serial = 0;
  invalid_packet(request);
  request = request_packet();
  request.epoch.platform = 0;
  invalid_packet(request);
  request = request_packet();
  request.epoch.generation = 0;
  invalid_packet(request);
  request = request_packet();
  request.epoch.user = -1;
  invalid_packet(request);
  request = request_packet();
  // The old packet layout is also refused, with all of its rights reclaimed.
  struct LegacyPacket {
    uint64_t magic = 0x414e44584c41554eULL;
    uint32_t version = 1;
    WorkLaunchOperation operation = WorkLaunchOperation::Prepare;
    WorkIdentity work{11, 1};
    AuthorityEpoch epoch{91, 8, 0};
    LaunchObjectIdentity aggregate{7, 10}, scope{7, 11};
    int32_t error = 0;
    uint32_t reserved = 0;
  } legacy;
  raw_send(sender, &legacy, sizeof(legacy), originals.data(), originals.size());
  rejected();
  raw_send(sender, &request, sizeof(request) - 1, originals.data(),
           originals.size());
  rejected();
  std::array<char, sizeof(request) + 1> oversized{};
  memcpy(oversized.data(), &request, sizeof(request));
  raw_send(sender, oversized.data(), oversized.size(), originals.data(),
           originals.size());
  rejected();
  // Truncated ancillary data must close every installed FD. Linux also closes
  // excess rights that do not fit in the receiver's control buffer.
  std::array<int, kExtraRights> excess{};
  excess.fill(originals[0]);
  raw_send(sender, &request, sizeof(request), excess.data(), excess.size());
  rejected();
  // A zero byte seqpacket may still deliver rights. It is not an empty EOF.
  raw_send(sender, &request, 0, originals.data(), originals.size());
  rejected(ECONNRESET);
  // Refusal closes a prior sparse receipt as well as newly delivered rights.
  request.stdio_closed = 2;
  auto roles = fixed_roles(originals, request.stdio_closed);
  assert(!SendWorkLaunch(sender, request, roles.data(), roles.size()));
  assert(!ReceiveWorkLaunch(receiver, peer, result));
  request.version = 1;
  raw_send(sender, &request, sizeof(request), originals.data(),
           originals.size());
  rejected();
  request = request_packet();
  for (LaunchPeer foreign : {LaunchPeer{peer.pid + 1, peer.uid, peer.gid},
                             LaunchPeer{peer.pid, peer.uid + 1, peer.gid},
                             LaunchPeer{peer.pid, peer.uid, peer.gid + 1}}) {
    assert(
        !SendWorkLaunch(sender, request, originals.data(), originals.size()));
    assert(ReceiveWorkLaunch(receiver, foreign, result) != 0);
    empty(result);
    assert(descriptors() == baseline);
  }
  int unconfigured[2];
  assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, unconfigured));
  assert(!SendWorkLaunch(unconfigured[0], request, originals.data(),
                         originals.size()));
  assert(ReceiveWorkLaunch(unconfigured[1], peer, result) == EPERM);
  empty(result);
  close(unconfigured[0]);
  close(unconfigured[1]);
  assert(descriptors() == baseline);
}
}  // namespace
int main() {
  int pair[2];
  assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair));
  assert(!ConfigureWorkLaunchSocket(pair[0]) &&
         !ConfigureWorkLaunchSocket(pair[1]));
  LaunchPeer peer{getpid(), getuid(), getgid()};
  Roles originals{};
  for (int& fd : originals) {
    // Distinct kernel objects expose accidental compact/fixed role confusion.
    int pipe[2];
    assert(!pipe2(pipe, O_CLOEXEC));
    fd = pipe[0];
    close(pipe[1]);
  }
  masks(pair[0], pair[1], peer, originals);
  legacy_profile(pair[0], pair[1], peer, originals);
  sender_roles(pair[0], pair[1], peer, originals);
  receiver_rejections(pair[0], pair[1], peer, originals);
  auto request = request_packet();
  request.stdio_closed = 7;
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
  WorkLaunchMessage result;
  assert(!ReceiveWorkLaunch(pair[0], {child, getuid(), getgid()}, result));
  empty(result);
  assert(result.packet.stdio_closed == request.stdio_closed);
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  close(pair[0]);
  for (int fd : originals) close(fd);
}
