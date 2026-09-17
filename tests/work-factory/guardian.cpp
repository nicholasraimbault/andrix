// SPDX-License-Identifier: Apache-2.0
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <map>

#include "common.h"
#include "guards.h"
#include "platform_lifecycle.h"

using namespace andrix::factory_proof;
using android::base::unique_fd;

int main(int argc, char** argv) {
  android::base::InitLogging(argv,
                             android::base::LogdLogger(android::base::SYSTEM));
  uint64_t manager = 0, work = 0;
  if (argc != 3 || !parse_id(argv[1], &manager) || !parse_id(argv[2], &work) ||
      !android::base::GetBoolProperty("ro.debuggable", false) ||
      !andrix::check_identity().empty() || role() != "u:r:andrixd:s0")
    fail("guardian bootstrap");
  const auto began = now_ms();
  const std::string group = current_group();
  std::string error;
  while (!(error = bounds_error(group, false)).empty()) {
    if (now_ms() - began > 15000) fail(error);
    usleep(10000);
  }
  andrix::PlatformLifecycle platform;
  if (!platform.start()) fail("platform start");
  while (!platform.ready()) {
    if (platform.failed() || now_ms() - began > 20000)
      fail("platform readiness");
    usleep(10000);
  }
  if (prctl(PR_SET_CHILD_SUBREAPER, 1)) fail("guardian subreaper");
  unique_fd control;
  while (control < 0 && now_ms() - began < 25000) {
    control = manager_socket(manager, false);
    if (control < 0) usleep(10000);
  }
  pid_t manager_pid = 0;
  if (control < 0 || !peer_is_coordinator(control, &manager_pid))
    fail("actual manager peer");
  const auto backend =
      android::base::GetProperty("ro.andrix.factory_backend", "");
  const std::string expected =
      std::string(kUidGroup) + "/pid_" +
      std::to_string(backend == "init" ? getpid() : manager_pid) +
      (backend == "delegated" ? "/work_" + std::to_string(work) : "");
  if ((backend != "init" && backend != "delegated") || group != expected ||
      getppid() != (backend == "init" ? 1 : manager_pid))
    fail("factory lineage and exact group");
  Packet hello;
  hello.operation = Hello;
  hello.manager = manager;
  hello.work = work;
  hello.guardian = getpid();
  if (!send_packet(control, hello)) fail("guardian registration");
  bool accepted = false;
  while (!accepted && now_ms() - began < 30000) {
    pollfd peer{control.get(), POLLIN | POLLHUP | POLLERR, 0};
    if (poll(&peer, 1, 10) < 0 && errno != EINTR) fail("registration poll");
    if (peer.revents & (POLLHUP | POLLERR)) _exit(0);
    Packet packet;
    if (receive_packet(control, &packet)) {
      if (packet.operation != Accept || packet.manager != manager ||
          packet.work != work)
        fail("exact registration");
      accepted = true;
    } else {
      usleep(10000);
    }
  }
  if (!accepted) fail("registration deadline");
  Packet state;
  state.operation = State;
  state.manager = manager;
  state.work = work;
  state.guardian = getpid();
  state.phase = Ready;
  unique_fd release, events;
  std::map<pid_t, WorkerEvent> descendants;
  uint64_t last_state = 0;
  while (now_ms() - began < 240000) {
    if (platform.failed()) _exit(0);
    pollfd fds[2] = {{control.get(), POLLIN | POLLHUP | POLLERR, 0},
                     {events.get(), POLLIN, 0}};
    if (poll(fds, 2, 10) < 0 && errno != EINTR) fail("guardian poll");
    if (fds[0].revents & (POLLHUP | POLLERR))
      _exit(0);  // Lost exact manager connection, not a reusable name.
    if (fds[0].revents & POLLIN) {
      Packet command;
      if (!receive_packet(control, &command) || command.manager != manager ||
          command.work != work)
        fail("guardian exact control");
      if (command.operation == Stop) _exit(command.crash ? 77 : 0);
      if (command.operation == Hold && state.phase == Ready) {
        if (!platform.ready() || !bounds_error(group, false).empty())
          fail("hold authority");
        unique_fd home(andrix::open_ce_home(&error));
        if (home < 0) fail(error);
        int input[2], output[2];
        labelled_channel(input);
        labelled_channel(output);
        unique_fd in_read(input[0]), in_write(input[1]), out_read(output[0]),
            out_write(output[1]);
        if (fcntl(out_read, F_SETFL, O_NONBLOCK)) fail("event channel flags");
        std::string parent = std::to_string(getpid()), scope = group;
        char* args[] = {const_cast<char*>(kWorker), parent.data(), scope.data(),
                        nullptr};
        char path[] = "PATH=/system/bin";
        char* env[] = {path, nullptr};
        const pid_t self = getpid();
        pid_t child = fork();
        if (!child) {
          if (getppid() != self || dup2(in_read, 0) < 0 ||
              dup2(out_write, 1) < 0)
            _exit(125);
          for (int fd = 3; fd < 128; ++fd) close(fd);
          execve(kWorker, args, env);
          _exit(127);
        }
        if (child < 0) fail("entry fork");
        state.entry = child;
        state.phase = Holding;
        release = std::move(in_write);
        events = std::move(out_read);
      } else if (command.operation == Release && state.phase == Held) {
        if (!platform.ready() || !bounds_error(group, false).empty())
          fail("release authority");
        char byte = 'R';
        if (release < 0 || write(release, &byte, 1) != 1)
          fail("payload release");
        release.reset();
        state.phase = Released;
      } else {
        fail("control ordering");
      }
    }
    if (events >= 0) {
      WorkerEvent event;
      auto count =
          recv(events, &event, sizeof(event), MSG_DONTWAIT | MSG_TRUNC);
      if (count > 0) {
        if (count != sizeof(event) || event.magic != kWorkerMagic ||
            event.uid != 7500 || event.pid <= 1 ||
            event.binder_errno != EPERM ||
            (event.cgroup_errno != EACCES && event.cgroup_errno != EPERM))
          fail("actual worker negative controls");
        if (event.kind == WorkerHeld && event.pid == state.entry &&
            state.phase == Holding)
          state.phase = Held;
        else if (event.kind == WorkerPulse && event.pid != state.entry &&
                 state.phase == Released && event.session == event.pid &&
                 event.group == event.pid) {
          descendants[event.pid] = event;
          if (descendants.size() > 2) fail("descendant count");
          size_t i = 0;
          for (const auto& [pid, unused] : descendants) {
            (void)unused;
            state.descendants[i++] = pid;
          }
          ++state.pulses;
        } else
          fail("worker event ordering");
      } else if (count < 0 && errno != EAGAIN && errno != EINTR)
        fail("worker event read");
    }
    int status = 0;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
      if (pid == state.entry) {
        if (state.phase != Released || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
          fail("entry status/order");
        state.entry_exited = 1;
      }
    }
    if (state.entry && pid < 0 && errno == ECHILD) _exit(0);
    if (now_ms() - last_state >= 50) {
      // Bounded snapshots. A full observer socket is not a reason to kill
      // payloads.
      if (!send_packet(control, state) && errno != EAGAIN && errno != EINTR)
        _exit(0);
      last_state = now_ms();
    }
  }
  _exit(0);
}
