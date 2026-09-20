// SPDX-License-Identifier: Apache-2.0
// Ordinary owner test client. Never a privileged bootstrap or installed
// service.
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "launch_description.h"
#include "work_channel.h"
#include "work_service_protocol.h"

using namespace andrix;
using Op = WorkServiceOperation;
using Result = WorkRegistryResult;
namespace {
#define NEED(x)                                                                \
  do {                                                                         \
    if (!(x)) {                                                                \
      dprintf(2, "TRANSPORT_PROBE_FAILED line=%d %s errno=%d\n", __LINE__, #x, \
              errno);                                                          \
      exit(112);                                                               \
    }                                                                          \
  } while (0)
struct Fd {
  int value = -1;
  explicit Fd(int value = -1) : value(value) {}
  ~Fd() { Close(); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept : value(std::exchange(other.value, -1)) {}
  Fd& operator=(Fd&& other) noexcept {
    Close();
    value = std::exchange(other.value, -1);
    return *this;
  }
  void Close() {
    if (value >= 0) close(std::exchange(value, -1));
  }
};
uint64_t now() {
  timespec t{};
  NEED(!clock_gettime(CLOCK_MONOTONIC, &t));
  return uint64_t(t.tv_sec) * 1000 + uint64_t(t.tv_nsec) / 1000000;
}
void ready(int fd, short events, int timeout = 20) {
  pollfd wait{fd, events, 0};
  int result = poll(&wait, 1, timeout);
  NEED(result >= 0 || errno == EINTR);
}
struct Request {
  WorkFrameHeader header;
};
struct Peer {
  Fd socket;
  AuthorizedWorkPeer peer;
  WorkServiceIdentity identity;
  uint64_t sequence = 0, receives = 0;
  explicit Peer(const std::string& endpoint) {
    NEED(!endpoint.empty() &&
         endpoint.size() + 1 < sizeof(sockaddr_un{}.sun_path));
    socket =
        Fd(::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    NEED(socket.value >= 0 && !ConfigureWorkPeerSocket(socket.value));
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path + 1, endpoint.data(), endpoint.size());
    NEED(!connect(socket.value, reinterpret_cast<sockaddr*>(&address),
                  offsetof(sockaddr_un, sun_path) + endpoint.size() + 1));
    int error = 0;
    auto authorized =
        AuthorizedWorkPeer::Capture(socket.value, WorkPeerSide::Client, error);
    NEED(authorized.has_value());
    peer = std::move(*authorized);
    auto greeting = Call(Op::Hello, {});
    NEED(greeting.result == Result::Accepted);
    identity = greeting.service;
  }
  Request Send(Op op, WorkServiceRequest request, std::span<const int> fds = {},
               const WorkServiceIdentity* override_identity = nullptr) {
    if (op != Op::Hello)
      request.service = override_identity ? *override_identity : identity;
    NEED(ValidWorkServiceRequest(op, request, fds.size()) &&
         sequence != UINT64_MAX);
    Request token;
    token.header.operation = static_cast<uint32_t>(op);
    token.header.correlation = ++sequence;
    auto bytes = EncodeWorkServiceRequest(request);
    const auto deadline = now() + 10000;
    for (;;) {
      int error = SendWorkFrame(socket.value, token.header, bytes, fds);
      if (!error) return token;
      NEED((error == EAGAIN || error == EINTR) && now() < deadline);
      ready(socket.value, POLLOUT);
    }
  }
  WorkServiceReply Receive(Request token) {
    WorkFrame frame;
    const auto deadline = now() + 10000;
    for (;;) {
      int error = ReceiveAuthorizedWorkFrame(socket.value, peer, frame);
      if (!error) break;
      NEED((error == EAGAIN || error == EINTR) && now() < deadline);
      ready(socket.value, POLLIN);
    }
    ++receives;
    WorkServiceReply reply;
    NEED(frame.header().correlation == token.header.correlation &&
         frame.header().operation == token.header.operation);
    NEED(!frame.descriptor_count() &&
         DecodeWorkServiceReply(frame.body(), reply));
    NEED(token.header.operation == uint32_t(Op::Hello) ||
         reply.service == identity);
    return reply;
  }
  void CloseConfirmed() {
    // All replies on this conversation were consumed. Half close and observe
    // server EOF, not just our own close, before claiming its handles retired.
    NEED(socket.value >= 0 && !shutdown(socket.value, SHUT_WR));
    const auto deadline = now() + 10000;
    for (;;) {
      char byte;
      ssize_t count = recv(socket.value, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
      if (!count) break;
      NEED(count < 0 && (errno == EAGAIN || errno == EINTR) &&
           now() < deadline);
      ready(socket.value, POLLIN);
    }
    socket.Close();
  }
  WorkServiceReply Call(
      Op op, WorkServiceRequest request, std::span<const int> fds = {},
      const WorkServiceIdentity* override_identity = nullptr) {
    return Receive(Send(op, request, fds, override_identity));
  }
};
WorkServiceRequest serial(uint64_t work) {
  WorkServiceRequest r;
  r.serial = work;
  return r;
}
WorkServiceReport one(const WorkServiceReply& reply) {
  NEED((reply.result == Result::Accepted || reply.result == Result::Existing) &&
       reply.works.size() == 1);
  return reply.works[0];
}
uint64_t stream(Peer& p) {
  auto r = p.Call(Op::OpenStream, {});
  NEED(r.result == Result::Accepted && r.stream);
  return r.stream;
}
WorkServiceReply reserve(Peer& p, uint64_t stream_id, uint64_t sequence) {
  WorkServiceRequest request;
  request.stream = stream_id;
  request.sequence = sequence;
  return p.Call(Op::Reserve, request);
}
void close_stream(Peer& p, uint64_t id) {
  WorkServiceRequest request;
  request.stream = id;
  NEED(p.Call(Op::CloseStream, request).result == Result::Accepted);
}
std::unique_ptr<Peer> bind(const std::string& endpoint, uint64_t work) {
  auto result = std::make_unique<Peer>(endpoint + ".ctl");
  NEED(one(result->Call(Op::Bind, serial(work))).catalog.work.work.serial ==
       work);
  return result;
}
WorkServiceReport inspect(Peer& p, uint64_t work) {
  return one(p.Call(Op::Inspect, serial(work)));
}
template <class Predicate>
WorkServiceReport until(Peer& p, uint64_t work, Predicate predicate) {
  const auto deadline = now() + 20000;
  for (;;) {
    auto value = inspect(p, work);
    NEED(!value.catalog.work.blocked && !value.runtime.blocked);
    if (predicate(value)) return value;
    NEED(now() < deadline);
    usleep(20000);
  }
}
WorkServiceReport retired(Peer& p, uint64_t work) {
  return until(p, work, [](const auto& r) {
    return r.catalog.work.complete &&
           r.runtime.phase == WorkRuntimePhase::Missing &&
           r.catalog.inputs != WorkInputState::Preparing &&
           r.catalog.inputs != WorkInputState::Releasing;
  });
}
struct Input {
  Fd description, reader, writer;
  uint64_t id = 0;
  std::string output;
  bool eof = false;
};
Input input(const std::string& executable, const std::string& directory) {
  LaunchDescription launch{executable,
                           {executable, "--payload"},
                           {"PATH=/usr/bin:/system/bin", "HOME=" + directory},
                           directory};
  LaunchFailure failure;
  Input i;
  i.description = Fd(SealLaunch(launch, {}, failure));
  NEED(i.description.value >= 0);
  int pipefd[2];
  NEED(!pipe2(pipefd, O_CLOEXEC));
  i.reader = Fd(pipefd[0]);
  i.writer = Fd(pipefd[1]);
  NEED(!fcntl(i.reader.value, F_SETFL,
              fcntl(i.reader.value, F_GETFL) | O_NONBLOCK));
  return i;
}
void prepare(Peer& p, uint64_t work, Input& i) {
  WorkServiceRequest request = serial(work);
  request.stdio_closed = 1;
  std::array<int, 3> fds{i.description.value, i.writer.value, i.writer.value};
  auto reply = p.Call(Op::Prepare, request, fds);
  NEED(reply.result == Result::Accepted && reply.input);
  i.id = reply.input;
  i.description.Close();
  i.writer.Close();
}
WorkServiceReply start(Peer& p, uint64_t work, uint64_t id) {
  auto r = serial(work);
  r.input = id;
  return p.Call(Op::Start, r);
}
void drain(Input& i, bool eof) {
  const auto deadline = now() + 15000;
  for (;;) {
    char bytes[256];
    ssize_t count = read(i.reader.value, bytes, sizeof(bytes));
    if (count > 0) {
      i.output.append(bytes, count);
      NEED(i.output.size() < 512);
    } else if (!count) {
      i.eof = true;
      break;
    } else
      NEED(errno == EAGAIN || errno == EINTR);
    if (!eof && i.output.find('\n') != std::string::npos) break;
    NEED(now() < deadline);
    ready(i.reader.value, POLLIN);
  }
  if (eof) NEED(i.eof);
}
struct Notice {
  uint64_t receives_before = 0, receives_after = 0;
  uint32_t operation = 0;
  pid_t submitter = 0;
};
Notice disappear(Peer& p, Op op, WorkServiceRequest request,
                 std::span<const int> fds = {}) {
  int channel[2];
  NEED(!pipe2(channel, O_CLOEXEC));
  Fd reader(channel[0]), writer(channel[1]);
  pid_t child = fork();
  NEED(child >= 0);
  if (!child) {
    reader.Close();
    // Same-principal inherited socket use, not a PID-authentication shortcut.
    // Retain only descriptors genuinely needed for this send and notification.
    for (int fd = 3; fd < 128; ++fd) {
      bool keep = fd == p.socket.value || fd == writer.value;
      for (int passed : fds) keep |= fd == passed;
      if (!keep) close(fd);
    }
    Notice note{p.receives, p.receives, uint32_t(op), getpid()};
    p.Send(op, request, fds);
    note.receives_after = p.receives;
    NEED(write(writer.value, &note, sizeof(note)) == ssize_t(sizeof(note)));
    writer.Close();
    for (;;) pause();  // Never receive the operation reply.
  }
  Fd pidfd(int(syscall(SYS_pidfd_open, child, 0)));
  NEED(pidfd.value >= 0);
  writer.Close();
  p.socket.Close();  // Child is now the only client endpoint owner.
  Notice note;
  ready(reader.value, POLLIN, 10000);
  NEED(read(reader.value, &note, sizeof(note)) == ssize_t(sizeof(note)) &&
       note.receives_before == note.receives_after &&
       note.operation == uint32_t(op) && note.submitter == child);
  pollfd alive{pidfd.value, POLLIN, 0};
  NEED(poll(&alive, 1, 0) == 0);
  NEED(!syscall(SYS_pidfd_send_signal, pidfd.value, SIGKILL, nullptr, 0));
  int status;
  NEED(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
       WTERMSIG(status) == SIGKILL);
  return note;
}
void owner_profile(bool descriptors) {
  NEED(getuid() == 7500 && geteuid() == 7500 && getgid() == 7500 &&
       getegid() == 7500);
  NEED(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 &&
       prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2);
  char sid[128]{};
  Fd f(open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC));
  NEED(f.value >= 0 && read(f.value, sid, 127) > 0);
  f.Close();
  sid[strcspn(sid, "\n")] = 0;
  NEED(!strcmp(sid, "u:r:andrix_owner:s0"));
  if (descriptors) {
    DIR* directory = opendir("/proc/self/fd");
    NEED(directory);
    dirent* entry;
    while ((entry = readdir(directory)))
      if (entry->d_name[0] != '.') {
        int fd = atoi(entry->d_name);
        NEED(fd <= 2 || fd == dirfd(directory));
      }
    closedir(directory);
  }
}
int payload() {
  owner_profile(true);
  signal(SIGHUP, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  dprintf(1, "PAYLOAD_ONCE pid=%d\n", getpid());
  alarm(180);
  for (;;) pause();
}
std::string endpoint_update(const std::string& path) {
  const auto deadline = now() + 90000;
  for (;;) {
    Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (file.value >= 0) {
      char bytes[128]{};
      ssize_t count = read(file.value, bytes, sizeof(bytes) - 1);
      NEED(count > 0 && count < ssize_t(sizeof(bytes) - 1));
      std::string value(bytes, count);
      while (!value.empty() && (value.back() == '\n' || value.back() == '\r'))
        value.pop_back();
      NEED(value.starts_with("andrix.work.") && value.size() < 100);
      return value;
    }
    NEED(errno == ENOENT && now() < deadline);
    usleep(20000);
  }
}
void self_test() {
  WorkServiceRequest request;
  request.service = {1, 2, 3};
  request.serial = 4;
  request.input = 5;
  auto wire = EncodeWorkServiceRequest(request);
  WorkServiceRequest decoded;
  NEED(DecodeWorkServiceRequest(wire, decoded) &&
       decoded.service == request.service && decoded.serial == 4 &&
       decoded.input == 5);
  NEED(ValidWorkServiceRequest(Op::Start, request, 0));
  WorkServiceReply reply;
  reply.service = request.service;
  reply.result = Result::Stale;
  WorkServiceReply copy;
  NEED(DecodeWorkServiceReply(EncodeWorkServiceReply(reply), copy) &&
       copy.result == Result::Stale);
  auto i = input("/ordinary/program", "/ordinary");
  LaunchDescription description;
  LaunchFailure failure;
  NEED(ReadLaunch(i.description.value, {}, description, failure) &&
       description.arguments[1] == "--payload");
  puts(
      "{\"transport_probe_codec_and_link\":true,\"Android_runtime_qualified\":"
      "false}");
}
}  // namespace
int main(int argc, char** argv) {
  setbuf(stdout, nullptr);
  if (argc == 2 && !strcmp(argv[1], "--self-test")) {
    self_test();
    return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "--payload")) return payload();
  NEED(argc == 5 && !strcmp(argv[1], "--exercise"));
  owner_profile(false);
  alarm(240);
  const std::string endpoint = argv[2], directory = argv[3], update = argv[4];
  char* actual = realpath(argv[0], nullptr);
  NEED(actual);
  const std::string executable = actual;
  free(actual);
  NEED(access(update.c_str(), F_OK) < 0 && errno == ENOENT);
  WorkServiceIdentity original;
  uint64_t cancelled_work = 0, cancelled_input = 0;
  {
    Peer management(endpoint);
    original = management.identity;
    uint64_t id = stream(management);
    auto reserved = reserve(management, id, 1);
    NEED(reserved.result == Result::Accepted);
    cancelled_work = reserved.serial;
    auto control = bind(endpoint, cancelled_work);
    auto io = input(executable, directory);
    auto request = serial(cancelled_work);
    request.stdio_closed = 1;
    std::array<int, 3> fds{io.description.value, io.writer.value,
                           io.writer.value};
    disappear(management, Op::Prepare, request, fds);
    io.description.Close();
    io.writer.Close();
    auto closed = until(*control, cancelled_work, [](const auto& r) {
      return r.catalog.work.complete &&
             r.catalog.inputs == WorkInputState::Rejected;
    });
    NEED(closed.catalog.input_error == ECANCELED);
    NEED(!closed.catalog.work.start_accepted &&
         closed.catalog.work.entry_gate_closed &&
         closed.catalog.work.stop_sources == uint32_t(WorkStopSource::Manager));
    NEED(closed.catalog.work.initial == WorkInitialState::Absent &&
         closed.runtime.phase == WorkRuntimePhase::Missing &&
         closed.catalog.input.serial);
    cancelled_input = closed.catalog.input.serial;
    drain(io, true);
    NEED(io.output.empty());
    Peer reconnect(endpoint);
    auto existing = reserve(reconnect, id, 1);
    NEED(existing.result == Result::Existing &&
         existing.serial == cancelled_work);
    NEED(start(reconnect, cancelled_work, cancelled_input).result ==
         Result::WrongState);
    close_stream(reconnect, id);
    reconnect.CloseConfirmed();
    NEED(control->Call(Op::Forget, serial(cancelled_work)).result ==
         Result::Accepted);
    control.reset();
  }
  Peer management(endpoint);
  uint64_t id = stream(management);
  auto reserved = reserve(management, id, 1);
  NEED(reserved.result == Result::Accepted);
  const uint64_t a = reserved.serial;
  auto old = bind(endpoint, a);
  auto io_a = input(executable, directory);
  prepare(management, a, io_a);
  auto start_request = serial(a);
  start_request.input = io_a.id;
  Notice sent = disappear(management, Op::Start, start_request);
  auto live_a = until(*old, a, [](const auto& r) {
    return r.catalog.work.start_accepted && r.catalog.work.entry_claimed &&
           r.runtime.initial_pid > 1;
  });
  NEED(!live_a.catalog.work.stop_sources);
  drain(io_a, false);
  NEED(io_a.output ==
       "PAYLOAD_ONCE pid=" + std::to_string(live_a.runtime.initial_pid) + "\n");
  Peer reconcile(endpoint);
  auto known = reserve(reconcile, id, 1);
  NEED(known.result == Result::Existing && known.serial == a);
  NEED(one(known).catalog.input.serial == io_a.id &&
       one(known).catalog.work.start_accepted);
  for (unsigned n = 0; n < 20; ++n)
    NEED(start(reconcile, a, io_a.id).result == Result::Existing);
  auto same = inspect(*old, a);
  NEED(same.runtime.initial_pid == live_a.runtime.initial_pid &&
       same.catalog.work.scope_identity == live_a.catalog.work.scope_identity);
  NEED(old->Call(Op::Stop, serial(a)).result == Result::Accepted);
  auto done = retired(*old, a);
  NEED(done.catalog.work.initial_exit ==
       (WorkExit{WorkExitKind::Signal, SIGKILL}));
  NEED(start(reconcile, a, io_a.id).result == Result::Existing);
  drain(io_a, true);
  NEED(io_a.output ==
       "PAYLOAD_ONCE pid=" + std::to_string(live_a.runtime.initial_pid) + "\n");
  close_stream(reconcile, id);
  reconcile.CloseConfirmed();
  NEED(old->Call(Op::Forget, serial(a)).result == Result::Accepted &&
       inspect(*old, a).catalog.work.forgotten);
  Peer next(endpoint);
  {
    // This selected service has exactly two management workers. Two concurrent
    // Hello acknowledgements prove earlier submitter conversations have left
    // those workers; they cannot be an alternate pin for the old work record.
    Peer barrier(endpoint);
    barrier.CloseConfirmed();
  }
  uint64_t next_id = stream(next);
  auto b_reply = reserve(next, next_id, 1);
  NEED(b_reply.result == Result::Accepted);
  uint64_t b = b_reply.serial;
  auto control_b = bind(endpoint, b);
  auto io_b = input(executable, directory);
  prepare(next, b, io_b);
  NEED(io_b.id != io_a.id &&
       start(next, b, io_a.id).result == Result::Conflict &&
       !inspect(*control_b, b).catalog.work.start_accepted);
  NEED(start(next, b, io_b.id).result == Result::Accepted);
  auto live_b = until(*control_b, b, [](const auto& r) {
    return r.catalog.work.entry_claimed && r.runtime.initial_pid > 1;
  });
  drain(io_b, false);
  NEED(old->Call(Op::Stop, serial(a)).result == Result::Accepted);
  NEED(old->Call(Op::Bind, serial(b)).result == Result::Foreign &&
       old->Call(Op::Stop, serial(b)).result == Result::Foreign);
  NEED(inspect(*control_b, b).runtime.initial_pid ==
           live_b.runtime.initial_pid &&
       !inspect(*control_b, b).catalog.work.stop_sources);
  auto c = reserve(next, next_id, 2), d = reserve(next, next_id, 3);
  NEED(c.result == Result::Accepted && d.result == Result::Accepted);
  NEED(reserve(next, next_id, 4).result == Result::Capacity);
  old.reset();
  WorkServiceReply reused;
  const auto deadline = now() + 10000;
  do {
    reused = reserve(next, next_id, 4);
    if (reused.result != Result::Capacity) break;
    NEED(now() < deadline);
    usleep(20000);
  } while (true);
  NEED(reused.result == Result::Accepted && reused.serial > a);
  {
    Peer stale(endpoint + ".ctl");
    NEED(stale.Call(Op::Bind, serial(a)).result == Result::Stale);
  }
  close_stream(next, next_id);
  next.CloseConfirmed();
  for (uint64_t unused : {c.serial, d.serial, reused.serial}) {
    auto control = bind(endpoint, unused);
    auto state = retired(*control, unused);
    NEED(!state.catalog.work.start_accepted &&
         state.catalog.work.stop_sources == uint32_t(WorkStopSource::Manager));
    NEED(control->Call(Op::Forget, serial(unused)).result == Result::Accepted);
  }
  NEED(!inspect(*control_b, b).catalog.work.stop_sources);
  printf(
      "{\"phase\":1,\"cancelled_work\":%llu,\"cancelled_input\":%llu,"
      "\"cancelled_EOF\":true,\"start_reply_reads\":%llu,\"submitter_signal\":"
      "9,\"submitter_pid\":%d,\"parent_pid\":%d,\"accepted_work\":%llu,"
      "\"initial_pid\":%d,\"retry_existing_count\":21,"
      "\"single_payload_and_EOF\":true,\"forgotten_bound_record_pinned_"
      "capacity\":true,\"foreign_bind_and_stop_refused\":true,\"stale_input_"
      "refused\":true,\"released_slot_new_serial\":%llu,\"held_work\":%llu,"
      "\"held_pid\":%d,\"namespace\":\"%llu.%llu.%llu\"}\n",
      (unsigned long long)cancelled_work, (unsigned long long)cancelled_input,
      (unsigned long long)(sent.receives_after - sent.receives_before),
      sent.submitter, getpid(), (unsigned long long)a,
      live_a.runtime.initial_pid, (unsigned long long)reused.serial,
      (unsigned long long)b, live_b.runtime.initial_pid,
      (unsigned long long)original.boot,
      (unsigned long long)original.environment,
      (unsigned long long)original.manager);
  puts("TRANSPORT_OLD_CONTROL_HELD");
  const auto fresh_endpoint = endpoint_update(update);
  NEED(fresh_endpoint != endpoint);
  drain(io_b, true);
  NEED(io_b.output ==
       "PAYLOAD_ONCE pid=" + std::to_string(live_b.runtime.initial_pid) + "\n");
  WorkFrameHeader header;
  header.operation = uint32_t(Op::Stop);
  header.correlation = ++control_b->sequence;
  auto request = serial(b);
  request.service = original;
  int old_error = SendWorkFrame(control_b->socket.value, header,
                                EncodeWorkServiceRequest(request));
  if (!old_error) {
    WorkFrame frame;
    const auto limit = now() + 10000;
    do {
      old_error = ReceiveAuthorizedWorkFrame(control_b->socket.value,
                                             control_b->peer, frame);
      if (old_error != EAGAIN && old_error != EINTR) break;
      NEED(now() < limit);
      ready(control_b->socket.value, POLLIN);
    } while (true);
  }
  NEED(old_error && old_error != EAGAIN && old_error != EINTR);
  control_b.reset();
  Peer fresh(fresh_endpoint);
  NEED(fresh.identity != original && fresh.Call(Op::List, {}).works.empty());
  NEED(fresh.Call(Op::List, {}, {}, &original).result == Result::Stale);
  {
    Peer raw(fresh_endpoint + ".ctl");
    NEED(raw.Call(Op::Bind, serial(b), {}, &original).result == Result::Stale);
  }
  uint64_t fresh_stream = stream(fresh);
  auto f = reserve(fresh, fresh_stream, 1);
  NEED(f.result == Result::Accepted);
  auto fresh_control = bind(fresh_endpoint, f.serial);
  auto fresh_io = input(executable, directory);
  prepare(fresh, f.serial, fresh_io);
  NEED(start(fresh, f.serial, fresh_io.id).result == Result::Accepted);
  auto positive = until(*fresh_control, f.serial, [](const auto& r) {
    return r.catalog.work.entry_claimed && r.runtime.initial_pid > 1;
  });
  drain(fresh_io, false);
  NEED(fresh_control->Call(Op::Stop, serial(f.serial), {}, &original).result ==
       Result::Stale);
  auto still = inspect(*fresh_control, f.serial);
  NEED(still.runtime.initial_pid == positive.runtime.initial_pid &&
       !still.catalog.work.stop_sources &&
       !still.catalog.work.entry_gate_closed);
  NEED(fresh_control->Call(Op::Stop, serial(f.serial)).result ==
       Result::Accepted);
  retired(*fresh_control, f.serial);
  drain(fresh_io, true);
  NEED(fresh_io.output ==
       "PAYLOAD_ONCE pid=" + std::to_string(positive.runtime.initial_pid) +
           "\n");
  NEED(fresh_control->Call(Op::Forget, serial(f.serial)).result ==
       Result::Accepted);
  close_stream(fresh, fresh_stream);
  NEED(fresh.Call(Op::List, {}).works.empty());
  printf(
      "{\"phase\":2,\"old_retained_socket_error\":%d,\"old_namespace_list_bind_"
      "stop_stale\":true,\"fresh_work_unaffected_by_stale_Stop\":true,\"fresh_"
      "work\":%llu,\"fresh_initial_pid\":%d,\"fresh_EOF_and_retirement\":true,"
      "\"namespace\":\"%llu.%llu.%llu\"}\n",
      old_error, (unsigned long long)f.serial, positive.runtime.initial_pid,
      (unsigned long long)fresh.identity.boot,
      (unsigned long long)fresh.identity.environment,
      (unsigned long long)fresh.identity.manager);
  puts("TRANSPORT_PROBE_COMPLETE");
  return 0;
}
