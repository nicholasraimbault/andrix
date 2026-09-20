// SPDX-License-Identifier: Apache-2.0
// Native owner client for the separately selected work service.
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "work_channel.h"
#include "work_service_protocol.h"

using android::base::unique_fd;
using namespace andrix;
extern char** environ;
namespace {
[[noreturn]] void die(const char* message, int error = 0) {
  dprintf(2, "andrix-work: %s (%d)\n", message, error);
  exit(125);
}
class Client {
 public:
  explicit Client(const std::string& endpoint) {
    if (endpoint.empty() ||
        endpoint.size() + 1 >= sizeof(sockaddr_un{}.sun_path))
      die("invalid endpoint");
    socket_.reset(
        socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (socket_ < 0) die("socket", errno);
    int error = ConfigureWorkPeerSocket(socket_.get());
    if (error) die("message credentials", error);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path + 1, endpoint.data(), endpoint.size());
    if (connect(socket_.get(), reinterpret_cast<sockaddr*>(&address),
                offsetof(sockaddr_un, sun_path) + endpoint.size() + 1))
      die("owner environment unavailable", errno);
    peer_ =
        AuthorizedWorkPeer::Capture(socket_.get(), WorkPeerSide::Client, error);
    if (!peer_) die("manager authentication", error);
    auto hello = Call(WorkServiceOperation::Hello, {});
    if (hello.result != WorkRegistryResult::Accepted)
      die("manager hello", hello.error);
    identity = hello.service;
  }
  WorkServiceReply Call(WorkServiceOperation operation,
                        WorkServiceRequest request,
                        std::span<const int> descriptors = {}) {
    if (operation != WorkServiceOperation::Hello) request.service = identity;
    if (!ValidWorkServiceRequest(operation, request, descriptors.size()))
      die("invalid local operation");
    auto body = EncodeWorkServiceRequest(request);
    WorkFrameHeader header;
    header.operation = static_cast<uint32_t>(operation);
    if (sequence_ == UINT64_MAX) die("request sequence exhausted");
    header.correlation = ++sequence_;
    for (size_t step = 0;; ++step) {
      int error = SendWorkFrame(socket_.get(), header, body, descriptors);
      if (!error) break;
      if ((error != EINTR && error != EAGAIN) || step == 250)
        die("request send", error);
      pollfd wait{socket_.get(), POLLOUT, 0};
      poll(&wait, 1, 20);
    }
    WorkFrame received;
    for (size_t step = 0;; ++step) {
      int error = ReceiveAuthorizedWorkFrame(socket_.get(), *peer_, received);
      if (!error) break;
      if ((error != EINTR && error != EAGAIN) || step == 1500)
        die("request outcome unknown; do not resubmit as new work", error);
      pollfd wait{socket_.get(), POLLIN, 0};
      poll(&wait, 1, 20);
    }
    WorkServiceReply reply;
    if (received.header().correlation != header.correlation ||
        received.header().operation != header.operation ||
        received.descriptor_count() ||
        !DecodeWorkServiceReply(received.body(), reply) ||
        (operation != WorkServiceOperation::Hello && reply.service != identity))
      die("invalid reply; request outcome unknown; do not resubmit as new "
          "work");
    return reply;
  }
  void Close() { socket_.reset(); }
  WorkServiceIdentity identity;

 private:
  unique_fd socket_;
  std::optional<AuthorizedWorkPeer> peer_;
  uint64_t sequence_ = 0;
};
struct Reference {
  WorkServiceIdentity service;
  uint64_t serial = 0;
};
Reference parse(const char* text) {
  Reference result;
  uint64_t* fields[] = {&result.service.boot, &result.service.environment,
                        &result.service.manager, &result.serial};
  const char* end = text + strlen(text);
  for (size_t index = 0; index < 4; ++index) {
    const char* separator = index == 3 ? end : strchr(text, '.');
    if (!separator) die("invalid work reference");
    auto parsed = std::from_chars(text, separator, *fields[index]);
    if (parsed.ec != std::errc{} || parsed.ptr != separator || !*fields[index])
      die("invalid work reference");
    text = separator + (index == 3 ? 0 : 1);
  }
  return result;
}
void print_reference(int fd, Reference reference) {
  dprintf(fd, "%llu.%llu.%llu.%llu",
          static_cast<unsigned long long>(reference.service.boot),
          static_cast<unsigned long long>(reference.service.environment),
          static_cast<unsigned long long>(reference.service.manager),
          static_cast<unsigned long long>(reference.serial));
}
void print(const WorkServiceReply& reply,
           const WorkRequestReference* request = nullptr) {
  printf("{\"result\":%u,\"error\":%d,", static_cast<unsigned>(reply.result),
         reply.error);
  if (request) {
    printf("\"request\":\"%s\",\"reference\":",
           FormatWorkRequestReference(*request).c_str());
    if (reply.serial) {
      printf("\"");
      fflush(stdout);
      print_reference(1, {reply.service, reply.serial});
      printf("\",");
    } else
      printf("null,");
  }
  printf("\"works\":[");
  bool first = true;
  for (const auto& report : reply.works) {
    const auto& work = report.catalog.work;
    if (!first) printf(",");
    first = false;
    printf("{\"reference\":\"");
    fflush(stdout);
    print_reference(1, {reply.service, work.work.serial});
    printf(
        "\",\"request\":\"%s\",\"started\":%s,\"gate_closed\":%s,\"entry_"
        "claimed\":%s,\"stop_"
        "sources\":%u,"
        "\"creator_pending\":%s,\"initial\":%u,\"exit_kind\":%u,\"exit_value\":"
        "%d,"
        "\"population\":%u,\"scope\":%u,\"complete\":%s,\"blocked\":%s,"
        "\"inputs\":%u,"
        "\"input\":%llu,\"input_error\":%d,\"runtime\":%u,\"runtime_blocked\":%"
        "s,"
        "\"launch_error\":%d,\"cleanup_error\":%d,\"runtime_error\":%d,\"kill_"
        "error\":%d",
        FormatWorkRequestReference(
            {reply.service, work.stream, work.request_sequence})
            .c_str(),
        work.start_accepted ? "true" : "false",
        work.entry_gate_closed ? "true" : "false",
        work.entry_claimed ? "true" : "false", work.stop_sources,
        work.creator_pending ? "true" : "false",
        static_cast<unsigned>(work.initial),
        static_cast<unsigned>(work.initial_exit.kind), work.initial_exit.value,
        static_cast<unsigned>(work.population),
        static_cast<unsigned>(work.scope), work.complete ? "true" : "false",
        work.blocked ? "true" : "false",
        static_cast<unsigned>(report.catalog.inputs),
        static_cast<unsigned long long>(report.catalog.input.serial),
        report.catalog.input_error, static_cast<unsigned>(report.runtime.phase),
        report.runtime.blocked ? "true" : "false", work.launch_error,
        work.cleanup_error, report.runtime.error, report.runtime.kill_error);
    auto epoch = work.epoch.value_or(AuthorityEpoch{});
    printf(
        ",\"platform\":%llu,\"generation\":%llu,\"user\":%d,\"scope_device\":%"
        "llu,\"scope_inode\":%llu,\"initial_pid\":%d}",
        static_cast<unsigned long long>(epoch.platform),
        static_cast<unsigned long long>(epoch.generation), epoch.user,
        static_cast<unsigned long long>(work.scope_identity.device),
        static_cast<unsigned long long>(work.scope_identity.inode),
        report.runtime.initial_pid);
  }
  puts("]}");
}
WorkServiceReport one(const WorkServiceReply& reply) {
  if ((reply.result != WorkRegistryResult::Accepted &&
       reply.result != WorkRegistryResult::Existing) ||
      reply.works.size() != 1)
    die("work request refused",
        reply.error ? reply.error : static_cast<int>(reply.result));
  return reply.works[0];
}
void bind(Client& client, Reference work) {
  if (client.identity != work.service)
    die("stale work belongs to another environment");
  WorkServiceRequest request;
  request.serial = work.serial;
  one(client.Call(WorkServiceOperation::Bind, request));
}
int wait(Client& client, uint64_t serial, bool scope) {
  WorkServiceRequest request;
  request.serial = serial;
  for (;;) {
    auto report = one(client.Call(WorkServiceOperation::Inspect, request));
    const auto& work = report.catalog.work;
    if (!scope && work.initial == WorkInitialState::Reaped)
      return work.initial_exit.kind == WorkExitKind::Code
                 ? work.initial_exit.value
                 : 128 + work.initial_exit.value;
    if (work.complete && report.runtime.phase == WorkRuntimePhase::Missing &&
        report.catalog.inputs != WorkInputState::Preparing &&
        report.catalog.inputs != WorkInputState::Releasing) {
      if (scope) return 0;
      die("launch ended without an initial process",
          work.launch_error ? work.launch_error
                            : static_cast<int>(work.admission));
    }
    if (report.runtime.phase == WorkRuntimePhase::Blocked)
      die("work remains blocked and owned", report.runtime.error);
    usleep(50000);
  }
}
}  // namespace
int main(int argc, char** argv) {
  int argument = 1;
  std::string endpoint = android::base::GetProperty("andrix.work.endpoint", "");
  if (argument < argc && !strcmp(argv[argument], "--endpoint")) {
    if (++argument == argc) die("missing endpoint");
    endpoint = argv[argument++];
  }
  if (argument == argc)
    die("usage: run|start [--cwd DIR] -- EXEC ARGS... | list | "
        "info|stop|wait|forget REFERENCE | "
        "request-info|stream-close REQUEST_REFERENCE");
  std::string operation = argv[argument++];
  if (operation == "list") {
    if (argument != argc) die("unexpected list arguments");
    Client management(endpoint);
    print(management.Call(WorkServiceOperation::List, {}));
    return 0;
  }
  if (operation == "request-info" || operation == "stream-close") {
    if (argument + 1 != argc) die("one exact request reference is required");
    auto reference = ParseWorkRequestReference(argv[argument]);
    if (!reference) die("invalid request reference");
    Client management(endpoint);
    if (management.identity != reference->service)
      die("stale request belongs to another environment");
    WorkServiceRequest request;
    request.stream = reference->stream;
    request.sequence = operation == "request-info" ? reference->sequence : 0;
    auto reply = management.Call(operation == "request-info"
                                     ? WorkServiceOperation::LookupRequest
                                     : WorkServiceOperation::CloseStream,
                                 request);
    print(reply, &*reference);
    // Pending/NotFound/Stale are observations, never an implicit new request.
    return reply.result == WorkRegistryResult::Accepted ||
                   reply.result == WorkRegistryResult::Existing
               ? 0
               : 1;
  }
  if (operation == "info" || operation == "stop" || operation == "wait" ||
      operation == "forget") {
    if (argument + 1 != argc) die("one exact work reference is required");
    auto work = parse(argv[argument]);
    Client controls(endpoint + ".ctl");
    bind(controls, work);
    if (operation == "wait") return wait(controls, work.serial, true);
    WorkServiceRequest request;
    request.serial = work.serial;
    auto reply =
        controls.Call(operation == "stop"     ? WorkServiceOperation::Stop
                      : operation == "forget" ? WorkServiceOperation::Forget
                                              : WorkServiceOperation::Inspect,
                      request);
    print(reply);
    return reply.result == WorkRegistryResult::Accepted ||
                   reply.result == WorkRegistryResult::Existing
               ? 0
               : 1;
  }
  if (operation != "run" && operation != "start") die("unknown operation");
  LaunchDescription launch;
  bool have_directory = false;
  uint32_t closed_stdio = 0;
  while (argument < argc && strcmp(argv[argument], "--")) {
    std::string option = argv[argument++];
    if (argument == argc) die("missing launch option value");
    if (option == "--cwd" && !have_directory) {
      launch.directory = argv[argument++];
      have_directory = true;
    } else if (option == "--closed-stdio") {
      const char* text = argv[argument++];
      const char* end = text + strlen(text);
      auto parsed = std::from_chars(text, end, closed_stdio);
      if (parsed.ec != std::errc{} || parsed.ptr != end || closed_stdio > 7)
        die("closed stdio mask must be 0..7");
    } else
      die("invalid launch option");
  }
  if (!have_directory) {
    char* current = getcwd(nullptr, 0);
    if (!current) die("working directory", errno);
    launch.directory = current;
    free(current);
  }
  if (argument == argc || strcmp(argv[argument++], "--") || argument == argc)
    die("explicit executable is required after --");
  launch.executable = argv[argument];
  while (argument < argc) launch.arguments.emplace_back(argv[argument++]);
  for (char** value = environ; value && *value; ++value)
    launch.environment.emplace_back(*value);
  LaunchFailure failure;
  unique_fd description(SealLaunch(launch, {}, failure));
  if (description < 0) die("ordinary launch description", failure.error);
  Client management(endpoint);
  auto stream_reply = management.Call(WorkServiceOperation::OpenStream, {});
  if (stream_reply.result != WorkRegistryResult::Accepted ||
      !stream_reply.stream)
    die("request stream capacity");
  WorkServiceRequest request;
  request.stream = stream_reply.stream;
  request.sequence = 1;
  // Volatile caller output, not a durable receipt. Attempt publication before
  // Reserve so a lost work identity can be queried without allocating again.
  // Closed/discarded stderr cannot promise recovery and is not a history store.
  auto request_reference =
      FormatWorkRequestReference({management.identity, request.stream, 1});
  dprintf(2, "andrix-work: request %s\n", request_reference.c_str());
  auto reserved = management.Call(WorkServiceOperation::Reserve, request);
  if ((reserved.result != WorkRegistryResult::Accepted &&
       reserved.result != WorkRegistryResult::Existing) ||
      !reserved.serial)
    die("work reservation", reserved.error);
  Reference work{management.identity, reserved.serial};
  dprintf(2, "andrix-work: reserved ");
  print_reference(2, work);
  dprintf(2, "\n");
  request.sequence = 0;
  management.Call(WorkServiceOperation::CloseStream, request);
  Client controls(endpoint + ".ctl");
  bind(controls, work);
  std::array<int, 4> descriptors{description.get(), -1, -1, -1};
  size_t count = 1;
  request = {};
  request.serial = work.serial;
  request.stdio_closed = closed_stdio;
  for (int fd = 0; fd < 3; ++fd) {
    if (closed_stdio & (1U << fd)) continue;
    if (fcntl(fd, F_GETFD) >= 0)
      descriptors[count++] = fd;
    else if (errno == EBADF)
      request.stdio_closed |= 1U << fd;
    else
      die("standard descriptor", errno);
  }
  auto prepared = management.Call(WorkServiceOperation::Prepare, request,
                                  {descriptors.data(), count});
  if (prepared.result != WorkRegistryResult::Accepted || !prepared.input)
    die("input preparation", prepared.error);
  request = {};
  request.serial = work.serial;
  request.input = prepared.input;
  auto started = management.Call(WorkServiceOperation::Start, request);
  if (started.result != WorkRegistryResult::Accepted &&
      started.result != WorkRegistryResult::Existing)
    die("work start", started.error);
  management.Close();
  description.reset();  // Acceptance is not tied to this connection.
  if (operation == "start") {
    dprintf(2, "andrix-work: ");
    print_reference(2, work);
    dprintf(2, "\n");
    return 0;  // Accepted work is not owned by this client's lifetime.
  }
  return wait(controls, work.serial, false);  // Initial exit is not scope Stop.
}
