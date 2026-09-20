// SPDX-License-Identifier: Apache-2.0
// Selected registry/service integration. Not the legacy Console endpoint.
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "guards.h"
#include "platform_lifecycle.h"
#include "service_handoff.h"
#include "work_channel.h"
#include "work_runtime.h"
#include "work_service_protocol.h"

using android::base::unique_fd;
using namespace andrix;
namespace {
constexpr size_t kRecords = 4, kManagementWorkers = 2, kControlWorkers = 4;
constexpr char kEndpointProperty[] = "andrix.work.endpoint";
[[noreturn]] void fail(const char* reason) {
  LOG(ERROR) << "work manager refused: " << reason << " errno=" << errno;
  _exit(125);
}
void require(bool condition, const char* reason) {
  if (!condition) fail(reason);
}
uint64_t now() {
  timespec value{};
  require(!clock_gettime(CLOCK_MONOTONIC, &value), "clock");
  return uint64_t(value.tv_sec) * 1000 + uint64_t(value.tv_nsec) / 1000000;
}
int inherited(const char* name) {
  const char* text = getenv(name);
  if (!text) return -1;
  int fd = -1;
  auto parsed = std::from_chars(text, text + strlen(text), fd);
  return parsed.ec == std::errc{} && !*parsed.ptr && fd >= 3 && fd < 128 ? fd
                                                                         : -1;
}
std::string read_at(int directory, const char* name) {
  unique_fd fd(openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd < 0) return {};
  char bytes[128];
  ssize_t count = read(fd.get(), bytes, sizeof(bytes));
  if (count <= 0 || count == sizeof(bytes)) return {};
  std::string result(bytes, count);
  while (!result.empty() && result.back() == '\n') result.pop_back();
  return result;
}
class AndroidAuthority final : public WorkRuntimeAuthority {
 public:
  PlatformLifecycle platform;
  AdmissionResult Admit(const std::shared_ptr<WorkAdmission>& gate) override {
    return platform.admit_work(gate);
  }
  AdmissionResult Prepared(
      const std::shared_ptr<WorkAdmission>& gate) override {
    return platform.prepare_work(gate);
  }
  AdmissionResult Release(const std::shared_ptr<WorkAdmission>& gate) override {
    return platform.release_work(gate);
  }
  AdmissionResult Retire(const std::shared_ptr<WorkAdmission>& gate) override {
    return platform.retire_work(gate);
  }
};
struct Server {
  Server(WorkServiceIdentity identity, WorkRuntimeConfig runtime,
         std::shared_ptr<AndroidAuthority> authority)
      : identity(identity),
        catalog(identity.manager,
                {kRecords, 32, 2, {}, UINT64_MAX, UINT64_MAX, UINT64_MAX}),
        runtime(std::move(runtime), authority),
        authority(std::move(authority)) {}
  const WorkServiceIdentity identity;
  WorkCatalog catalog;
  WorkRuntime runtime;
  const std::shared_ptr<AndroidAuthority> authority;
};
unique_fd listener(const std::string& name) {
  require(name.size() + 1 < sizeof(sockaddr_un{}.sun_path), "endpoint name");
  require(!setsockcreatecon("u:object_r:andrix_work_api_socket:s0"),
          "public socket label");
  unique_fd socket_fd(
      socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  int socket_error = errno;
  require(!setsockcreatecon(nullptr), "restore socket label");
  errno = socket_error;
  require(socket_fd >= 0 && !ConfigureWorkPeerSocket(socket_fd.get()),
          "public socket");
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, name.data(), name.size());
  require(!bind(socket_fd.get(), reinterpret_cast<sockaddr*>(&address),
                offsetof(sockaddr_un, sun_path) + name.size() + 1) &&
              !listen(socket_fd.get(), 8),
          "public listener");
  return socket_fd;
}
void add_report(Server& server, const WorkHandle& work,
                WorkServiceReply& reply) {
  if (work)
    reply.works.push_back(
        {work.Inspect(), server.runtime.Inspect(work.identity())});
}
bool send_reply(int socket, WorkFrameHeader header,
                const WorkServiceReply& reply) {
  auto bytes = EncodeWorkServiceReply(reply);
  if (bytes.empty()) return false;
  header.kind = WorkFrameKind::Reply;
  const uint64_t issued = now();
  for (;;) {
    int error = SendWorkFrame(socket, header, bytes);
    if (!error) return true;
    if (error != EAGAIN && error != EINTR) return false;
    if (now() - issued >= 3000) return false;
    pollfd wait{socket, POLLOUT, 0};
    if (poll(&wait, 1, 20) < 0 && errno != EINTR) return false;
  }
}
void connection(Server& server, unique_fd socket, bool control_only) {
  int peer_error;
  auto peer = AuthorizedWorkPeer::Capture(socket.get(), WorkPeerSide::Manager,
                                          peer_error);
  if (!peer) return;
  WorkHandle bound;
  std::vector<WorkHandle> reservations;
  reservations.reserve(kRecords);
  uint64_t last_request = now();
  bool greeting = false;
  WorkFrame frame;
  for (;;) {
    int error = ReceiveAuthorizedWorkFrame(socket.get(), *peer, frame);
    if (error == EAGAIN || error == EINTR) {
      const uint64_t timeout = bound ? 180000 : 10000;
      if (now() - last_request >= timeout) break;
      pollfd wait{socket.get(), POLLIN, 0};
      if (poll(&wait, 1, 100) < 0 && errno != EINTR) break;
      continue;
    }
    if (error) break;
    last_request = now();
    WorkServiceRequest request;
    auto operation =
        static_cast<WorkServiceOperation>(frame.header().operation);
    if (!DecodeWorkServiceRequest(frame.body(), request) ||
        !ValidWorkServiceRequest(operation, request, frame.descriptor_count()))
      break;
    WorkServiceReply reply;
    reply.service = server.identity;
    reply.result = WorkRegistryResult::Accepted;
    if (operation == WorkServiceOperation::Hello) {
      if (greeting || bound) break;
      greeting = true;
    } else if (!greeting || request.service != server.identity) {
      reply.result = WorkRegistryResult::Stale;
    } else if (control_only) {
      if (operation == WorkServiceOperation::Bind &&
          (!bound || bound.identity().serial == request.serial)) {
        if (!bound)
          bound =
              server.catalog.Find({server.identity.manager, request.serial});
        if (!bound) reply.result = WorkRegistryResult::Stale;
      } else if (!bound || bound.identity().serial != request.serial) {
        reply.result = WorkRegistryResult::Foreign;
      } else if (operation == WorkServiceOperation::Stop) {
        bound.Stop();  // No registry lookup, admission, FD import or writer
                       // lock.
      } else if (operation == WorkServiceOperation::Forget) {
        reply.result = server.catalog.Forget(bound);
      } else if (operation != WorkServiceOperation::Inspect) {
        reply.result = WorkRegistryResult::WrongState;
      }
      reply.serial = request.serial;
      add_report(server, bound, reply);
    } else {
      if (operation == WorkServiceOperation::OpenStream) {
        reply.stream = server.catalog.OpenStream();
        if (!reply.stream) reply.result = WorkRegistryResult::Capacity;
      } else if (operation == WorkServiceOperation::CloseStream) {
        if (!server.catalog.CloseStream(request.stream))
          reply.result = WorkRegistryResult::Stale;
      } else if (operation == WorkServiceOperation::Reserve) {
        auto reserved =
            server.catalog.Reserve(request.stream, request.sequence);
        reply.result = reserved.result;
        reply.serial = reserved.identity.serial;
        reply.error = reserved.error;
        if (reserved.work) {
          bool known = false;
          for (const auto& work : reservations)
            known |= work.identity() == reserved.work.identity();
          if (!known) {
            if (reservations.size() == kRecords) {
              reserved.work.CancelUnstarted();
              server.catalog.CancelInputs(reserved.work);
            } else
              reservations.push_back(reserved.work);
          }
          add_report(server, reserved.work, reply);
        }
      } else if (operation == WorkServiceOperation::List) {
        for (auto& item : server.catalog.List())
          reply.works.push_back({item, server.runtime.Inspect(item.work.work)});
      } else if (operation == WorkServiceOperation::Prepare ||
                 operation == WorkServiceOperation::Start) {
        // An unaccepted management reservation belongs to this conversation.
        // Client loss can cancel it, never an already accepted work.
        WorkHandle work;
        for (const auto& candidate : reservations)
          if (candidate.identity().serial == request.serial) {
            work = candidate;
            break;
          }
        if (!work)
          reply.result = WorkRegistryResult::Foreign;
        else if (operation == WorkServiceOperation::Prepare) {
          unique_fd description(frame.Take(0));
          std::array<unique_fd, 3> received;
          std::array<int, 3> standard{-1, -1, -1};
          size_t next = 1;
          for (size_t index = 0; index < 3; ++index)
            if (!(request.stdio_closed & (1U << index))) {
              received[index].reset(frame.Take(next++));
              standard[index] = received[index].get();
            }
          auto prepared =
              server.catalog.Prepare(work, description.get(), standard);
          reply.result = prepared.result;
          reply.input = prepared.identity.serial;
          reply.error = prepared.error;
        } else {
          auto started = server.catalog.Start(
              work, {server.identity.manager, request.input});
          reply.result = started.result;
          if (started.backend) {
            int submit_error;
            if (!server.runtime.Submit(started, submit_error)) {
              started.backend.Abort(submit_error);
              started.stdio_lease.Release();
              started.backend.AdmissionFinished(AdmissionResult::Stopped);
              reply.error = submit_error;
            }
          }
        }
        reply.serial = request.serial;
        add_report(server, work, reply);
      } else
        reply.result = WorkRegistryResult::WrongState;
    }
    if (!send_reply(socket.get(), frame.header(), reply)) break;
    // Fast Stop acknowledgement precedes any last-close/cancellation wait.
    if (control_only && bound && operation == WorkServiceOperation::Stop)
      server.catalog.CancelInputs(bound);
    frame.Reset();
  }
  frame.Reset();
  // Do not retain a prepared writer after its submitting client disappears.
  // This races Start through the registry's exact unstarted cancellation, not
  // an unlocked snapshot of start_accepted. Accepted work survives disconnect.
  for (const auto& work : reservations)
    if (work.CancelUnstarted()) server.catalog.CancelInputs(work);
}
void accept_loop(Server* server, int listener_fd, bool controls) {
  for (;;) {
    unique_fd socket(
        accept4(listener_fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
    if (socket >= 0) {
      connection(*server, std::move(socket), controls);
      continue;
    }
    if (errno != EAGAIN && errno != EINTR) {
      timespec delay{0, 100000000};
      nanosleep(&delay, nullptr);
    }
    pollfd wait{listener_fd, POLLIN, 0};
    poll(&wait, 1, -1);
  }
}
}  // namespace
int main(int argc, char** argv) {
  android::base::InitLogging(argv,
                             android::base::LogdLogger(android::base::SYSTEM));
  require(argc == 1 && getppid() == 1 && check_identity().empty(),
          "fixed bootstrap identity");
  unique_fd aggregate(inherited("ANDROID_DELEGATED_ROOT_FD")),
      ready(inherited("ANDROID_DELEGATED_READY_FD"));
  require(aggregate >= 0 && ready >= 0, "generic handoff");
  require(fcntl(aggregate.get(), F_SETFD, FD_CLOEXEC) == 0 &&
              fcntl(ready.get(), F_SETFD, FD_CLOEXEC) == 0,
          "handoff cloexec");
  WorkServiceIdentity identity;
  const char* reference = getenv("ANDROID_DELEGATED_INSTANCE");
  const char* dot = reference ? strchr(reference, '.') : nullptr;
  require(dot != nullptr, "generic instance");
  const char* end = reference + strlen(reference);
  auto first = std::from_chars(reference, dot, identity.boot),
       second = std::from_chars(dot + 1, end, identity.environment);
  require(first.ec == std::errc{} && first.ptr == dot &&
              second.ec == std::errc{} && second.ptr == end && identity.boot &&
              identity.environment,
          "generic instance encoding");
  require(getrandom(&identity.manager, sizeof(identity.manager), 0) ==
                  sizeof(identity.manager) &&
              identity.manager,
          "manager incarnation");
  struct stat metadata{};
  struct statfs filesystem{};
  require(!fstat(aggregate.get(), &metadata) &&
              !fstatfs(aggregate.get(), &filesystem) &&
              filesystem.f_type == CGROUP2_SUPER_MAGIC &&
              metadata.st_uid == 0 && metadata.st_gid == 0,
          "protected aggregate");
  require(read_at(aggregate.get(), "memory.max") == "268435456" &&
              read_at(aggregate.get(), "memory.swap.max") == "0" &&
              read_at(aggregate.get(), "memory.oom.group") == "1",
          "aggregate limits");
  unique_fd work_namespace(
      openat(aggregate.get(), "work",
             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  require(work_namespace >= 0, "work namespace");
  ABinderProcess_setThreadPoolMaxThreadCount(1);
  ABinderProcess_startThreadPool();
  auto authority = std::make_shared<AndroidAuthority>();
  require(authority->platform.start(), "genuine lifecycle adapter");
  WorkRuntimeConfig runtime;
  runtime.jobs = kRecords;
  runtime.aggregate = aggregate.get();
  runtime.work_namespace = work_namespace.get();
  runtime.aggregate_identity = {static_cast<uint64_t>(metadata.st_dev),
                                static_cast<uint64_t>(metadata.st_ino)};
  runtime.launcher = "/system_ext/bin/andrix-work-launcher";
  runtime.cleanup = {8, 64, 512, 4096, 32};
  auto* server =
      new Server(identity, runtime,
                 authority);  // Process lifetime, never reconstructed in place.
  require(server->catalog.valid() && server->runtime.valid(),
          "bounded service components");
  std::string endpoint = "andrix.work." + std::to_string(identity.boot) + "." +
                         std::to_string(identity.environment) + "." +
                         std::to_string(identity.manager);
  unique_fd management = listener(endpoint),
            controls = listener(endpoint + ".ctl");
  for (size_t index = 0; index < kManagementWorkers; ++index)
    std::thread(accept_loop, server, management.get(), false).detach();
  for (size_t index = 0; index < kControlWorkers; ++index)
    std::thread(accept_loop, server, controls.get(), true).detach();
  std::thread([server] {
    for (;;) {
      server->runtime.Poll();
      server->catalog.Collect();
      usleep(20000);
    }
  }).detach();
  require(android::base::SetProperty(kEndpointProperty, endpoint),
          "publish protected locator");
  supervision::ServiceReadyMessage receipt;
  receipt.boot = identity.boot;
  receipt.instance = identity.environment;
  receipt.device = runtime.aggregate_identity.device;
  receipt.inode = runtime.aggregate_identity.inode;
  require(send(ready.get(), &receipt, sizeof(receipt), MSG_NOSIGNAL) ==
              sizeof(receipt),
          "generic readiness");
  ready.reset();
  for (;;) {
    // The real adapter already closes original gates on failure. Do not wait
    // for any input read, recorder, client or work kernel worker. Android owns
    // complete enclosing retirement before a replacement can activate.
    if (authority->platform.failed()) _exit(0);
    usleep(20000);
  }
}
