// SPDX-License-Identifier: Apache-2.0
#include "work_io.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <barrier>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "work_registry.h"

using namespace andrix;
using I = WorkIoResult;
namespace {
size_t count_fds() {
  DIR* directory = opendir("/proc/self/fd");
  assert(directory);
  size_t count = 0;
  while (auto* item = readdir(directory))
    if (item->d_name[0] != '.') ++count;
  assert(closedir(directory) == 0);
  return count;
}
WorkIoBinding capture(WorkIoPool& pool, const std::array<int, 3>& fds) {
  auto ticket = pool.Reserve();
  assert(ticket.result == I::Accepted && ticket.reservation);
  auto result = pool.Capture(ticket.reservation, fds);
  assert(result.result == I::Accepted && result.binding);
  return result.binding;
}
void descriptors_and_pinned_capacity() {
  int input[2], output[2];
  assert(pipe2(input, O_CLOEXEC | O_NONBLOCK) == 0 &&
         pipe2(output, O_CLOEXEC | O_NONBLOCK) == 0);
  const int input_flags = fcntl(input[0], F_GETFL),
            output_flags = fcntl(output[1], F_GETFL);
  const size_t before = count_fds();
  WorkIoPool pool(1, 1, UINT64_MAX);
  auto ticket = pool.Reserve();
  assert(pool.usage().pending == 1 && pool.Reserve().result == I::Capacity);
  auto result =
      pool.Capture(ticket.reservation, {input[0], output[1], output[1]});
  auto binding = result.binding;
  result.binding = {};
  auto lease = pool.Lease(binding);
  assert(lease.available());
  assert(binding && binding.identity() == (WorkIoIdentity{1, 1}));
  assert(count_fds() == before + 3);
  for (size_t i = 0; i < 3; ++i) {
    assert(lease.descriptor(i) >= 3 &&
           (fcntl(lease.descriptor(i), F_GETFD) & FD_CLOEXEC));
    assert(fcntl(lease.descriptor(i), F_GETFL) ==
           (i ? output_flags : input_flags));
  }
  assert(lease.descriptor(1) != lease.descriptor(2));
  assert(fcntl(input[0], F_GETFL) == input_flags &&
         fcntl(output[1], F_GETFL) == output_flags);
  assert(write(input[1], "a\0b", 3) == 3);
  char data[8]{};
  assert(read(lease.descriptor(0), data, sizeof(data)) == 3 &&
         memcmp(data, "a\0b", 3) == 0);
  assert(write(lease.descriptor(1), "one", 3) == 3);
  assert(write(lease.descriptor(2), "two", 3) == 3);
  assert(read(output[0], data, sizeof(data)) == 6 &&
         memcmp(data, "onetwo", 6) == 0);
  int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(null >= 0);
  assert(dup2(null, input[0]) == input[0]);  // Reuse the caller's FD number.
  close(null);
  assert(write(input[1], "old", 3) == 3);
  assert(read(lease.descriptor(0), data, sizeof(data)) == 3 &&
         memcmp(data, "old", 3) == 0);
  auto existing = pool.Capture(ticket.reservation, {-2, -2, -2});
  assert(existing.result == I::Existing &&
         existing.binding == binding);  // No replacement capture.
  existing.binding = {};
  assert(pool.Find(binding.identity()) == binding);
  assert(pool.Forget(binding) && !pool.Find(binding.identity()));
  assert(pool.Reserve().result == I::Capacity);
  assert(pool.FindReference(binding.identity()) == binding);
  assert(!pool.Lease(binding).available());
  lease.Release();
  assert(count_fds() == before);  // Identity retention no longer holds FDs.
  assert(pool.Reserve().result == I::Capacity);
  lease = {};
  binding = {};
  auto next = pool.Reserve();
  assert(next.result == I::Accepted && next.reservation.identity().serial == 2);
  assert(count_fds() == before);
  assert(pool.Capture(ticket.reservation, {-1, -1, -1}).result == I::Stale);
  assert(pool.Cancel(next.reservation));
  assert(
      pool.Capture(next.reservation, {input[0], output[1], output[1]}).result ==
      I::Closed);
  assert(count_fds() == before);
  for (int fd : {input[0], input[1], output[0], output[1]}) close(fd);
}
void invalid_modes_and_close() {
  WorkIoPool pool(1, 1, 20);
  int read_only = open("/dev/null", O_RDONLY | O_CLOEXEC);
  int write_only = open("/dev/null", O_WRONLY | O_CLOEXEC);
  int path = open("/dev/null", O_PATH | O_CLOEXEC);
  assert(read_only >= 0 && write_only >= 0 && path >= 0);
  const size_t before = count_fds();
  for (const auto& fds :
       {std::array<int, 3>{write_only, write_only, write_only},
        std::array<int, 3>{read_only, read_only, write_only},
        std::array<int, 3>{read_only, write_only, -2},
        std::array<int, 3>{path, write_only, write_only}}) {
    auto ticket = pool.Reserve();
    assert(ticket.result == I::Accepted);
    auto result = pool.Capture(ticket.reservation, fds);
    assert(result.result == I::Io && !result.binding && result.error);
    assert(pool.usage().pending == 0 && count_fds() == before);
  }
  auto closed = capture(pool, {-1, -1, -1});
  auto closed_lease = pool.Lease(closed);
  assert(closed_lease.available() && !closed.closed_plan() &&
         closed_lease.descriptor(0) == -1 && closed_lease.descriptor(2) == -1);
  assert(closed != WorkIoBinding::Closed());  // Distinct accepted binding, even
                                              // if equivalent I/O.
  pool.Close();
  assert(pool.Reserve().result == I::Closed);
  assert(!pool.Find(closed.identity()) &&
         pool.FindReference(closed.identity()) == closed);
  assert(closed_lease.available() && !pool.Lease(closed).available());
  assert(!pool.Forget(WorkIoBinding::Closed()));
  WorkIoPool foreign(2, 1, 10);
  assert(!foreign.Forget(closed));
  auto pending = foreign.Reserve();
  assert(pool.Capture(pending.reservation, {-1, -1, -1}).result == I::Foreign);
  assert(!pool.Cancel(pending.reservation));
  foreign.Close();
  assert(foreign.Capture(pending.reservation, {-1, -1, -1}).result ==
         I::Closed);
  WorkIoPool exhausted(3, 1, 0);
  assert(exhausted.Reserve().result == I::Exhausted);
  WorkIoPool invalid(0, 1, 10);
  assert(invalid.Reserve().result == I::Closed);
  close(read_only);
  close(write_only);
  close(path);
}
std::vector<uint8_t> description() {
  std::vector<uint8_t> bytes;
  LaunchFailure failure;
  assert(EncodeLaunch({"/owner/program", {"program"}, {"X=1"}, "/owner"}, {},
                      bytes, failure));
  return bytes;
}
WorkControl reserve_work(WorkRegistry& registry,
                         const WorkRequestStream& stream, uint64_t sequence) {
  auto pending = registry.Reserve(stream, sequence);
  assert(pending.result == WorkRegistryResult::Accepted);
  int error;
  auto gate = WorkAdmission::Reserve(pending.work, error);
  auto done = registry.ReservationFinished(pending.allocation, std::move(gate));
  assert(done.result == WorkRegistryResult::Accepted);
  return done.control;
}
void immutable_start_binding() {
  WorkRegistry registry(7, {2, 1, 1, {}, UINT64_MAX, UINT64_MAX, UINT64_MAX});
  auto stream = registry.OpenStream();
  auto control = reserve_work(registry, stream, 1);
  WorkIoPool pool(7, 2, 20), alias_pool(7, 1, 20), foreign(8, 1, 20);
  // Separate opens have equal inode/device metadata but separate OFDs.
  const char* temporary = getenv("TMPDIR");
  std::string path =
      std::string(temporary ? temporary : "/tmp") + "/andrix-io-XXXXXX";
  std::vector<char> name(path.begin(), path.end());
  name.push_back('\0');
  int first = mkstemp(name.data());
  assert(first >= 0 && write(first, "abcdef", 6) == 6);
  int second = open(name.data(), O_RDWR | O_CLOEXEC);
  assert(second >= 0 && unlink(name.data()) == 0);
  struct stat a{}, b{};
  assert(fstat(first, &a) == 0 && fstat(second, &b) == 0 &&
         a.st_dev == b.st_dev && a.st_ino == b.st_ino);
  assert(lseek(first, 0, SEEK_SET) == 0 && lseek(second, 3, SEEK_SET) == 3);
  auto original = capture(pool, {first, first, first});
  auto different = capture(pool, {second, second, second});
  auto numeric_alias = capture(alias_pool, {second, second, second});
  auto other_manager = capture(foreign, {-1, -1, -1});
  assert(numeric_alias.identity() == original.identity() &&
         numeric_alias != original);
  assert(registry.Start(control, description(), {}).result ==
         WorkRegistryResult::Invalid);
  assert(registry.Start(control, description(), foreign.Lease(other_manager))
             .result == WorkRegistryResult::Foreign);
  auto start = registry.Start(control, description(), pool.Lease(original));
  assert(start.result == WorkRegistryResult::Accepted &&
         start.backend.stdio() == original);
  assert(control.Inspect().stdio == original.identity() &&
         control.Inspect().stdio_configured &&
         !control.Inspect().stdio_closed_plan);
  assert(registry.Start(control, description(), pool.Lease(original)).result ==
         WorkRegistryResult::Existing);
  assert(registry.Start(control, description(), pool.Lease(different)).result ==
         WorkRegistryResult::Conflict);
  assert(registry.Start(control, description(), alias_pool.Lease(numeric_alias))
             .result == WorkRegistryResult::Conflict);
  assert(registry.Start(control, description()).result ==
         WorkRegistryResult::Conflict);
  assert(pool.Forget(original) && !pool.Find(original.identity()));
  assert(!pool.Lease(original).available());
  assert(registry.Start(control, description(), pool.Lease(original)).result ==
         WorkRegistryResult::Existing);
  original = {};
  assert(pool.Reserve().result ==
         I::Capacity);  // Work and backend pin the actual binding.
  char c;
  assert(read(start.stdio_lease.descriptor(0), &c, 1) == 1 && c == 'a');
  auto different_lease = pool.Lease(different);
  assert(read(different_lease.descriptor(0), &c, 1) == 1 && c == 'd');
  start.stdio_lease.Release();
  assert(!start.stdio_lease.available());
  control.Stop();
  assert(!start.backend.AdmissionFinished(AdmissionResult::Stopped));
  assert(registry.Forget(control) == WorkRegistryResult::Accepted);
  start.backend = {};
  start.stdio_lease = {};
  control = {};
  auto next_work = reserve_work(registry, stream,
                                2);  // Retires identity, not stream resources.
  assert(pool.Reserve().result == I::Accepted);
  assert(!next_work.Inspect().stdio_configured);
  close(first);
  close(second);
}
void metadata_does_not_hold_pipe_writer() {
  for (bool handoff : {false, true}) {
    int pipefd[2];
    assert(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
    WorkIoPool pool(9, 1, 10);
    auto binding = capture(pool, {-1, pipefd[1], -1});
    WorkRegistry registry(9, {2, 1, 1, {}, 10, 10, 10});
    auto stream = registry.OpenStream();
    auto control = reserve_work(registry, stream, 1);
    auto start = registry.Start(control, description(), pool.Lease(binding));
    assert(start.backend && start.stdio_lease.available());
    close(pipefd[1]);
    assert(pool.Forget(binding) && !pool.Find(binding.identity()));
    assert(pool.FindReference(binding.identity()) == binding);
    auto reference = pool.Lease(binding);
    assert(!reference.available() && reference.binding() == binding);
    auto again = registry.Start(control, description(), reference);
    assert(again.result == WorkRegistryResult::Existing && !again.backend &&
           !again.stdio_lease.available());
    auto other_work = reserve_work(registry, stream, 2);
    assert(registry.Start(other_work, description(), reference).result ==
           WorkRegistryResult::Closed);
    char byte;
    assert(read(pipefd[0], &byte, 1) == -1 &&
           errno == EAGAIN);  // Creator owns the writer.
    int recipient = -1;
    if (handoff) {
      recipient = fcntl(start.stdio_lease.descriptor(1), F_DUPFD_CLOEXEC, 3);
      assert(recipient >= 0);
    }
    start.stdio_lease.Release();
    if (handoff) {
      assert(read(pipefd[0], &byte, 1) == -1 && errno == EAGAIN);
      close(recipient);  // Actual recipient ownership ends independently.
    }
    assert(read(pipefd[0], &byte, 1) == 0);
    assert(start.backend.stdio() == binding &&
           pool.Reserve().result == I::Capacity);
    control.Stop();
    assert(!start.backend.AdmissionFinished(AdmissionResult::Stopped));
    assert(control.Inspect().complete && read(pipefd[0], &byte, 1) == 0);
    // Keep all of the completed work/control/input metadata until scope exit.
    assert(registry.Start(control, description(), reference).result ==
           WorkRegistryResult::Existing);
    close(pipefd[0]);
  }
}
void duplicate_capture_races() {
  int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  assert(fd >= 0);
  const size_t before = count_fds();
  for (size_t i = 0; i < 200; ++i) {
    WorkIoPool pool(1, 1, 3);
    auto ticket = pool.Reserve();
    std::array<WorkIoReply, 2> results;
    std::barrier ready(2);
    std::thread first([&] {
      ready.arrive_and_wait();
      results[0] = pool.Capture(ticket.reservation, {fd, fd, fd});
    });
    ready.arrive_and_wait();
    results[1] = pool.Capture(ticket.reservation, {fd, fd, fd});
    first.join();
    assert((results[0].result == I::Accepted) !=
           (results[1].result == I::Accepted));
    for (const auto& result : results)
      assert(result.result == I::Accepted || result.result == I::Existing ||
             result.result == I::Pending);
    assert(count_fds() == before + 3);
    auto completed = pool.Capture(ticket.reservation, {-2, -2, -2});
    assert(completed.result == I::Existing && completed.binding);
    assert(pool.Forget(completed.binding));
    assert(count_fds() ==
           before);  // Even all three metadata replies retain no FDs.
  }
  close(fd);
}
void capture_cancel_races() {
  int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  assert(fd >= 0);
  const size_t before = count_fds();
  for (size_t i = 0; i < 200; ++i) {
    WorkIoPool pool(1, 1, 3);
    auto ticket = pool.Reserve();
    WorkIoReply outcome;
    std::barrier ready(2);
    std::thread importer([&] {
      ready.arrive_and_wait();
      outcome = pool.Capture(ticket.reservation, {fd, fd, fd});
    });
    ready.arrive_and_wait();
    pool.Cancel(ticket.reservation);
    importer.join();
    assert(pool.usage().pending == 0);
    if (outcome.result == I::Accepted) {
      assert(pool.Forget(outcome.binding));
      outcome.binding = {};
    } else
      assert(outcome.result == I::Closed);
    auto next = pool.Reserve();
    assert(next.result == I::Accepted &&
           next.reservation.identity().serial == 2);
    assert(count_fds() == before);
  }
  close(fd);
}
}  // namespace
int main() {
  alarm(30);
  const size_t before = count_fds();
  descriptors_and_pinned_capacity();
  invalid_modes_and_close();
  immutable_start_binding();
  metadata_does_not_hold_pipe_writer();
  duplicate_capture_races();
  capture_cancel_races();
  assert(count_fds() == before);
  puts(
      "{\"retained_OFDs_not_numeric_FDs\":true,\"Start_matches_actual_"
      "binding\":true,\"metadata_does_not_suppress_EOF\":true,"
      "\"mutable_Unix_offsets_preserved\":true,\"finite_duplicate_import_"
      "races\":200,"
      "\"finite_capture_"
      "cancel_races\":200,\"Android_MAC_or_real_work_backend_qualified\":"
      "false}");
}
