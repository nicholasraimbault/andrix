// SPDX-License-Identifier: Apache-2.0
#include "work_catalog.h"

#include <fcntl.h>
#include <unistd.h>

#include <barrier>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <thread>

#include "work_service_protocol.h"

using namespace andrix;
using R = WorkRegistryResult;
namespace {
WorkRegistryLimits limits(size_t records = 4) {
  return {records, 4,    records > 1 ? size_t{2} : size_t{1}, {}, 10000,
          10000,   10000};
}
int description(const char* name = "ordinary") {
  LaunchDescription launch{
      "/owner/program", {name, "one argument"}, {"X=1", "X=2"}, "/owner"};
  LaunchFailure failure;
  int fd = SealLaunch(launch, {}, failure);
  assert(fd >= 0);
  return fd;
}
WorkHandle reserve(WorkCatalog& catalog, uint64_t stream, uint64_t sequence) {
  auto reply = catalog.Reserve(stream, sequence);
  if (reply.result != R::Accepted || !reply.work)
    fprintf(stderr,
            "reserve failed stream=%llu sequence=%llu result=%u error=%d "
            "records=%zu\n",
            static_cast<unsigned long long>(stream),
            static_cast<unsigned long long>(sequence),
            static_cast<unsigned>(reply.result), reply.error,
            catalog.usage().records);
  assert(reply.result == R::Accepted && reply.work);
  return reply.work;
}
void preparation_and_consumption() {
  WorkCatalog catalog(7, limits(2));
  auto stream = catalog.OpenStream();
  assert(stream);
  auto work = reserve(catalog, stream, 1);
  auto again = catalog.Reserve(stream, 1);
  assert(again.result == R::Existing && again.identity == work.identity());
  int pipefd[2];
  assert(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
  int sealed = description();
  auto input = catalog.Prepare(work, sealed, {-1, pipefd[1], -1});
  assert(input.result == R::Accepted && input.identity.serial);
  assert(catalog.Prepare(work, -1, {-2, -2, -2}).result == R::Conflict);
  close(sealed);
  close(pipefd[1]);
  assert(work.Inspect().inputs == WorkInputState::Ready);
  assert(catalog.Start(work, {7, input.identity.serial + 1}).result ==
         R::Conflict);
  auto start = catalog.Start(work, input.identity);
  assert(start.result == R::Accepted && start.backend &&
         start.stdio_lease.available());
  assert(work.Inspect().inputs == WorkInputState::Consumed);
  assert(!work.CancelUnstarted());  // Client loss never stops accepted work.
  assert(!work.Inspect().work.entry_gate_closed);
  auto retry = catalog.Start(work, input.identity);
  assert(retry.result == R::Existing && !retry.backend &&
         !retry.stdio_lease.available());
  char byte;
  assert(read(pipefd[0], &byte, 1) == -1 && errno == EAGAIN);
  start.stdio_lease.Release();
  assert(read(pipefd[0], &byte, 1) ==
         0);  // No explicit input Forget by the client.
  assert(catalog.CloseStream(stream));
  work.Stop();
  assert(!start.backend.AdmissionFinished(AdmissionResult::Stopped));
  assert(catalog.Forget(work) == R::Accepted && !catalog.Find(work.identity()));
  auto old = work.identity();
  start = {};
  retry = {};
  again = {};
  work = {};
  catalog.Collect();
  auto second_stream = catalog.OpenStream();
  auto replacement = reserve(catalog, second_stream, 1);
  assert(replacement.identity() != old &&
         !replacement.Inspect().work.entry_gate_closed);
  assert(catalog.List().size() == 1);
  close(pipefd[0]);
}
void cancellation_and_foreign_handles() {
  WorkCatalog catalog(1, limits()), foreign(2, limits());
  auto work = reserve(catalog, catalog.OpenStream(), 1);
  assert(work.CancelUnstarted());
  assert(work.Inspect().work.complete &&
         work.Inspect().work.stop_sources ==
             static_cast<uint32_t>(WorkStopSource::Manager));
  assert(catalog.Prepare(work, -2, {-2, -2, -2}).result == R::Closed);
  assert(catalog.CancelInputs(work).state == WorkInputState::Rejected);
  assert(foreign.Prepare(work, -2, {-2, -2, -2}).result == R::Foreign);
  assert(foreign.Forget(work) == R::Foreign);
  assert(catalog.Forget(work) == R::Accepted);
  auto second = reserve(catalog, catalog.OpenStream(), 1);
  int data = open("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(data >= 0);
  auto rejected = catalog.Prepare(second, data, {-1, -1, -1});
  assert(rejected.result == R::Invalid &&
         rejected.state == WorkInputState::Rejected);
  assert(catalog.Prepare(second, data, {-1, -1, -1}).result == R::Conflict);
  second.Stop();
  assert(catalog.Forget(second) == R::Accepted);
  close(data);
}
void prepare_stop_races() {
  int sealed = description();
  for (size_t n = 0; n < 100; ++n) {
    WorkCatalog catalog(1, limits(1));
    auto work = reserve(catalog, catalog.OpenStream(), 1);
    int pipefd[2];
    assert(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
    WorkInputReply result;
    std::barrier ready(2);
    std::thread prepare([&] {
      ready.arrive_and_wait();
      result = catalog.Prepare(work, sealed, {-1, pipefd[1], -1});
    });
    ready.arrive_and_wait();
    work.Stop();
    catalog.CancelInputs(work);
    prepare.join();
    catalog.CancelInputs(work);
    assert(work.Inspect().work.complete &&
           work.Inspect().inputs == WorkInputState::Rejected);
    close(pipefd[1]);
    char byte;
    assert(read(pipefd[0], &byte, 1) == 0);
    close(pipefd[0]);
    assert(catalog.Forget(work) == R::Accepted);
  }
  close(sealed);
}
void start_disconnect_races() {
  int sealed = description();
  for (size_t n = 0; n < 100; ++n) {
    WorkCatalog catalog(1, limits(1));
    auto work = reserve(catalog, catalog.OpenStream(), 1);
    auto input = catalog.Prepare(work, sealed, {-1, -1, -1});
    assert(input.result == R::Accepted);
    std::barrier ready(2);
    WorkStartReply reply;
    std::thread start([&] {
      ready.arrive_and_wait();
      reply = catalog.Start(work, input.identity);
    });
    ready.arrive_and_wait();
    bool cancelled = work.CancelUnstarted();
    if (cancelled) catalog.CancelInputs(work);
    start.join();
    if (cancelled) {
      assert(!reply.backend &&
             (reply.result == R::Closed || reply.result == R::WrongState));
      assert(!work.Inspect().work.start_accepted);
    } else {
      assert(reply.result == R::Accepted && reply.backend &&
             !work.Inspect().work.entry_gate_closed);
      work.Stop();
      reply.stdio_lease.Release();
      assert(!reply.backend.AdmissionFinished(AdmissionResult::Stopped));
    }
    assert(work.Inspect().work.complete);
  }
  close(sealed);
}
void wire_codec() {
  WorkServiceRequest request;
  auto bytes = EncodeWorkServiceRequest(request);
  WorkServiceRequest received;
  assert(bytes.size() == kWorkServiceRequestBytes &&
         DecodeWorkServiceRequest(bytes, received));
  assert(ValidWorkServiceRequest(WorkServiceOperation::Hello, received, 0));
  request.service = {10, 20, 30};
  request.serial = 1;
  for (uint32_t mask = 0; mask < 8; ++mask) {
    request.stdio_closed = mask;
    bytes = EncodeWorkServiceRequest(request);
    assert(DecodeWorkServiceRequest(bytes, received) &&
           received.stdio_closed == mask);
    size_t open = 0;
    for (unsigned n = 0; n < 3; ++n) open += !(mask & (1U << n));
    assert(ValidWorkServiceRequest(WorkServiceOperation::Prepare, received,
                                   open + 1));
    assert(!ValidWorkServiceRequest(WorkServiceOperation::Prepare, received,
                                    open));
  }
  bytes.back() = 1;
  assert(!DecodeWorkServiceRequest(bytes, received));
  WorkServiceReply reply;
  reply.service = {10, 20, 30};
  reply.result = R::Accepted;
  WorkServiceReport report;
  report.catalog.work.work = {30, 4};
  report.catalog.work.stream = 2;
  report.catalog.work.request_sequence = 9;
  report.catalog.work.epoch = AuthorityEpoch{800, 15, 0};
  report.catalog.work.entry_gate_closed = true;
  report.catalog.work.start_accepted = true;
  report.catalog.work.initial = WorkInitialState::Reaped;
  report.catalog.work.initial_exit = {WorkExitKind::Signal, 9};
  report.catalog.inputs = WorkInputState::Consumed;
  report.catalog.input = {30, 7};
  report.runtime = {
      {30, 4}, WorkRuntimePhase::Observing, false, true, false, 0, 0, 42};
  reply.works.push_back(report);
  bytes = EncodeWorkServiceReply(reply);
  WorkServiceReply decoded;
  assert(DecodeWorkServiceReply(bytes, decoded));
  assert(decoded.works.size() == 1 &&
         decoded.works[0].catalog.work.epoch == report.catalog.work.epoch);
  assert(decoded.works[0].catalog.work.initial_exit ==
             report.catalog.work.initial_exit &&
         decoded.works[0].runtime.initial_pid == 42);
  for (size_t n = 0; n < bytes.size(); ++n)
    assert(!DecodeWorkServiceReply({bytes.data(), n}, decoded));
  bytes.push_back(0);
  assert(!DecodeWorkServiceReply(bytes, decoded));
}
}  // namespace
int main() {
  alarm(30);
  preparation_and_consumption();
  cancellation_and_foreign_handles();
  prepare_stop_races();
  start_disconnect_races();
  wire_codec();
  puts(
      "{\"catalog_prepare_stop_races\":100,\"start_disconnect_races\":100,"
      "\"consumed_registration_EOF\":true,\"operation_codec\":true,\"Android_"
      "authentication_or_runtime_backend_qualified\":false}");
}
