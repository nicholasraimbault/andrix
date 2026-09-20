// SPDX-License-Identifier: Apache-2.0
#include <fcntl.h>
#include <unistd.h>

#include <barrier>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <thread>

#include "work_catalog.h"
#include "work_service_protocol.h"

using namespace andrix;
using R = WorkRegistryResult;
namespace {
WorkRegistryLimits limits(size_t records = 2, size_t streams = 1) {
  return {records, streams, 1, {}, 10000, 10000, 10000};
}
void unknown_open_reply() {
  WorkCatalog catalog(1, limits());
  uint64_t previous = 0;
  for (unsigned n = 0; n < 100; ++n) {
    uint64_t opened;
    {
      WorkStreamScope connection(catalog);
      opened = connection.OpenStream();
      assert(opened > previous && catalog.StreamUnused(opened));
      assert(!connection.OpenStream());  // No eviction of a live unused stream.
      assert(catalog.LookupRequest(opened, 1).result == R::NotFound);
      assert(catalog.usage().records == 0);
    }  // No reservation named this stream. Lost reply does not strand it.
    assert(catalog.LookupRequest(opened, 1).result == R::Stale);
    previous = opened;
  }
  WorkStreamScope connection(catalog);
  auto first = connection.OpenStream();
  assert(first > previous && catalog.CloseStream(first));
  auto second = connection.OpenStream();
  assert(second > first);  // Closed bookkeeping is pruned without rebinding.
}
void used_stream_survives_issuer() {
  WorkCatalog catalog(2, limits());
  uint64_t stream;
  WorkHandle work;
  {
    WorkStreamScope issuer(catalog);
    stream = issuer.OpenStream();
    // Another authenticated conversation may name the issued stream.
    auto reserved = catalog.Reserve(stream, 1);
    assert(reserved.result == R::Accepted);
    work = std::move(reserved.work);
    assert(!catalog.StreamUnused(stream));
    assert(!catalog.CloseStreamIfUnused(stream));
  }
  auto retry = catalog.Reserve(stream, 1);
  assert(retry.result == R::Existing && retry.identity == work.identity());
  assert(!work.Inspect().work.entry_gate_closed);
  assert(catalog.CloseStream(stream));
  assert(!work.Inspect().work.entry_gate_closed);
  WorkStreamScope replacement(catalog);
  auto fresh = replacement.OpenStream();
  assert(fresh > stream);
  auto queried = catalog.LookupRequest(stream, 1);
  assert(queried.result == R::Existing && queried.identity == work.identity());
  assert(catalog.LookupRequest(fresh, 1).result == R::NotFound);
}
void pending_and_retired_stream_lookup() {
  WorkRegistry registry(3, limits(1));
  auto stream = registry.OpenStream();
  const auto original = stream.identity();
  assert(registry.LookupRequest(0, 1).result == R::Invalid);
  assert(registry.LookupRequest(original, 0).result == R::Invalid);
  assert(registry.LookupRequest(original + 1, 1).result == R::Foreign);
  for (unsigned n = 0; n < 50; ++n)
    assert(registry.LookupRequest(original, 5).result == R::NotFound);
  assert(registry.usage().records == 0 && registry.StreamUnused(stream));
  auto pending = registry.Reserve(stream, 5);
  assert(pending.result == R::Accepted && pending.allocation);
  auto query = registry.LookupRequest(original, 5);
  assert(query.result == R::Pending && query.work == pending.work &&
         !query.allocation && !query.control);
  assert(!registry.CloseStreamIfUnused(stream));
  assert(registry.LookupRequest(original, 4).result == R::Stale);
  assert(registry.LookupRequest(original, 6).result == R::NotFound);
  assert(registry.CloseStream(stream));
  stream = {};
  auto fresh = registry.OpenStream();
  assert(fresh && fresh.identity() > original);
  assert(registry.LookupRequest(original, 5).result == R::Pending);
  assert(registry.usage().allocating == 1);
  assert(registry.Reserve(fresh, 1).result == R::Capacity);
  int error = 0;
  auto late = WorkAdmission::Reserve(pending.work, error);
  assert(late && !error);
  assert(registry.ReservationFinished(pending.allocation, late).result ==
         R::Closed);
  assert(late->phase() == AdmissionPhase::Stopped);
  query = registry.LookupRequest(original, 5);
  assert(query.result == R::Closed && query.work == pending.work &&
         query.error == ECANCELED && !query.allocation && !query.control);
  assert(registry.usage().allocating == 0);
  auto next = registry.Reserve(fresh, 1);
  assert(next.result == R::Accepted && next.work != pending.work);
  assert(registry.LookupRequest(original, 5).result == R::Stale);
  assert(registry.ReservationFinished(next.allocation, {}, ENOMEM).result ==
         R::Closed);
}
void readonly_input_recovery() {
  WorkCatalog catalog(4, limits());
  WorkStreamScope issuer(catalog);
  const auto stream = issuer.OpenStream();
  auto reserved = catalog.Reserve(stream, 1);
  assert(reserved.result == R::Accepted);
  auto identity = reserved.identity;
  int pipefd[2];
  assert(!pipe2(pipefd, O_NONBLOCK | O_CLOEXEC));
  LaunchFailure failure;
  int description =
      SealLaunch({"/ordinary", {"ordinary"}, {}, "/"}, {}, failure);
  assert(description >= 0);
  auto input = catalog.Prepare(reserved.work, description, {-1, pipefd[1], -1});
  assert(input.result == R::Accepted);
  close(description);
  close(pipefd[1]);
  assert(catalog.CloseStream(stream));
  const auto fresh = issuer.OpenStream();
  assert(fresh > stream);
  {
    auto observer = catalog.LookupRequest(stream, 1);
    assert(observer.result == R::Existing && observer.identity == identity);
    assert(observer.work.Inspect().input == input.identity);
    assert(observer.work.Inspect().inputs == WorkInputState::Ready);
    // Merely dropping the querying handle is not client-loss cancellation.
  }
  assert(!reserved.work.Inspect().work.entry_gate_closed);
  char byte;
  assert(read(pipefd[0], &byte, 1) == -1 && errno == EAGAIN);
  assert(reserved.work.CancelUnstarted());
  assert(catalog.CancelInputs(reserved.work).state == WorkInputState::Rejected);
  assert(read(pipefd[0], &byte, 1) == 0);
  close(pipefd[0]);
  auto outcome = catalog.LookupRequest(stream, 1);
  assert(outcome.result == R::Existing && outcome.identity == identity &&
         outcome.work.Inspect().work.complete &&
         !outcome.work.Inspect().work.start_accepted);
  assert(catalog.Forget(reserved.work) == R::Accepted);
  assert(catalog.LookupRequest(stream, 1).result == R::Stale);
  assert(outcome.work.identity() == identity);  // Retained control still exact.
}
void used_stream_not_work_stop() {
  WorkCatalog catalog(5, limits());
  auto stream = catalog.OpenStream();
  auto reserved = catalog.Reserve(stream, 1);
  LaunchFailure failure;
  int description =
      SealLaunch({"/ordinary", {"ordinary"}, {}, "/"}, {}, failure);
  assert(description >= 0);
  auto input = catalog.Prepare(reserved.work, description, {-1, -1, -1});
  close(description);
  auto accepted = catalog.Start(reserved.work, input.identity);
  assert(accepted.result == R::Accepted && accepted.backend);
  assert(!catalog.CloseStreamIfUnused(stream));
  assert(catalog.CloseStream(stream));
  auto observed = catalog.LookupRequest(stream, 1);
  assert(observed.result == R::Existing &&
         observed.identity == reserved.identity);
  assert(observed.work.Inspect().work.start_accepted &&
         !observed.work.Inspect().work.entry_gate_closed);
  assert(catalog.Start(observed.work, input.identity).result == R::Existing);
  reserved.work.Stop();
  accepted.stdio_lease.Release();
  assert(!accepted.backend.AdmissionFinished(AdmissionResult::Stopped));
}
void unused_close_reserve_race() {
  for (unsigned n = 0; n < 200; ++n) {
    WorkRegistry registry(6, limits(1));
    auto stream = registry.OpenStream();
    std::barrier begin(2);
    WorkReserveReply result;
    std::thread sender([&] {
      begin.arrive_and_wait();
      result = registry.Reserve(stream, 1);
    });
    begin.arrive_and_wait();
    bool closed = registry.CloseStreamIfUnused(stream);
    sender.join();
    if (closed) {
      assert(result.result == R::Closed && !result.allocation);
      assert(registry.usage().allocating == 0);
    } else {
      assert(result.result == R::Accepted && result.allocation);
      assert(registry.LookupRequest(stream.identity(), 1).result == R::Pending);
      assert(registry.usage().allocating == 1);
      assert(registry.CloseStream(stream));
      assert(registry.ReservationFinished(result.allocation, {}, ECANCELED)
                 .result == R::Closed);
    }
  }
}
void unissued_capacity_and_exhaustion() {
  WorkRegistry registry(7, limits(1, 2)), foreign(8, limits());
  auto issued = registry.OpenStream(), unused = registry.OpenStream();
  auto foreign_stream = foreign.OpenStream();
  assert(!registry.StreamUnused(foreign_stream));
  assert(!registry.CloseStreamIfUnused(foreign_stream));
  assert(foreign.StreamUnused(foreign_stream));
  auto pending = registry.Reserve(issued, 1);
  assert(pending.result == R::Accepted && pending.allocation);
  assert(registry.Reserve(unused, 1).result == R::Capacity);
  assert(registry.StreamUnused(unused));
  assert(registry.CloseStreamIfUnused(unused));
  assert(registry.LookupRequest(unused.identity(), 1).result == R::Stale);
  assert(registry.usage().allocating == 1);
  assert(registry.ReservationFinished(pending.allocation, {}, ENOMEM).result ==
         R::Closed);
  auto bounded = limits();
  bounded.stream_serial_limit = 2;
  WorkCatalog exhausted(9, bounded);
  for (unsigned n = 0; n < 2; ++n) {
    WorkStreamScope connection(exhausted);
    assert(connection.OpenStream() == n + 1);
  }
  WorkStreamScope no_wrap(exhausted);
  assert(!no_wrap.OpenStream());
}
void codec_and_references() {
  WorkRequestReference reference{{1, 2, 3}, 4, 5};
  assert(FormatWorkRequestReference(reference) == "1.2.3.4.5");
  assert(ParseWorkRequestReference("1.2.3.4.5") == reference);
  WorkRequestReference maximum{
      {UINT64_MAX, UINT64_MAX, UINT64_MAX}, UINT64_MAX, UINT64_MAX};
  assert(ParseWorkRequestReference(FormatWorkRequestReference(maximum)) ==
         maximum);
  for (const char* bad : {"", "1.2.3.4", "1.2.3.4.5.6", "1.2.3.4.5.",
                          "1.2.3.0.1", "1.2.3.4.0", "+1.2.3.4.5", "1.2.3.-4.5",
                          "1.2.3.4.5 ", "1.2.3.4.18446744073709551616"})
    assert(!ParseWorkRequestReference(bad));
  assert(FormatWorkRequestReference({}).empty());
  WorkServiceRequest request;
  request.service = reference.service;
  request.stream = reference.stream;
  request.sequence = reference.sequence;
  assert(
      ValidWorkServiceRequest(WorkServiceOperation::LookupRequest, request, 0));
  assert(!ValidWorkServiceRequest(WorkServiceOperation::LookupRequest, request,
                                  1));
  request.serial = 1;
  assert(!ValidWorkServiceRequest(WorkServiceOperation::LookupRequest, request,
                                  0));
  WorkServiceReply reply, decoded;
  reply.service = reference.service;
  reply.result = R::NotFound;
  auto wire = EncodeWorkServiceReply(reply);
  assert(DecodeWorkServiceReply(wire, decoded) &&
         decoded.result == R::NotFound);
}
}  // namespace
int main() {
  alarm(30);
  unknown_open_reply();
  used_stream_survives_issuer();
  pending_and_retired_stream_lookup();
  readonly_input_recovery();
  used_stream_not_work_stop();
  unused_close_reserve_race();
  unissued_capacity_and_exhaustion();
  codec_and_references();
  puts(
      "{\"unused_stream_closure_cycles\":100,\"unused_close_reserve_races\":"
      "200,"
      "\"lookup_never_allocates\":true,\"closed_stream_result_recovery\":true,"
      "\"query_does_not_adopt_submission\":true,"
      "\"retained_stream_independent_of_work_stop\":true,"
      "\"reference_codec\":true,\"Android_runtime_qualified\":false}");
}
