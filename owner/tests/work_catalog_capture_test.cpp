// SPDX-License-Identifier: Apache-2.0
// Scheduling control in the test allocator, not a production callback/API.
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <latch>
#include <new>
#include <thread>
#include <utility>

#include "work_catalog.h"

namespace {
struct AllocationPause {
  std::latch reached{1}, resume{1};
  unsigned remaining = 1;
};
thread_local AllocationPause* pause_allocation = nullptr;
void* allocate(size_t bytes) {
  void* result = std::malloc(bytes ? bytes : 1);
  if (!result) std::abort();
  auto* pause = pause_allocation;
  if (pause && !--pause->remaining) {
    pause_allocation = nullptr;  // The barrier cannot recursively pause itself.
    pause->reached.count_down();
    pause->resume.wait();
  }
  return result;
}
}  // namespace
void* operator new(size_t bytes) { return allocate(bytes); }
void* operator new[](size_t bytes) { return allocate(bytes); }
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, size_t) noexcept { std::free(memory); }

using namespace andrix;
using Result = WorkRegistryResult;
namespace {
WorkRegistryLimits limits() { return {1, 4, 1, {}, 10000, 10000, 10000}; }
WorkHandle reserve(WorkCatalog& catalog, uint64_t stream) {
  auto reply = catalog.Reserve(stream, 1);
  assert(reply.result == Result::Accepted && reply.work);
  return std::move(reply.work);
}
struct ResultRow {
  bool pinned_during_pause = false, late_handle = false;
  bool late_record_forgotten = false, capacity_reusable = false;
  Result late_result = Result::Invalid, next_result = Result::Invalid;
};
ResultRow collected_before_capture(bool reserve_retry) {
  WorkCatalog catalog(7, limits());
  auto stream = catalog.OpenStream();
  auto work = reserve(catalog, stream);
  const auto identity = work.identity();
  assert(work.CancelUnstarted());
  assert(catalog.CancelInputs(work).state == WorkInputState::Rejected);
  WorkHandle late;
  Result late_result = Result::Invalid;
  AllocationPause pause;
  // Find's first allocation is Capture's candidate Work, after registry.Find
  // has returned its Record-only control. Reserve first allocates Collect's
  // retirement vector, then its Existing path reaches the same candidate.
  pause.remaining = reserve_retry ? 2 : 1;
  std::thread finder([&] {
    pause_allocation = &pause;
    if (reserve_retry) {
      auto reply = catalog.Reserve(stream, 1);
      late_result = reply.result;
      late = std::move(reply.work);
    } else {
      late = catalog.Find(identity);
    }
    assert(!pause_allocation);
  });
  pause.reached.wait();
  assert(catalog.Forget(work) == Result::Accepted);
  work = {};
  catalog.Collect();
  assert(!catalog.Find(identity) && catalog.List().empty());
  // Validate the schedule: a retained registry control must still pin this
  // only slot. Pausing before registry lookup would not establish the race.
  auto during = catalog.Reserve(stream, 2);
  const bool pinned = during.result == Result::Capacity && !during.work;
  pause.resume.count_down();
  finder.join();
  ResultRow result;
  result.pinned_during_pause = pinned;
  result.late_handle = bool(late);
  result.late_result = late_result;
  result.late_record_forgotten = late && late.Inspect().work.forgotten;
  late = {};
  catalog.Collect();
  auto next = catalog.Reserve(stream, 2);
  result.next_result = next.result;
  result.capacity_reusable =
      next.result == Result::Accepted && next.work && next.identity != identity;
  return result;
}
void existing_canonical_handle() {
  WorkCatalog catalog(8, limits());
  auto stream = catalog.OpenStream();
  auto work = reserve(catalog, stream);
  const auto identity = work.identity();
  assert(work.CancelUnstarted());
  assert(catalog.CancelInputs(work).state == WorkInputState::Rejected);
  AllocationPause pause;
  WorkHandle late;
  std::thread finder([&] {
    pause_allocation = &pause;
    late = catalog.Find(identity);
    assert(!pause_allocation);
  });
  pause.reached.wait();
  assert(catalog.Forget(work) == Result::Accepted);
  catalog
      .Collect();  // Original public handle still retains canonical metadata.
  pause.resume.count_down();
  finder.join();
  assert(late && late.identity() == identity && late.Inspect().work.forgotten);
  assert(late.Inspect().inputs == WorkInputState::Rejected);
  assert(!catalog.Find(identity));
  late = {};
  work = {};
  catalog.Collect();
  assert(catalog.Reserve(stream, 2).result == Result::Accepted);
}
void concurrent_capture_retirement() {
  for (unsigned round = 0; round < 200; ++round) {
    WorkCatalog catalog(9, limits());
    auto stream = catalog.OpenStream();
    auto work = reserve(catalog, stream);
    const auto identity = work.identity();
    assert(work.CancelUnstarted());
    assert(catalog.CancelInputs(work).state == WorkInputState::Rejected);
    std::latch start{1};
    std::thread finder([&] {
      start.wait();
      for (unsigned index = 0; index < 50; ++index) {
        auto found = catalog.Find(identity);
        if (found) assert(found.identity() == identity);
        auto retry = catalog.Reserve(stream, 1);
        assert(retry.result == Result::Existing ||
               retry.result == Result::Stale);
      }
    });
    std::thread collector([&] {
      start.wait();
      for (unsigned index = 0; index < 50; ++index) catalog.Collect();
    });
    start.count_down();
    assert(catalog.Forget(work) == Result::Accepted);
    work = {};
    finder.join();
    collector.join();
    catalog.Collect();
    assert(catalog.Reserve(stream, 2).result == Result::Accepted);
  }
}
void print(const char* operation, const ResultRow& row) {
  printf(
      "{\"operation\":\"%s\",\"registry_control_pinned\":%s,"
      "\"late_handle\":%s,\"late_record_forgotten\":%s,"
      "\"late_result\":%u,\"capacity_reusable\":%s,\"next_result\":%u}\n",
      operation, row.pinned_during_pause ? "true" : "false",
      row.late_handle ? "true" : "false",
      row.late_record_forgotten ? "true" : "false",
      static_cast<unsigned>(row.late_result),
      row.capacity_reusable ? "true" : "false",
      static_cast<unsigned>(row.next_result));
}
}  // namespace
int main() {
  alarm(30);
  const auto find = collected_before_capture(false);
  const auto retry = collected_before_capture(true);
  print("Find", find);
  print("Reserve", retry);
  if (!find.pinned_during_pause || find.late_handle ||
      !find.capacity_reusable || !retry.pinned_during_pause ||
      retry.late_handle || !retry.capacity_reusable ||
      retry.late_result != Result::Stale)
    return 1;
  existing_canonical_handle();
  concurrent_capture_retirement();
  puts(
      "{\"catalog_capture_retirement\":true,\"concurrent_rounds\":200,"
      "\"production_capture_code_instrumented\":false,"
      "\"Android_runtime_qualified\":false}");
}
