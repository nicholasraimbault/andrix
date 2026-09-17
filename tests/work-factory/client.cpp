// SPDX-License-Identifier: Apache-2.0
#include <aidl/dev/andrix/proof/factory/FactoryState.h>
#include <aidl/dev/andrix/proof/factory/IFactory.h>
#include <aidl/dev/andrix/proof/factory/IWork.h>
#include <aidl/dev/andrix/proof/factory/WorkState.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>

#include "common.h"
#include "group_observation.h"

using namespace andrix::factory_proof;
namespace api = aidl::dev::andrix::proof::factory;
namespace {
[[noreturn]] void bad(const char* message) {
  fprintf(stderr, "FACTORY_PROOF_FAILED %s\n", message);
  exit(1);
}
void check(bool result, const char* message) {
  if (!result) bad(message);
}
void wait_for(const std::function<bool()>& predicate, const char* message,
              uint64_t timeout = 30000) {
  auto end = now_ms() + timeout;
  while (!predicate()) {
    if (now_ms() > end) bad(message);
    usleep(10000);
  }
}
std::shared_ptr<api::IFactory> service() {
  std::shared_ptr<api::IFactory> result;
  wait_for(
      [&] {
        ndk::SpAIBinder binder(AServiceManager_checkService(kManagerService));
        if (binder.get()) result = api::IFactory::fromBinder(binder);
        return bool(result);
      },
      "factory discovery");
  return result;
}
api::FactoryState factory_state(const std::shared_ptr<api::IFactory>& factory) {
  api::FactoryState state;
  check(factory->observe(&state).isOk(), "factory observe");
  return state;
}
struct Work {
  std::shared_ptr<api::IWork> control;
  api::WorkState state;
};
void observe(Work& work) {
  check(work.control && work.control->observe(&work.state).isOk(),
        "exact work observe");
}
Work find(const std::shared_ptr<api::IFactory>& factory, int64_t request) {
  Work work;
  check(factory->find(request, &work.control).isOk() && work.control,
        "existing request lookup");
  observe(work);
  return work;
}
Work create(const std::shared_ptr<api::IFactory>& factory, int64_t request,
            bool blocked = false) {
  Work work;
  check(factory->create(request, blocked, &work.control).isOk() && work.control,
        "create accepted");
  observe(work);
  return work;
}
void record(const char* event, Work& work) {
  observe(work);
  auto& s = work.state;
  printf(
      "{\"event\":\"%s\",\"managerId\":%lld,\"workId\":%lld,\"phase\":%d,"
      "\"guardian\":%d,"
      "\"entry\":%d,\"entryExited\":%s,\"pulses\":%lld,\"stopRequests\":%lld,"
      "\"stopCallerPid\":%d,"
      "\"creationReturned\":%s,\"guardianExited\":%s,\"guardianStatus\":%d,"
      "\"groupPath\":\"%s\",\"descendants\":[",
      event, static_cast<long long>(s.managerId),
      static_cast<long long>(s.workId), s.phase, s.guardianPid, s.entryPid,
      s.entryExited ? "true" : "false", static_cast<long long>(s.pulses),
      static_cast<long long>(s.stopRequests), s.stopCallerPid,
      s.creationReturned ? "true" : "false",
      s.guardianExited ? "true" : "false", s.guardianStatus,
      s.groupPath.c_str());
  for (size_t i = 0; i < s.descendants.size(); ++i)
    printf("%s%d", i ? "," : "", s.descendants[i]);
  puts("]}");
  fflush(stdout);
}
void ready(Work& work) {
  wait_for(
      [&] {
        observe(work);
        return work.state.phase == Ready && work.state.creationReturned;
      },
      "ready scope");
}
void hold(Work& work) {
  bool accepted = false;
  check(work.control->hold(work.state.workId, &accepted).isOk() && accepted,
        "hold accepted");
  wait_for(
      [&] {
        observe(work);
        return work.state.phase == Held;
      },
      "held acknowledgement");
  check(!work.state.entryExited && work.state.entryPid > 1 &&
            work.state.pulses == 0 && work.state.descendants.empty(),
        "no payload before release");
  record("held", work);
}
void release(Work& work) {
  bool accepted = false;
  check(work.control->release(work.state.workId, &accepted).isOk() && accepted,
        "release accepted");
  wait_for(
      [&] {
        observe(work);
        return work.state.entryExited && work.state.descendants.size() == 2 &&
               work.state.pulses > 0;
      },
      "live detached descendants");
  record("running", work);
}
void fresh(Work& work, const char* label) {
  observe(work);
  auto before = work.state.pulses;
  wait_for(
      [&] {
        observe(work);
        return work.state.pulses > before && work.state.phase == Released;
      },
      "fresh independent work");
  record(label, work);
}
void removed(Work& work) {
  wait_for(
      [&] {
        observe(work);
        return work.state.phase == Removed;
      },
      "complete group removal");
  struct stat st{};
  check(!work.state.groupPath.empty() &&
            lstat(work.state.groupPath.c_str(), &st) < 0 && errno == ENOENT,
        "kernel group absent");
  record("removed", work);
}
void stop(Work& work, bool crash = false) {
  struct stat st{};
  check(lstat(work.state.groupPath.c_str(), &st) == 0,
        "positive group before Stop");
  check(work.control->stop(work.state.workId, crash).isOk(), "Stop transport");
  removed(work);
}
void wrong(Work& work, int64_t id) {
  observe(work);
  auto count = work.state.stopRequests;
  check(work.control->stop(id, false).isOk(), "wrong-ID transport");
  wait_for(
      [&] {
        observe(work);
        return work.state.stopRequests > count;
      },
      "wrong-ID processed");
  check(work.state.stopCallerPid == 0, "actual oneway PID zero");
  record("wrong_id_processed", work);
}
}  // namespace
int main(int argc, char** argv) {
  if (argc != 2 || getuid() != 2000 || role() != "u:r:shell:s0" ||
      !android::base::GetBoolProperty("ro.debuggable", false))
    bad("actual debug Shell only");
  const std::string command = argv[1];
  if (command != "prepare" && command != "release" && command != "inspect" &&
      command != "turnover" && command != "manager-fault")
    bad("fixed command");
  if (command == "prepare")
    check(android::base::SetProperty("sys.andrix.factory.run", "true"),
          "factory trigger");
  auto factory = service();
  auto initial = factory_state(factory);
  printf(
      "{\"event\":\"factory\",\"managerId\":%lld,\"managerPid\":%d,\"backend\":"
      "\"%s\",\"groupPath\":\"%s\",\"reserved\":%d}\n",
      static_cast<long long>(initial.managerId), initial.managerPid,
      initial.backend.c_str(), initial.groupPath.c_str(), initial.reserved);
  if (command == "prepare") {
    check(initial.reserved == 0, "fresh manager");
    auto a = create(factory, 101), b = create(factory, 102),
         duplicate = create(factory, 101);
    check(duplicate.state.workId == a.state.workId &&
              duplicate.state.managerId == a.state.managerId,
          "same request no duplicate");
    check(a.state.workId != b.state.workId, "independent identities");
    ready(a);
    ready(b);
    hold(a);
    hold(b);
  } else if (command == "release") {
    auto a = find(factory, 101), b = find(factory, 102);
    release(a);
    release(b);
  } else if (command == "inspect") {
    auto a = find(factory, 101), b = find(factory, 102);
    record("inspect_a", a);
    record("inspect_b", b);
  } else if (command == "turnover") {
    auto a = find(factory, 101), b = find(factory, 102);
    fresh(a, "before_stop_a");
    fresh(b, "before_stop_b");
    wrong(a, b.state.workId);
    check(a.state.phase == Released, "wrong ID cannot stop A");
    stop(a, true);
    fresh(b, "after_a_b");
    auto replacement = create(factory, 103);
    ready(replacement);
    check(replacement.state.workId != a.state.workId,
          "fresh replacement identity");
    wrong(a, replacement.state.workId);
    check(a.state.phase == Removed, "old handle remains tombstone");
    wrong(replacement, a.state.workId);
    check(replacement.state.phase == Ready, "old ID cannot stop replacement");
    hold(replacement);
    stop(replacement);
    bool accepted = true;
    check(replacement.control->release(replacement.state.workId, &accepted)
                  .isOk() &&
              !accepted,
          "late release rejected");
    fresh(b, "after_cancelled_replacement_b");
    auto late = create(factory, 104, true);
    wait_for([&] { return factory_state(factory).allocatorBlocked; },
             "real blocked allocation worker");
    check(late.control->stop(late.state.workId, false).isOk(),
          "blocked allocation Stop");
    wait_for(
        [&] {
          observe(late);
          return late.state.phase == Stopping && late.state.stopRequests > 0;
        },
        "independent Stop while allocator blocked");
    record("stopped_while_allocator_blocked", late);
    accepted = false;
    check(factory->unblockAllocator(initial.managerId, &accepted).isOk() &&
              accepted,
          "late allocation completion");
    removed(late);
    check(late.state.guardianPid > 1 && late.state.entryPid == 0 &&
              late.state.pulses == 0,
          "late helper cleaned without payload");
    fresh(b, "after_late_completion_b");
    stop(b);
  } else {
    auto a = create(factory, 201), b = create(factory, 202);
    ready(a);
    ready(b);
    hold(a);
    hold(b);
    release(a);
    release(b);
    fresh(a, "before_manager_loss_a");
    fresh(b, "before_manager_loss_b");
    const std::string first = a.state.groupPath, second = b.state.groupPath,
                      manager_group = initial.groupPath;
    auto first_fd = open_group(first), second_fd = open_group(second);
    GroupObservation first_state(first_fd.get()), second_state(second_fd.get());
    check(first_fd >= 0 && second_fd >= 0 &&
              first_state.read() == GroupPopulation::Populated &&
              second_state.read() == GroupPopulation::Populated,
          "live groups before manager loss");
    check(factory->crash(initial.managerId).isOk(), "manager crash transport");
    wait_for(
        [&] {
          api::FactoryState unused;
          auto status = factory->observe(&unused);
          return status.getStatus() == STATUS_DEAD_OBJECT;
        },
        "old manager Binder death");
    GroupPopulation first_after = GroupPopulation::Unknown;
    GroupPopulation second_after = GroupPopulation::Unknown;
    wait_for(
        [&] {
          first_after = first_state.read();
          second_after = second_state.read();
          auto quiescent = [](GroupPopulation state) {
            return state == GroupPopulation::Empty ||
                   state == GroupPopulation::Removed;
          };
          return quiescent(first_after) && quiescent(second_after);
        },
        "manager loss complete process termination");
    printf(
        "{\"event\":\"manager_loss_groups_quiescent\",\"first\":\"%s\","
        "\"second\":\"%s\"}\n",
        population_name(first_after), population_name(second_after));
    fflush(stdout);
    check(android::base::SetProperty("sys.andrix.factory.recover", "true"),
          "fresh manager recovery trigger");
    std::shared_ptr<api::IFactory> recovered;
    wait_for(
        [&] {
          ndk::SpAIBinder binder(AServiceManager_checkService(kManagerService));
          if (!binder.get()) return false;
          auto candidate = api::IFactory::fromBinder(binder);
          api::FactoryState state;
          if (!candidate || !candidate->observe(&state).isOk() ||
              state.managerId == initial.managerId)
            return false;
          check(state.reserved == 0,
                "no ordinary jobs automatically restarted");
          recovered = candidate;
          return true;
        },
        "new manager identity", 40000);
    const auto recovered_state = factory_state(recovered);
    printf(
        "{\"event\":\"factory_recovered\",\"managerId\":%lld,\"managerPid\":%d,"
        "\"groupPath\":\"%s\",\"reserved\":%d}\n",
        static_cast<long long>(recovered_state.managerId),
        recovered_state.managerPid, recovered_state.groupPath.c_str(),
        recovered_state.reserved);
    fflush(stdout);
    for (const auto& path : {first, second, manager_group}) {
      struct stat st{};
      check(lstat(path.c_str(), &st) < 0 && errno == ENOENT,
            "old hierarchy reclaimed");
    }
    api::WorkState unused;
    check(a.control->observe(&unused).getStatus() == STATUS_DEAD_OBJECT,
          "old work control cannot retarget");
    auto fresh_work = create(recovered, 301);
    ready(fresh_work);
    hold(fresh_work);
    release(fresh_work);
    stop(fresh_work);
    auto state = factory_state(recovered);
    const auto path = state.groupPath;
    check(recovered->finish(state.managerId).isOk(), "graceful manager finish");
    wait_for(
        [&] {
          struct stat st{};
          return lstat(path.c_str(), &st) < 0 && errno == ENOENT;
        },
        "final manager group removed");
    puts("{\"event\":\"manager_recovery_and_final_cleanup\"}");
  }
  puts(
      "FACTORY_PROOF_COMMAND_COMPLETED requires independent Android "
      "assessment");
  return 0;
}
