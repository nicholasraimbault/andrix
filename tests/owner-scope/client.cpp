// SPDX-License-Identifier: Apache-2.0
// Fixed Shell observer/controller for the lab scopes only. No arbitrary target argument.
#include <aidl/dev/andrix/proof/scope/IScopeProof.h>
#include <aidl/dev/andrix/proof/scope/ScopeState.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

using aidl::dev::andrix::proof::scope::IScopeProof;
using aidl::dev::andrix::proof::scope::ScopeState;
namespace {
[[noreturn]] void fail(const char* why) {
  fprintf(stderr, "SCOPE_PROOF_FAILED %s\n", why); exit(1);
}
void require(bool ok, const char* why) { if (!ok) fail(why); }
template <class Test> void wait_for(Test test, const char* why) {
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  do {
    if (test()) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  } while (std::chrono::steady_clock::now() < until);
  fail(why);
}
struct Work {
  std::shared_ptr<IScopeProof> service;
  ScopeState state;
};
Work find(const char* slot, int64_t previous = 0) {
  Work value;
  const std::string name = std::string("andrix.proof.scope.") + slot;
  wait_for([&] {
    ndk::SpAIBinder binder(AServiceManager_checkService(name.c_str()));
    if (!binder.get()) return false;
    auto service = IScopeProof::fromBinder(binder);
    ScopeState state;
    if (!service || !service->observe(&state).isOk() || state.scopeId <= 0 ||
        state.guardianPid <= 1 || state.scopeId == previous) return false;
    value.service = service; value.state = state; return true;
  }, "scope discovery deadline");
  return value;
}
ScopeState observe(Work& work) {
  ScopeState current;
  require(work.service->observe(&current).isOk(), "exact Binder observe");
  require(current.scopeId == work.state.scopeId && current.guardianPid == work.state.guardianPid,
          "immutable scope identity");
  work.state = current; return current;
}
void record(const char* event, const Work& work) {
  const auto& s = work.state;
  printf("{\"event\":\"%s\",\"scopeId\":%lld,\"guardian\":%d,\"phase\":%d,"
         "\"entry\":%d,\"entryExited\":%s,\"pulses\":%lld,\"stopRequests\":%lld,\"stopCallerPid\":%d,\"descendants\":[",
         event, static_cast<long long>(s.scopeId), s.guardianPid, s.phase, s.entryPid,
         s.entryExited ? "true" : "false", static_cast<long long>(s.pulses),
         static_cast<long long>(s.stopRequests), s.lastStopCallerPid);
  for (size_t i = 0; i < s.descendants.size(); ++i) printf("%s%d", i ? "," : "", s.descendants[i]);
  printf("]}\n"); fflush(stdout);
}
void held(Work& work) {
  bool accepted = false;
  require(work.service->hold(work.state.scopeId, &accepted).isOk() && accepted, "hold accepted");
  wait_for([&] { observe(work); return work.state.phase == 2; }, "held entry acknowledgement");
  require(work.state.entryPid > 1 && !work.state.entryExited && work.state.descendants.empty() &&
          work.state.pulses == 0, "no payload before release");
  record("held", work);
}
void running(Work& work) {
  bool accepted = false;
  require(work.service->release(work.state.scopeId, &accepted).isOk() && accepted, "release accepted");
  wait_for([&] {
    observe(work); return work.state.phase == 3 && work.state.entryExited &&
                         work.state.descendants.size() == 2 && work.state.pulses >= 2;
  }, "entry exit and live detached descendants");
  record("running", work);
}
void fresh(Work& work, const char* event) {
  int64_t before = observe(work).pulses;
  wait_for([&] { observe(work); return work.state.pulses > before; }, "independent live positive");
  require(work.state.entryExited && work.state.descendants.size() == 2, "descendants still alive");
  record(event, work);
}
void gone(const Work& work) {
  const std::string group = "/sys/fs/cgroup/system/uid_7500/pid_" + std::to_string(work.state.guardianPid);
  wait_for([&] {
    struct stat st{};
    if (lstat(group.c_str(), &st) == 0) return false;
    require(errno == ENOENT, "kernel group observation denied or failed");
    return true;
  }, "actual init group removal");
  printf("{\"event\":\"group_removed\",\"scopeId\":%lld,\"guardian\":%d}\n",
         static_cast<long long>(work.state.scopeId), work.state.guardianPid); fflush(stdout);
}
void stop(Work& work, bool crash = false) {
  const std::string path = "/sys/fs/cgroup/system/uid_7500/pid_" + std::to_string(work.state.guardianPid);
  struct stat before{};
  require(lstat(path.c_str(), &before) == 0 && S_ISDIR(before.st_mode), "live group before Stop");
  require(work.service->stop(work.state.scopeId, crash).isOk(), "Stop transport submission");
  gone(work); // Submission and observed cleanup remain separate records.
}
void reject(Work& work, int64_t wrong) {
  int64_t before = observe(work).stopRequests;
  require(wrong != work.state.scopeId && work.service->stop(wrong, false).isOk(), "wrong-ID submission");
  wait_for([&] { observe(work); return work.state.stopRequests > before; }, "wrong-ID request processed");
  require(work.state.lastStopCallerPid == 0, "actual oneway PID observation");
  record("wrong_id_processed_scope_survived", work);
}
}

int main(int argc, char** argv) {
  if (getuid() != 2000 || !android::base::GetBoolProperty("ro.debuggable", false) || argc != 2)
    fail("actual debug Shell and one fixed command required");
  const std::string action(argv[1]);
  if (action == "prepare") {
    require(!android::base::GetBoolProperty("sys.andrix.scope_probe.consumed", false), "batch already consumed");
    require(android::base::SetProperty("sys.andrix.scope_probe.run", "true"), "fixed factory trigger");
    Work a = find("a"), b = find("b");
    require(a.state.scopeId != b.state.scopeId && a.state.guardianPid != b.state.guardianPid,
            "independent initial scopes");
    held(a); held(b);
  } else if (action == "release") {
    Work a = find("a"), b = find("b"); running(a); running(b);
  } else if (action == "inspect") {
    Work a = find("a"), b = find("b"); record("inspect_a", a); record("inspect_b", b);
  } else if (action == "turnover") {
    Work a = find("a"), b = find("b"); fresh(a, "before_a_crash"); fresh(b, "before_a_crash_b");
    reject(a, b.state.scopeId);
    stop(a, true); fresh(b, "after_a_crash_b");
    require(!android::base::GetBoolProperty("sys.andrix.scope_probe.replaced", false), "replacement already consumed");
    require(android::base::SetProperty("sys.andrix.scope_probe.replace_a", "true"), "fixed replacement trigger");
    Work next = find("a", a.state.scopeId);
    record("replacement_a", next);
    auto old = a.service->stop(a.state.scopeId, false);
    require(!old.isOk() && old.getStatus() == STATUS_DEAD_OBJECT, "old Binder was not dead");
    printf("{\"event\":\"old_binder_dead\"}\n"); fflush(stdout);
    reject(next, a.state.scopeId);
    require(next.state.phase == 0 && next.state.entryPid == 0, "replacement did not execute payload");
    held(next); stop(next);
    bool accepted = true;
    auto late = next.service->release(next.state.scopeId, &accepted);
    require(!late.isOk() && late.getStatus() == STATUS_DEAD_OBJECT, "late release reached dead scope");
    printf("{\"event\":\"late_release_dead\"}\n"); fflush(stdout);
    fresh(b, "after_cancelled_a2_b"); stop(b);
  } else {
    fail("unknown fixed command");
  }
  printf("SCOPE_PROOF_COMMAND_COMPLETED requires independent authority/group assessment\n");
  return 0;
}
