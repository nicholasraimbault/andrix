// SPDX-License-Identifier: Apache-2.0
// Host-only driver for the real native components. Not an installed control
// API.
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <string>
#include <string_view>

#include "captured_cgroup.h"
#include "instance_state.h"

using namespace andrix::supervision;
namespace {
const char* cleanup_name(Cleanup value) {
  switch (value) {
    case Cleanup::NotStarted:
      return "not_started";
    case Cleanup::Stopping:
      return "stopping";
    case Cleanup::Reclaiming:
      return "reclaiming";
    case Cleanup::Blocked:
      return "blocked";
    case Cleanup::Retired:
      return "retired";
  }
  return "unknown";
}
Population state_population(GroupPopulation value) {
  switch (value) {
    case GroupPopulation::Unknown:
      return Population::Unknown;
    case GroupPopulation::Populated:
      return Population::Populated;
    case GroupPopulation::Empty:
      return Population::Empty;
    case GroupPopulation::Removed:
      return Population::Removed;
  }
  return Population::Unknown;
}
uint64_t number(const char* value) {
  assert(value && *value && *value != '-');
  errno = 0;
  char* end = nullptr;
  auto n = strtoull(value, &end, 10);
  assert(!errno && end && !*end);
  return n;
}
std::string read_file(const std::string& path) {
  std::ifstream stream(path);
  assert(stream);
  std::string value;
  std::getline(stream, value);
  return value;
}
void check_scope(int parent) {
  const auto membership = read_file("/proc/self/cgroup");
  assert(membership.starts_with("0::/") && membership.ends_with("/control"));
  const auto path = std::string("/sys/fs/cgroup") +
                    membership.substr(3, membership.size() - 3 - 8);
  assert(path.starts_with("/sys/fs/cgroup/user.slice/user-" +
                          std::to_string(getuid()) + ".slice/"));
  const auto name = path.substr(path.find_last_of('/') + 1);
  assert(std::regex_match(
      name,
      std::regex(
          "andrix-delegated-native-kernel-[0-9]{8}t[0-9]{6}z\\.service")));
  struct stat expected{}, actual{};
  assert(!stat(path.c_str(), &expected) && !fstat(parent, &actual));
  assert(S_ISDIR(actual.st_mode) && expected.st_dev == actual.st_dev &&
         expected.st_ino == actual.st_ino);
  assert(read_file(path + "/memory.max") == "536870912");
  assert(read_file(path + "/memory.swap.max") == "0");
  assert(read_file(path + "/cpu.max") == "200000 100000");
  assert(read_file(path + "/pids.max") == "128");
  rlimit core{};
  assert(!getrlimit(RLIMIT_CORE, &core) && core.rlim_cur == 0 &&
         core.rlim_max == 0);
}
void result(const char* event, bool accepted, const InstanceState& state,
            Failure error = {}) {
  std::cout << "{\"event\":\"" << event
            << "\",\"accepted\":" << (accepted ? "true" : "false")
            << ",\"cleanup\":\"" << cleanup_name(state.cleanup())
            << "\",\"pending_mutations\":" << state.pending_mutations()
            << ",\"observation_pending\":"
            << (state.observation_pending() ? "true" : "false")
            << ",\"cleanup_pending\":"
            << (state.cleanup_pending() ? "true" : "false")
            << ",\"restart_allowed\":"
            << (state.restart_allowed() ? "true" : "false") << ",\"error\":\""
            << group_error_name(error.code) << "\",\"errno\":" << error.error
            << "}\n"
            << std::flush;
}
}  // namespace
int main(int argc, char** argv) {
  assert(argc == 9);
  const auto input = number(argv[1]);
  assert(input <= INT_MAX);
  const int parent = static_cast<int>(input);
  check_scope(parent);
  CleanupLimits limits{
      number(argv[3]), number(argv[4]),
      number(argv[5]), number(argv[6]),
      number(argv[7]), static_cast<DirectoryRetirement>(number(argv[8]))};
  Failure error;
  auto scope = CapturedCgroup::Capture(parent, argv[2], limits, error);
  close(parent);  // CapturedCgroup owns its duplicate, no borrowed descriptor
                  // lifetime.
  if (!scope) {
    std::cout << "{\"event\":\"capture_failed\",\"error\":\""
              << group_error_name(error.code) << "\",\"errno\":" << error.error
              << "}\n"
              << std::flush;
    return 2;
  }
  const InstanceId ref(1, 1);
  InstanceState state(ref, {2, 100000, 100000});
  auto mutation = state.begin_mutation(ref);
  assert(mutation && state.capture_root(ref));
  std::unique_ptr<ReclamationCursor> cursor;
  std::optional<ObservationTicket> observation;
  PopulationResult sampled;
  std::optional<CleanupTicket> queued;
  size_t queued_budget = 0;
  const auto id = scope->identity();
  std::cout << "{\"event\":\"captured\",\"device\":" << id.device
            << ",\"inode\":" << id.inode << "}\n"
            << std::flush;
  auto run_step = [&](const CleanupTicket& ticket, size_t budget) {
    if (!cursor) cursor = scope->BeginReclaim(error);
    if (!cursor) {
      assert(state.finish_cleanup_step(ticket, CleanupResult::Failed));
      result("step", false, state, error);
      return;
    }
    auto step = cursor->Step(budget);
    const auto completion =
        step.state == CursorState::Retired    ? CleanupResult::Reclaimed
        : step.state == CursorState::Progress ? CleanupResult::Progress
                                              : CleanupResult::Failed;
    const bool applied = state.finish_cleanup_step(ticket, completion);
    const auto stats = scope->stats();
    std::cout << "{\"event\":\"step\",\"accepted\":"
              << (applied ? "true" : "false") << ",\"cleanup\":\""
              << cleanup_name(state.cleanup()) << "\",\"restart_allowed\":"
              << (state.restart_allowed() ? "true" : "false") << ",\"error\":\""
              << group_error_name(step.failure.code)
              << "\",\"errno\":" << step.failure.error
              << ",\"steps\":" << step.steps
              << ",\"total_steps\":" << stats.steps
              << ",\"directory_visits\":" << stats.directory_visits
              << ",\"entry_visits\":" << stats.entry_visits
              << ",\"removed_directories\":" << stats.removed_directories
              << "}\n"
              << std::flush;
  };
  for (std::string command; std::getline(std::cin, command);) {
    if (command == "quit") {
      result("quit", true, state);
      return 0;
    }
    if (command == "finish-mutation") {
      bool ok = mutation && state.finish_mutation(*mutation);
      mutation.reset();
      result("mutation", ok, state);
    } else if (command == "process-exit") {
      result("process_exit", state.report_initial_process_exit(ref), state);
    } else if (command == "reaped") {
      result("reaped", state.report_initial_process_reaped(ref), state);
    } else if (command == "signal") {
      state.stop(ref);
      error = scope->Kill();
      result("signal", error.code == GroupError::None, state, error);
    } else if (command == "raw-population") {
      const auto actual = scope->ObservePopulation();
      std::cout << "{\"event\":\"raw_population\",\"sample\":\""
                << population_name(actual.state)
                << "\",\"errno\":" << actual.error << "}\n"
                << std::flush;
    } else if (command == "observe" || command == "read-begin") {
      auto next = state.begin_observation(ref);
      if (!next) {
        result("observation_rejected", false, state);
        continue;
      }
      observation.emplace(*next);
      sampled = scope->ObservePopulation();
      bool accepted = true;
      if (command == "observe") {
        accepted = state.finish_observation(*observation,
                                            state_population(sampled.state));
        observation.reset();
      }
      std::cout << "{\"event\":\"population\",\"sample\":\""
                << population_name(sampled.state)
                << "\",\"accepted\":" << (accepted ? "true" : "false")
                << ",\"cleanup\":\"" << cleanup_name(state.cleanup())
                << "\",\"errno\":" << sampled.error << "}\n"
                << std::flush;
    } else if (command == "read-finish") {
      bool ok =
          observation && state.finish_observation(
                             *observation, state_population(sampled.state));
      observation.reset();
      result("read_finish", ok, state);
    } else if (command == "read-timeout") {
      result("read_timeout",
             observation && state.observation_timed_out(*observation), state);
    } else if (command == "drop") {
      assert(!queued);
      cursor.reset();
      result("dropped_cursor", true, state);
    } else if (command == "second-cursor") {
      auto duplicate = scope->BeginReclaim(error);
      result("second_cursor", bool(duplicate), state, error);
    } else if (command.starts_with("step ") || command.starts_with("queue ")) {
      const size_t budget = number(command.c_str() + command.find(' ') + 1);
      auto ticket = state.begin_cleanup_step(ref);
      if (!ticket) {
        result("step_rejected", false, state);
        continue;
      }
      if (command.starts_with("queue ")) {
        queued.emplace(*ticket);
        queued_budget = budget;
        result("queued", true, state);
      } else
        run_step(*ticket, budget);
    } else if (command == "timeout") {
      result("timeout", queued && state.cleanup_timed_out(*queued), state);
    } else if (command == "finish-queued") {
      assert(queued);
      auto ticket = *queued;
      queued.reset();
      run_step(ticket, queued_budget);
    } else {
      return 3;
    }
  }
  return 4;
}
