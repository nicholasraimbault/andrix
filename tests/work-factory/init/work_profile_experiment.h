// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "service.h"

namespace android::init {

class ServiceList;

// Construction probe only. This is not a launch interface or a Work identity API.
// Requires the two friendships documented in integration.txt, not parser changes.
class WorkProfileExperiment {
  public:
    using TokenLine = std::vector<std::string>;
    using TrustedDefinition = std::vector<TokenLine>;

    struct Instance {
        uint64_t id;
        Service* service;  // Borrowed from the destination list, not a lifetime handle.
    };

    // Detached diagnostic values from an actual Service. No mutable references,
    // callback objects or setters into the Service are exposed by this snapshot.
    struct Snapshot {
        std::string name;
        std::string filename;
        std::vector<std::string> args;
        std::optional<uid_t> parsed_uid;
        gid_t gid;
        std::vector<gid_t> supp_gids;
        std::optional<CapSet> capabilities;
        int priority;
        int oom_score_adjust;
        std::vector<std::string> task_profiles;
        std::vector<std::pair<int, rlimit>> rlimits;
        std::string seclabel;
        unsigned flags;
        pid_t pid;
        unsigned long start_order;
        int crash_count;
        android::base::boot_clock::time_point time_started;
        android::base::boot_clock::time_point time_crashed;
        bool sigstop;
        size_t reap_callback_count;
        size_t onrestart_command_count;
        std::vector<std::pair<std::string, std::string>> environment_vars;
        std::vector<std::pair<std::string, std::string>> once_environment_vars;
    };

    static TrustedDefinition FixtureDefinition();

    // Only trusted image code may supply this definition. Injection exists for
    // host negative tests, NOT for requests from owner code or external callers.
    // Taking a value gives this factory its own immutable token definition.
    explicit WorkProfileExperiment(TrustedDefinition trusted_image_definition);
    WorkProfileExperiment(const WorkProfileExperiment&) = delete;
    WorkProfileExperiment& operator=(const WorkProfileExperiment&) = delete;
    WorkProfileExperiment(WorkProfileExperiment&&) = delete;
    WorkProfileExperiment& operator=(WorkProfileExperiment&&) = delete;

    // Serial use only. No request executable, UID, SID, path or budget parameters.
    // Every attempt consumes an ID, including validation and collision failures.
    // On failure destination is unchanged. On success it owns the parsed object.
    Result<Instance> Create(ServiceList& destination);

    static Snapshot Inspect(const Service& service);

  private:
    static Result<void> ValidateDefinition(const TrustedDefinition& definition);
    static Result<void> ValidateConstructed(const Service& service, const std::string& name);

    const TrustedDefinition definition_;
    uint64_t next_id_ = 1;  // Zero is the exhausted sentinel, never an instance ID.
};

}  // namespace android::init
