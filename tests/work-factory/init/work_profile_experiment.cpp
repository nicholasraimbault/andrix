// SPDX-License-Identifier: Apache-2.0
#include "work_profile_experiment.h"

#include <limits>
#include <map>
#include <set>
#include <sys/resource.h>

#include "service_list.h"
#include "service_parser.h"

namespace android::init {
namespace {
constexpr char kExecutable[] = "/system_ext/bin/andrix-factory-guardian-probe";
constexpr char kSource[] = "<Andrix image profile construction experiment>";
constexpr unsigned kParsedFlags = SVC_DISABLED | SVC_RC_DISABLED | SVC_ONESHOT;
const std::map<int, rlim_t> kLimits = {
    {RLIMIT_NPROC, 32}, {RLIMIT_NOFILE, 128}, {RLIMIT_CORE, 0}, {RLIMIT_FSIZE, 67108864}};
}

WorkProfileExperiment::TrustedDefinition WorkProfileExperiment::FixtureDefinition() {
    // Fixed experiment values only, not final product resource defaults.
    return {{"user", "7500"}, {"group", "7500", "3003"}, {"capabilities"},
            {"priority", "10"}, {"oom_score_adjust", "700"},
            {"task_profiles", "SCHED_SP_BACKGROUND"}, {"disabled"}, {"oneshot"},
            {"rlimit", "nproc", "32", "32"}, {"rlimit", "nofile", "128", "128"},
            {"rlimit", "core", "0", "0"}, {"rlimit", "fsize", "67108864", "67108864"}};
}

WorkProfileExperiment::WorkProfileExperiment(TrustedDefinition definition)
    : definition_(std::move(definition)) {}

Result<void> WorkProfileExperiment::ValidateDefinition(const TrustedDefinition& definition) {
    const std::set<std::string> supported = {"user", "group", "capabilities", "priority",
        "oom_score_adjust", "task_profiles", "disabled", "oneshot", "rlimit"};
    if (definition.empty() || definition.size() > 24) return Error() << "bounded profile required";
    std::set<std::string> seen;
    for (const auto& line : definition) {
        if (line.empty() || line.size() > 8 || !supported.contains(line[0])) {
            return Error() << "unsupported profile option";
        }
        for (const auto& token : line) {
            if (token.empty() || token.size() > 128 || token.find('$') != std::string::npos) {
                return Error() << "bounded literal profile tokens required";
            }
            for (const unsigned char byte : token) {
                if (byte <= 32 || byte == 127) return Error() << "control/space in profile token";
            }
        }
        const auto key = line[0] == "rlimit" && line.size() > 1 ? "rlimit:" + line[1] : line[0];
        if (!seen.insert(key).second) return Error() << "duplicate profile option";
    }
    return {};
}

Result<void> WorkProfileExperiment::ValidateConstructed(const Service& service,
                                                       const std::string& name) {
    const auto& attr = service.proc_attr_;
    if (service.name_ != name || service.filename_ != kSource ||
        service.args_ != std::vector<std::string>{kExecutable} ||
        attr.parsed_uid != std::optional<uid_t>{7500} || attr.gid != 7500 ||
        attr.supp_gids != std::vector<gid_t>{3003} || !service.capabilities_.has_value() ||
        !service.capabilities_->none() || attr.priority != 10 || service.oom_score_adjust_ != 700 ||
        service.task_profiles_ != std::vector<std::string>{"SCHED_SP_BACKGROUND"} ||
        service.flags_ != kParsedFlags) {
        return Error() << "complete fixed fixture profile not preserved";
    }
    if (attr.rlimits.size() != kLimits.size()) return Error() << "complete limits required";
    std::set<int> seen;
    for (const auto& [resource, limit] : attr.rlimits) {
        const auto expected = kLimits.find(resource);
        if (expected == kLimits.end() || !seen.insert(resource).second ||
            limit.rlim_cur != expected->second || limit.rlim_max != expected->second) {
            return Error() << "invalid or repeated resource limit";
        }
    }
    if (service.pid_ || service.start_order_ || service.crash_count_ || service.sigstop_ ||
        service.process_cgroup_empty_ || service.override_ || service.updatable_ ||
        service.disable_hardened_malloc_ || service.shared_kallsyms_file_ ||
        !attr.console.empty() || attr.stdio_to_kmsg || attr.ioprio_class != IoSchedClass_NONE ||
        attr.ioprio_pri || service.namespaces_.flags || !service.namespaces_.namespaces_to_enter.empty() ||
        !service.seclabel_.empty() || !service.sockets_.empty() || !service.files_.empty() ||
        !service.environment_vars_.empty() || !service.once_environment_vars_.empty() ||
        !service.reap_callbacks_.empty() || service.onrestart_.NumCommands() ||
        !service.interfaces_.empty() || !service.keycodes_.empty() ||
        !service.writepid_files_.empty() || service.timeout_period_.has_value() ||
        service.on_failure_reboot_target_.has_value() || service.mount_namespace_.has_value() ||
        service.swappiness_ != -1 || service.soft_limit_in_bytes_ != -1 ||
        service.limit_in_bytes_ != -1 || service.limit_percent_ != -1 ||
        !service.limit_property_.empty() || service.subcontext_) {
        return Error() << "unsupported or inherited instance state";
    }
    return {};
}

Result<WorkProfileExperiment::Instance> WorkProfileExperiment::Create(ServiceList& destination) {
    if (next_id_ == 0) return Error() << "instance sequence exhausted";
    const auto id = next_id_;
    next_id_ = id == std::numeric_limits<uint64_t>::max() ? 0 : id + 1;
    const std::string name = "andrix-profile-probe-" + std::to_string(id);
    if (destination.FindService(name)) return Error() << "instance name collision";
    if (auto valid = ValidateDefinition(definition_); !valid.ok()) return valid.error();

    // Parse into a private list. A malformed or unsupported definition must not
    // publish even a disabled partial service in the actual destination.
    ServiceList staging;
    ServiceParser parser(&staging, nullptr);
    if (auto parsed = parser.ParseSection({"service", name, kExecutable}, kSource, 1); !parsed.ok()) {
        return parsed.error();
    }
    int line_number = 2;
    for (const auto& line : definition_) {
        if (auto parsed = parser.ParseLineSection(TokenLine(line), line_number++); !parsed.ok()) {
            return parsed.error();
        }
    }
    if (auto ended = parser.EndSection(); !ended.ok()) return ended.error();
    if (staging.services_.size() != 1) return Error() << "one constructed instance required";
    auto instance = std::move(staging.services_.front());
    staging.services_.clear();
    if (auto valid = ValidateConstructed(*instance, name); !valid.ok()) return valid.error();

    // Only the launch bookkeeping changes. This newly constructed object has
    // never been started. No live service/PID/callback/restart state is cloned.
    instance->flags_ = SVC_ONESHOT | SVC_TEMPORARY;
    Service* pointer = instance.get();
    destination.AddService(std::move(instance));
    return Instance{id, pointer};
}

WorkProfileExperiment::Snapshot WorkProfileExperiment::Inspect(const Service& service) {
    return {service.name_, service.filename_, service.args_, service.proc_attr_.parsed_uid,
        service.proc_attr_.gid, service.proc_attr_.supp_gids, service.capabilities_,
        service.proc_attr_.priority, service.oom_score_adjust_, service.task_profiles_,
        service.proc_attr_.rlimits, service.seclabel_, service.flags_, service.pid_,
        service.start_order_, service.crash_count_, service.time_started_, service.time_crashed_,
        service.sigstop_, service.reap_callbacks_.size(), service.onrestart_.NumCommands(),
        service.environment_vars_, service.once_environment_vars_};
}
}  // namespace android::init
