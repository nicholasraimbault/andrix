// SPDX-License-Identifier: Apache-2.0
// Uses the actual Android init parser and Service objects. No service is executed.
#include "work_profile_experiment.h"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>
#include <sys/resource.h>
#include <gtest/gtest.h>

#include "service_list.h"

namespace android::init {
namespace {
using Definition = WorkProfileExperiment::TrustedDefinition;
using Line = WorkProfileExperiment::TokenLine;
constexpr char kExec[] = "/system_ext/bin/andrix-factory-guardian-probe";

void CheckProfile(const WorkProfileExperiment::Snapshot& value) {
    EXPECT_EQ(value.parsed_uid, std::optional<uid_t>{7500});
    EXPECT_EQ(value.gid, 7500U);
    EXPECT_EQ(value.supp_gids, (std::vector<gid_t>{3003}));
    ASSERT_TRUE(value.capabilities.has_value());
    EXPECT_TRUE(value.capabilities->none());
    EXPECT_EQ(value.args, (std::vector<std::string>{kExec}));
    EXPECT_EQ(value.priority, 10);
    EXPECT_EQ(value.oom_score_adjust, 700);
    EXPECT_EQ(value.task_profiles, (std::vector<std::string>{"SCHED_SP_BACKGROUND"}));
    const std::map<int, rlim_t> limits = {{RLIMIT_NPROC,32}, {RLIMIT_NOFILE,128},
                                       {RLIMIT_CORE,0}, {RLIMIT_FSIZE,67108864}};
    ASSERT_EQ(value.rlimits.size(), limits.size());
    std::set<int> seen;
    for (const auto& [resource, bound] : value.rlimits) {
        ASSERT_TRUE(limits.contains(resource));
        EXPECT_TRUE(seen.insert(resource).second);
        EXPECT_EQ(bound.rlim_cur, limits.at(resource));
        EXPECT_EQ(bound.rlim_max, limits.at(resource));
    }
    EXPECT_EQ(value.flags, static_cast<unsigned>(SVC_ONESHOT | SVC_TEMPORARY));
    EXPECT_EQ(value.pid, 0);
    EXPECT_EQ(value.crash_count, 0);
    EXPECT_EQ(value.start_order, 0U);
    EXPECT_EQ(value.time_started.time_since_epoch().count(), 0);
    EXPECT_EQ(value.time_crashed.time_since_epoch().count(), 0);
    EXPECT_FALSE(value.sigstop);
    EXPECT_EQ(value.reap_callback_count, 0U);
    EXPECT_EQ(value.onrestart_command_count, 0U);
    EXPECT_TRUE(value.environment_vars.empty());
    EXPECT_TRUE(value.once_environment_vars.empty());
}

Definition Change(const std::string& option, Line replacement) {
    auto result = WorkProfileExperiment::FixtureDefinition();
    auto found = std::find_if(result.begin(),result.end(),[&](const auto& line){return line[0]==option;});
    if (found == result.end()) std::abort();
    if (replacement.empty()) result.erase(found);
    else *found = std::move(replacement);
    return result;
}

TEST(WorkProfileExperiment, ActualParserBuildsFreshCompleteInstances) {
    auto definition = WorkProfileExperiment::FixtureDefinition();
    WorkProfileExperiment factory(definition);
    definition[0][1] = "0"; // The stored image definition is an independent immutable value.
    ServiceList destination;
    auto first = factory.Create(destination);
    ASSERT_TRUE(first.ok()) << first.error();
    auto first_snapshot = WorkProfileExperiment::Inspect(*first->service);
    CheckProfile(first_snapshot);
    first->service->set_sigstop(true);
    first->service->set_oneshot(false);
    first->service->set_filename("mutated first instance only");
    first->service->AddReapCallback([](const siginfo_t&) {});
    auto second = factory.Create(destination);
    ASSERT_TRUE(second.ok()) << second.error();
    ASSERT_EQ(destination.size(), 2U);
    EXPECT_NE(first->id, second->id);
    EXPECT_NE(first->service, second->service);
    EXPECT_NE(first->service->name(), second->service->name());
    CheckProfile(WorkProfileExperiment::Inspect(*second->service));
    auto mutated = WorkProfileExperiment::Inspect(*first->service);
    EXPECT_TRUE(mutated.sigstop);
    EXPECT_EQ(mutated.reap_callback_count, 1U);
    EXPECT_EQ(mutated.filename, "mutated first instance only");
}

TEST(WorkProfileExperiment, FailedCollisionConsumesSequenceWithoutReplacingService) {
    ServiceList destination;
    WorkProfileExperiment first(WorkProfileExperiment::FixtureDefinition());
    auto kept = first.Create(destination);
    ASSERT_TRUE(kept.ok()) << kept.error();
    WorkProfileExperiment second(WorkProfileExperiment::FixtureDefinition());
    auto collision = second.Create(destination);
    EXPECT_FALSE(collision.ok());
    ASSERT_EQ(destination.size(), 1U);
    EXPECT_EQ(destination.FindService(kept->service->name()), kept->service);
    auto fresh = second.Create(destination);
    ASSERT_TRUE(fresh.ok()) << fresh.error();
    EXPECT_EQ(fresh->id, 2U);
    destination.RemoveService(*kept->service);
    auto next = second.Create(destination);
    ASSERT_TRUE(next.ok()) << next.error();
    EXPECT_EQ(next->id, 3U);
    EXPECT_EQ(next->service->name(), "andrix-profile-probe-3");
    // This is a factory-local construction sequence, not a kernel lifetime handle.
}

TEST(WorkProfileExperiment, MissingOrUnsafeFieldsNeverPublishPartialService) {
    std::vector<Definition> bad = {
        {}, Change("user",{}), Change("user",{"user","0"}),
        Change("user",{"user","not_a_uid"}), Change("group",{"group","7500"}),
        Change("group",{"group","7500","3003","1000"}),
        Change("capabilities",{}), Change("capabilities",{"capabilities","SETUID"}),
        Change("capabilities",{"capabilities","NOT_A_CAPABILITY"}),
        Change("priority",{}), Change("priority",{"priority","0"}),
        Change("oom_score_adjust",{"oom_score_adjust","0"}),
        Change("task_profiles",{"task_profiles","SCHED_SP_FOREGROUND"}),
        Change("task_profiles",{}), Change("oneshot",{}), Change("disabled",{}),
        Change("rlimit",{"rlimit","nproc","33","33"}), Change("rlimit",{}),
        Change("user",{"user","${sys.some_uid}"}), Change("user",{"user","7500 extra"}),
        Change("priority",{"priority","10","11"}),
    };
    const std::vector<Line> extra = {{"user","7500"}, {"rlimit","nproc","32","32"},
        {"rlimit","6","32","32"}, {"setenv","A","B"}, {"namespace","pid"},
        {"seclabel","u:r:andrixd:s0"}, {"onrestart","restart","other"},
        {"socket","unrelated","stream","0666","root","root"}, {"critical"},
        {"updatable"}, {"override"}, {"unknown_option"}, {}};
    for (const auto& line : extra) {
        auto definition = WorkProfileExperiment::FixtureDefinition();
        definition.push_back(line);bad.push_back(std::move(definition));
    }
    for (size_t index=0; index<bad.size(); ++index) {
        SCOPED_TRACE(index);
        ServiceList destination;
        WorkProfileExperiment good(WorkProfileExperiment::FixtureDefinition());
        auto existing=good.Create(destination);
        ASSERT_TRUE(existing.ok()) << existing.error();
        WorkProfileExperiment rejected(std::move(bad[index]));
        // Consume the colliding first ID, then exercise actual profile rejection.
        EXPECT_FALSE(rejected.Create(destination).ok());
        EXPECT_FALSE(rejected.Create(destination).ok());
        EXPECT_FALSE(rejected.Create(destination).ok());
        EXPECT_EQ(destination.size(),1U);
        EXPECT_EQ(destination.FindService(existing->service->name()),existing->service);
        CheckProfile(WorkProfileExperiment::Inspect(*existing->service));
    }
}

TEST(WorkProfileExperiment, ExistingTemporaryConstructorHasAbsentCapabilityProfile) {
    auto temporary = Service::MakeTemporaryOneshotService(
        {"exec_background","-","7500","7500","3003","--",kExec});
    ASSERT_TRUE(temporary.ok()) << temporary.error();
    const auto value = WorkProfileExperiment::Inspect(**temporary);
    EXPECT_EQ(value.parsed_uid,std::optional<uid_t>{7500});
    EXPECT_EQ(value.gid,7500U);
    EXPECT_EQ(value.supp_gids,(std::vector<gid_t>{3003}));
    EXPECT_FALSE(value.capabilities.has_value());
    EXPECT_TRUE(value.rlimits.empty());
    EXPECT_TRUE(value.task_profiles.empty());
    EXPECT_EQ(value.priority,0);
    EXPECT_NE(value.oom_score_adjust,700);
    // No process was launched and no credentials/capabilities were changed.
}
}  // namespace
}  // namespace android::init
