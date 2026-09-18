// SPDX-License-Identifier: Apache-2.0
// Actual init parser construction, with no service launch or credential changes.
#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <vector>

#include "delegated_service.h"
#include "service.h"
#include "service_list.h"
#include "service_parser.h"

namespace android::init {
namespace {
using Lines = std::vector<std::vector<std::string>>;
Lines Profile() {
    return {{"user", "7500"},
            {"group", "7500", "3003"},
            {"disabled"},
            {"capabilities"},
            {"seclabel", "u:r:andrixd:s0"},
            {"priority", "10"},
            {"oom_score_adjust", "700"},
            {"task_profiles", "SCHED_SP_BACKGROUND"},
            {"rlimit", "nproc", "32", "32"},
            {"rlimit", "nofile", "128", "128"},
            {"rlimit", "core", "0", "0"},
            {"rlimit", "fsize", "67108864", "67108864"},
            {"delegated_scope", "268435456", "0", "64", "8"}};
}
Result<void> Parse(ServiceList& services, const Lines& definition) {
    ServiceParser parser(&services, nullptr);
    OR_RETURN(parser.ParseSection({"service", "delegated-test", "/system_ext/bin/fixed-bootstrap"},
                                  "/system_ext/etc/init/delegated-test.rc", 1));
    int line = 2;
    for (auto option : definition) OR_RETURN(parser.ParseLineSection(std::move(option), line++));
    return parser.EndSection();
}
TEST(DelegatedServiceProfile, ParsesCompleteDeclaredProfileWithoutStarting) {
    ServiceList services;
    auto parsed = Parse(services, Profile());
    ASSERT_TRUE(parsed.ok()) << parsed.error();
    ASSERT_EQ(services.size(), 1U);
    auto* service = services.FindService("delegated-test");
    ASSERT_NE(service, nullptr);
    EXPECT_EQ(service->pid(), 0);
    EXPECT_FALSE(service->IsRunning());
    EXPECT_EQ(service->uid(), 7500U);
    EXPECT_EQ(service->gid(), 7500U);
    EXPECT_EQ(service->seclabel(), "u:r:andrixd:s0");
    EXPECT_TRUE(DelegatedService::Validate(*service).ok());
    EXPECT_FALSE(DelegatedService::Pending(*service));
}
TEST(DelegatedServiceProfile, RejectsIncompleteAndUnsupportedProfiles) {
    for (const char* option : {"user", "group", "capabilities", "seclabel", "oom_score_adjust"}) {
        auto lines = Profile();
        std::erase_if(lines, [&](const auto& line) { return line[0] == option; });
        ServiceList services;
        auto parsed = Parse(services, lines);
        EXPECT_FALSE(parsed.ok()) << option;
        EXPECT_EQ(services.size(), 0U);
    }
    for (const std::vector<std::string>& extra : {std::vector<std::string>{"gentle_kill"},
                                                  {"console"},
                                                  {"updatable"},
                                                  {"namespace", "mnt"},
                                                  {"file", "/dev/null", "r"},
                                                  {"memcg.limit_in_bytes", "268435456"}}) {
        auto lines = Profile();
        lines.push_back(extra);
        ServiceList services;
        EXPECT_FALSE(Parse(services, lines).ok()) << extra[0];
        EXPECT_EQ(services.size(), 0U);
    }
    for (auto replacement : {std::vector<std::string>{"capabilities", "SETUID"},
                             {"task_profiles", "MemoryLow"},
                             {"delegated_scope", "268435456", "1", "64", "8"}}) {
        auto lines = Profile();
        for (auto& line : lines)
            if (line[0] == replacement[0]) line = replacement;
        ServiceList services;
        EXPECT_FALSE(Parse(services, lines).ok()) << replacement[0];
        EXPECT_EQ(services.size(), 0U);
    }
}
TEST(DelegatedServiceProfile, ReapCallbacksRequireAnExplicitSemanticsExtension) {
    ServiceList services;
    ASSERT_TRUE(Parse(services, Profile()).ok());
    auto* service = services.FindService("delegated-test");
    ASSERT_NE(service, nullptr);
    service->AddReapCallback([](const siginfo_t&) {});
    EXPECT_FALSE(DelegatedService::Validate(*service).ok());
    EXPECT_EQ(service->pid(), 0);
}
TEST(DelegatedServiceProfile, UnsupportedExecWaitRefusesBeforeFlagMutation) {
    ServiceList services;
    ASSERT_TRUE(Parse(services, Profile()).ok());
    auto* service = services.FindService("delegated-test");
    ASSERT_NE(service, nullptr);
    auto flags = service->flags();
    EXPECT_FALSE(service->ExecStart().ok());
    EXPECT_EQ(service->flags(), flags);
    EXPECT_EQ(service->pid(), 0);
    EXPECT_FALSE(Service::is_exec_service_running());
}
}  // namespace
}  // namespace android::init
