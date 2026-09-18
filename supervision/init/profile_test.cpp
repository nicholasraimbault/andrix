// SPDX-License-Identifier: Apache-2.0
// Actual init parser construction, with no service launch or credential changes.
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <string>
#include <vector>

#include "delegated_service.h"
#include "epoll.h"
#include "service.h"
#include "service_list.h"
#include "service_parser.h"

namespace android::init {
void TestDelegatedEventRetirement(Epoll&, android::base::unique_fd&);
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
TEST(DelegatedServiceEvents, DescriptorNumberStaysOwnedUntilDeferredHandlerRemoval) {
    using android::base::unique_fd;
    Epoll epoll;
    ASSERT_TRUE(epoll.Open().ok());
    unique_fd old(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(old.get(), 0);
    const int old_number = old.get();
    unique_fd replacement;
    bool registration_ok = false;
    int calls = 0;
    ASSERT_TRUE(epoll.RegisterHandler(old.get(), [&] {
                         ++calls;
                         TestDelegatedEventRetirement(epoll, old);
                         EXPECT_LT(old.get(), 0);
                         EXPECT_GE(fcntl(old_number, F_GETFD), 0);
                         replacement.reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
                         EXPECT_NE(replacement.get(), old_number);
                         registration_ok =
                                 epoll.RegisterHandler(replacement.get(), [&] { ++calls; }).ok();
                     }).ok());
    const uint64_t pulse = 1;
    ASSERT_EQ(write(old.get(), &pulse, sizeof(pulse)), static_cast<ssize_t>(sizeof(pulse)));
    auto delivered = epoll.Wait(std::chrono::milliseconds(500));
    ASSERT_TRUE(delivered.ok());
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(registration_ok);
    DelegatedService::AfterWait();
    EXPECT_EQ(fcntl(old_number, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    unique_fd reused(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_EQ(reused.get(), old_number);
    EXPECT_TRUE(epoll.RegisterHandler(reused.get(), [&] { calls += 10; }).ok());
    ASSERT_EQ(write(replacement.get(), &pulse, sizeof(pulse)), static_cast<ssize_t>(sizeof(pulse)));
    ASSERT_TRUE(epoll.Wait(std::chrono::milliseconds(500)).ok());
    EXPECT_EQ(calls, 2);
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
