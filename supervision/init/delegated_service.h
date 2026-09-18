// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <signal.h>
#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "result.h"

namespace android::init {
class Descriptor;
class Epoll;
class Service;
class InterprocessFifo;
struct DelegatedInstance;

// Opt-in named-service profile under trusted init configuration. Initial proof
// support is deliberately narrower than the full existing service grammar.
struct DelegatedProfile;  // Defined beside Service so all consumers share its layout.

class DelegatedService {
  public:
    static Result<void> Configure(Service& service, const std::vector<std::string>& args);
    static Result<void> Validate(const Service& service);
    static Result<void> BeforeStart(Service& service);
    static Result<void> Prepare(Service& service, std::vector<Descriptor>& descriptors);
    static Result<void> Assign(Service& service, pid_t process);
    static void HoldActivation(Service& service, InterprocessFifo&& gate);
    static void NoProcess(Service& service);
    static void SetupFailed(Service& service);
    static bool Signal(Service& service, int signal);
    static bool DeferReap(Service& service, const siginfo_t& status);
    static bool WorkerExited(pid_t pid, const siginfo_t& status);
    static void Reaped(pid_t pid);
    static bool Enabled(const Service& service);
    static int RegisterWithLmkd(int socket, const Service& service);
    static bool Pending(const Service& service);
    static bool Removable(const Service& service);
    static bool Empty(const Service& service);
    static void Install(Epoll& epoll, std::function<void()> wake);
    static bool AnyStopping();
    static void Pump();
    static void AfterWait();
    static Result<void> StopExact(Service& service, std::string_view reference);
    // Lab fault controls are built only with this opt-in proof, never a product API.
    static Result<void> WorkerFault(Service& service, std::string_view reference,
                                    std::string_view operation);
    static Result<void> MemoryTest(Service& service, std::string_view reference);
};
}  // namespace android::init
