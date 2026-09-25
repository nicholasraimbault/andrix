// SPDX-License-Identifier: Apache-2.0
// Refusal/ownership checks only. Real cgroup execution is a separate fixture.
#include "work_runtime.h"

#include <fcntl.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdio>

#include "work_catalog.h"

using namespace andrix;
struct Authority final : WorkRuntimeAuthority {
  int calls = 0;
  AdmissionResult Admit(const std::shared_ptr<WorkAdmission>&) override {
    ++calls;
    return AdmissionResult::Invalid;
  }
  AdmissionResult Prepared(const std::shared_ptr<WorkAdmission>&) override {
    ++calls;
    return AdmissionResult::Invalid;
  }
  AdmissionResult Release(const std::shared_ptr<WorkAdmission>&) override {
    ++calls;
    return AdmissionResult::Invalid;
  }
  AdmissionResult Retire(const std::shared_ptr<WorkAdmission>&) override {
    ++calls;
    return AdmissionResult::Invalid;
  }
};
int main() {
  auto authority = std::make_shared<Authority>();
  WorkRuntimeConfig config;
  config.jobs = 2;
  config.launcher = "/not-a-usable-bootstrap";
  config.cleanup = {8, 64, 512, 4096, 32};
  WorkRuntime runtime(config, authority);
  assert(!runtime.valid());
  PrincipalProfile principal;
  principal.binding = {1, 1, 0, 0, 10146, 10146, "dev.andrix.nativeaccount"};
  principal.selinux_context = "u:r:andrix_native:s0";
  assert(ValidPrincipalProfile(principal));
  assert(!authority->AcceptsPrincipal(principal));
  auto principal_config = config;
  principal_config.principal = principal;
  principal_config.principal_home = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(principal_config.principal_home >= 0);
  {
    WorkRuntime unbound(principal_config, authority);
    assert(!unbound.valid() && authority->calls == 0);
  }
  close(principal_config.principal_home);
  WorkCatalog catalog(1, {1, 1, 1, {}, 10, 10, 10});
  auto reserved = catalog.Reserve(catalog.OpenStream(), 1);
  LaunchFailure failure;
  int description =
      SealLaunch({"/owner/program", {"program"}, {}, "/owner"}, {}, failure);
  assert(description >= 0);
  auto input = catalog.Prepare(reserved.work, description, {-1, -1, -1});
  close(description);
  auto accepted = catalog.Start(reserved.work, input.identity);
  assert(accepted.backend && catalog.usage().creators == 1);
  int error = 0;
  assert(!runtime.Submit(accepted, error) && error == ESHUTDOWN);
  assert(accepted.backend && accepted.stdio_lease.available() &&
         authority->calls == 0);
  // Refusal does not consume or silently settle the still-owned creator.
  assert(catalog.usage().creators == 1);
  accepted.backend.Abort(error);
  accepted.stdio_lease.Release();
  assert(!accepted.backend.AdmissionFinished(AdmissionResult::Stopped));
  assert(reserved.work.Inspect().work.complete &&
         catalog.usage().creators == 0);
  runtime.Poll();
  assert(runtime.drained());
  puts(
      "{\"invalid_environment_refused_without_creation\":true,\"creator_ticket_"
      "retained_on_submit_refusal\":true,\"real_kernel_runtime_qualified\":"
      "false}");
}
