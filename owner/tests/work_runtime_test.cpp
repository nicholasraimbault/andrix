// SPDX-License-Identifier: Apache-2.0
// Refusal/ownership checks only. Real cgroup execution is a separate fixture.
#include "work_runtime.h"

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
