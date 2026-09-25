// SPDX-License-Identifier: Apache-2.0
// Role/home refusal checks on the host. No Android credential specialization claim.
#include "principal_credentials.h"

#include <fcntl.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>

using namespace andrix;
int main() {
  PrincipalProfile profile;
  profile.binding.instance = 1;
  profile.binding.generation = 2;
  profile.binding.user = 0;
  profile.binding.user_serial = 7;
  profile.binding.uid = profile.binding.gid = 10146;
  profile.binding.package_name = "dev.andrix.nativeaccount";
  profile.selinux_context = "u:r:andrix_native:s0:c146,c512";
  assert(ValidPrincipalProfile(profile));
  assert(PrincipalManagerContext(profile) ==
         "u:r:andrix_principal_manager:s0:c146,c512");
  // A label string is not authority to select another platform domain.
  for (const char* label : {"u:r:system_server:s0", "u:r:andrix_native:s00",
                            "u:r:andrix_native_other:s0", "u:r:andrix_owner:s0"}) {
    auto foreign = profile;
    foreign.selinux_context = label;
    assert(PrincipalManagerContext(foreign).empty());
    assert(!CheckPrincipalCredentials(foreign, PrincipalStage::Manager).empty());
    assert(!CheckPrincipalCredentials(foreign, PrincipalStage::Payload).empty());
  }
  assert(!CheckPrincipalCredentials(profile, static_cast<PrincipalStage>(27)).empty());
  // This host is not a platform-specialized principal manager or payload.
  assert(!CheckPrincipalCredentials(profile, PrincipalStage::Manager).empty());
  assert(!CheckPrincipalCredentials(profile, PrincipalStage::Payload).empty());
  assert(!CheckPrincipalHome(-1, profile).empty());
  int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(directory >= 0 && !CheckPrincipalHome(directory, profile).empty());
  assert(fcntl(directory, F_GETFD) >= 0);  // Borrowed handles remain owned by caller.
  close(directory);
  int path = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
  assert(path >= 0 && !CheckPrincipalHome(path, profile).empty());
  close(path);
  puts("principal role/home refusals checked; actual Android specialization unqualified");
}
