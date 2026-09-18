// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <string>

#include "work_launch_protocol.h"
namespace andrix {
// Internal parts of the fixed complete launch transition, never caller selected
// credentials. The first vehicle inherits its declared bounded init profile.
std::string CheckLaunchStage(int aggregate_fd, int scope_fd,
                             LaunchObjectIdentity aggregate,
                             LaunchObjectIdentity scope);
std::string CheckOwnerEntry();
bool ManagementDescriptorsClosed(int remaining_description_fd);
}  // namespace andrix
