// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <span>
#include <string>

#include "work_launch_protocol.h"
namespace andrix {
// Internal parts of the fixed complete launch transition, never caller selected
// credentials. The first vehicle inherits its declared bounded init profile.
std::string CheckLaunchStage(int aggregate_fd, int scope_fd,
                             LaunchObjectIdentity aggregate,
                             LaunchObjectIdentity scope);
std::string CheckOwnerEntry();
// Resource checks are separate from credentials. The current bounded resource
// class remains the existing vehicle's class, not a new product quota.
std::string CheckWorkLimits();
std::string CheckCapturedWorkScope(int aggregate_fd, int scope_fd,
                                  LaunchObjectIdentity aggregate,
                                  LaunchObjectIdentity scope);
bool OnlyDeclaredDescriptors(std::span<const int> allowed);
bool ManagementDescriptorsClosed(int remaining_description_fd);
}  // namespace andrix
