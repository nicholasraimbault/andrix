// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <sys/types.h>

namespace andrix {

// Return a diagnostic on failure, empty on success. No caller-controlled paths.
std::string check_identity();
std::string check_resource_bounds(pid_t coordinator = 0);
// A successful descriptor refers to the genuine existing encrypted home; caller
// owns it. Never create a home here or fall back to another filesystem/path.
int open_ce_home(std::string* error);
// Reads encryption metadata only. Key management/status remains vold's authority;
// Android UserManager plus the controller process lifetime gate session access.
bool ce_policy_valid(int home_fd, std::string* error);

}  // namespace andrix
