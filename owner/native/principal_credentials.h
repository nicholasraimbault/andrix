// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>

#include "principal_profile.h"

namespace andrix {
// The platform specializes a manager once. Work launch does not offer a UID,
// group or MAC mutation operation. These checks verify the resulting complete
// credentials before entering ordinary native code.
enum class PrincipalStage { Manager, Payload };

// Empty means the profile does not select the ordinary native worker role.
// A syntactically valid profile or a sealed FD never authorizes a MAC role.
std::string PrincipalManagerContext(const PrincipalProfile& profile);
std::string CheckPrincipalCredentials(const PrincipalProfile& profile,
                                      PrincipalStage stage);
// Checks a captured directory's owner, label and encryption format. It neither
// authenticates its CE storage identity/key identifier nor establishes current
// CE authority. The trusted account-home provider and admission own those facts.
// Home mode/group are owner controlled; launch does not require the creator's
// initial 0700 mode or primary GID to remain unchanged.
std::string CheckPrincipalHome(int fd, const PrincipalProfile& profile);
}  // namespace andrix
