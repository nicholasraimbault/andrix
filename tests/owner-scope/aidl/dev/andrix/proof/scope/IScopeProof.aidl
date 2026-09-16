// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.scope;

import dev.andrix.proof.scope.ScopeState;

// Fixed lab fixture only, not an owner execution or resource-management API.
interface IScopeProof {
    ScopeState observe();
    boolean hold(long scopeId);
    boolean release(long scopeId);
    // The counter in observe shows that a rejected old/wrong request was processed.
    // A matching request exits this exact guardian. Transport return is not cleanup.
    oneway void stop(long scopeId, boolean crash);
}
