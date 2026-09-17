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
    // Kernel UID/SID authenticate oneway; Binder does not provide its caller PID.
    oneway void stop(long scopeId, boolean crash);
}
