// SPDX-License-Identifier: Apache-2.0
package dev.andrix.session;

import dev.andrix.session.Attachment;
import android.os.IBinder;

// Local experimental interface, not a production stable/VINTF API. Identity is
// authenticated by Binder UID + SID. Booleans come only from the signer-mapped
// console TCB's Android state checks; they are not accepted from ordinary APKs.
interface IOwnerSession {
    // The named console sends its own process-local Binder, not a supplied handle.
    // Death ends the native session even if the UI attachment was already closed.
    void registerController(IBinder lifetime);
    Attachment attach(int rows, int columns, boolean uiEligible, boolean userUnlocked);
    boolean renew(long generation, boolean uiEligible, boolean userUnlocked);
    void resize(long generation, int rows, int columns);
    void detach(long generation);
    void endSession(long generation);
    String status();
}
