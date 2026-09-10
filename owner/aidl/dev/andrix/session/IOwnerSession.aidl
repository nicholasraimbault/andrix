// SPDX-License-Identifier: Apache-2.0
package dev.andrix.session;

import dev.andrix.session.Attachment;

// Local experimental interface, not a production stable/VINTF API. Identity is
// authenticated by Binder UID + SID. Booleans come only from the signer-mapped
// console TCB's Android state checks; they are not accepted from ordinary APKs.
interface IOwnerSession {
    Attachment attach(int rows, int columns, boolean uiEligible, boolean userUnlocked);
    boolean renew(long generation, boolean uiEligible, boolean userUnlocked);
    void resize(long generation, int rows, int columns);
    void detach(long generation);
    void endSession(long generation);
    String status();
}
