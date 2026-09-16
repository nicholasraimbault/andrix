// SPDX-License-Identifier: Apache-2.0
package dev.andrix.session;

import dev.andrix.session.Attachment;
import dev.andrix.session.WorkInfo;
import android.os.IBinder;

// Local experimental interface, not a production stable/VINTF API. Identity is
// authenticated by Binder UID + SID. Booleans come only from the signer-mapped
// console TCB's Android state checks; they are not accepted from ordinary APKs.
interface IOwnerSession {
    // The named console sends its own process-local Binder, not a supplied handle.
    // Plain work ends on process death. Explicit kept work retires its presentation
    // instead, provided Android's independent lifecycle/Keep grant remains valid.
    void registerController(IBinder lifetime);
    // Resume only output already parsed by this controller process. A different
    // native session resets parser state; offsets never replace Binder identity.
    Attachment attach(int rows, int columns, boolean uiEligible, boolean userUnlocked,
                      long previousSessionId, long nextOutputOffset);
    boolean renew(long generation, boolean uiEligible, boolean userUnlocked);
    boolean acknowledgeOutput(long generation, long nextOutputOffset);
    void resize(long generation, int rows, int columns);
    void detach(long generation);
    void endSession(long generation);
    String status();
    // Append new transactions: never renumber the existing plain-session API.
    // Explicit NEW kept terminal; never adopts or replaces an existing plain shell.
    Attachment startKept(int rows, int columns, boolean uiEligible, boolean userUnlocked);
    // Stop is computation-only, not an attach/read/input capability. The daemon
    // hosts one immutable work identity for its whole process lifetime.
    void stopKeptWork();
    // Append only. Reading metadata neither creates work/presentations nor
    // renews an attachment or retention grant. Requires the registered caller.
    WorkInfo describeWork();
    // Target this exact service Binder AND workId, never a freshly resolved
    // service name. No attachment lease or parser is needed. True means a Stop
    // request was accepted, not that Android finished group cleanup or storage I/O.
    boolean stopWork(long workId);
}
