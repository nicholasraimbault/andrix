// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lifecycle;

// The coordinator supplies its process-lifetime object to keepWork. Stop targets
// this Binder, not a reusable PID/init service name. Native authenticates actual
// UID1000 + system_server SID, matches its immutable workId and requires a positive
// registration (including a still-pending grant), then exits directly. One grant
// attempt is made per native work/process lifetime; Android init reaps its group.
// No attach authority.
// Oneway delivery is a stop request, NOT process-group cleanup acknowledgement.
oneway interface IKeptWork {
    void stop(long workId, long keepRegistration);
}
