// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.scope;

parcelable ScopeState {
    long scopeId;
    int guardianPid;
    int phase;
    int entryPid;
    boolean entryExited;
    int[] descendants;
    long pulses;
    long stopRequests;
    int lastStopCallerPid;
}
