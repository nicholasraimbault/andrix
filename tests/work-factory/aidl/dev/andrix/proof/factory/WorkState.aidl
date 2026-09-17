// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.factory;
parcelable WorkState {
    long managerId;
    long workId;
    int phase;
    int guardianPid;
    int entryPid;
    boolean entryExited;
    int[] descendants;
    long pulses;
    long stopRequests;
    int stopCallerPid;
    String groupPath;
    boolean creationReturned;
    boolean guardianExited;
    int guardianStatus;
}
