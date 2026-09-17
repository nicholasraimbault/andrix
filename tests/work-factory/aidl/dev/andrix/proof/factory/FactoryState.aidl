// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.factory;
parcelable FactoryState {
    long managerId;
    int managerPid;
    String backend;
    String groupPath;
    int reserved;
    int created;
    int removed;
    boolean allocatorBlocked;
}
