// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lifecycle;

// Authenticated system_server observation, not an owner-home capability or a
// guarantee that all inode keys/processes were synchronously removed.
parcelable PlatformState {
    long instance;
    long generation;
    boolean available;
}
