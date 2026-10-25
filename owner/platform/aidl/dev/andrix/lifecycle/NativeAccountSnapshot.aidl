// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lifecycle;

import dev.andrix.lifecycle.NativeAccountRow;

// Cached Package Manager metadata. No CE, login, designation or execution grant.
parcelable NativeAccountSnapshot {
    const int AVAILABLE = 1;
    const int UNAVAILABLE = 2;
    const int UNSUPPORTED_USER = 3;

    const int STORE_READY = 1;
    const int STORE_MISSING = 2;
    const int STORE_DAMAGED = 3;
    const int STORE_CONFLICT = 4;
    const int STORE_NEWER = 5;
    const int STORE_UNAVAILABLE = 6;

    int userId;
    long userSerial; // -1 if authoritative serial unavailable.
    int status;
    int store;
    boolean complete;
    NativeAccountRow[] rows; // At most 64. Empty means no accounts only when AVAILABLE and complete.
}
