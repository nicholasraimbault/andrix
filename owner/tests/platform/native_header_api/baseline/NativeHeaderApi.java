// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativePrincipalPins.Snapshot;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * Host only adapter of the header footprint tests to store, persistence and projection APIs
 * that predate creation plans: the reviewed c9264e4 and earlier d104e15 sources. It maps each
 * call onto the old Snapshot and static projection surface and ignores the signer rows, which
 * those sources cannot take. Their stores and host facades have no format to select. Only the
 * test harness selects it. Not product code.
 */
final class NativeHeaderApi {
    static NativeIdentityStore store(Path root) {
        return new NativeIdentityStore(root.toFile());
    }

    static PackageManagerService pm(Path root, boolean initialize) {
        return new PackageManagerService(root, initialize);
    }

    static Header project(NativeIdentityPersistence persistence, NativeIdentityStore.Loaded loaded,
            Snapshot snapshot, Map<Long, Set<String>> rows) {
        return NativeIdentityPersistence.projectReservation(loaded, snapshot);
    }

    static boolean reserve(NativeIdentityPersistence persistence, Snapshot snapshot,
            Map<Long, Set<String>> rows) {
        return persistence.reservePending(snapshot);
    }

    private NativeHeaderApi() {}
}
