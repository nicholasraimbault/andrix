// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativePrincipalPins.Snapshot;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * Host only adapter of the header footprint tests to the creation plan sources. Every store and
 * every host facade is Format.V1: the rollback reader of the 78456b3 image and the legacy version
 * 1 writer paths, never the production V2 default of the facade. Every reservation is a
 * CreationPlan of the snapshot with the test's explicit signer rows. It adds no overload to
 * product code and selects no format from anything but this literal. Not product code.
 */
final class NativeHeaderApi {
    static NativeIdentityStore store(Path root) {
        return new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
    }

    static PackageManagerService pm(Path root, boolean initialize) {
        return new PackageManagerService(root, initialize, NativeIdentityStore.Format.V1);
    }

    static Header project(NativeIdentityPersistence persistence, NativeIdentityStore.Loaded loaded,
            Snapshot snapshot, Map<Long, Set<String>> rows) {
        return persistence.projectReservation(loaded,
                new NativeIdentityPersistence.CreationPlan(snapshot, rows));
    }

    static boolean reserve(NativeIdentityPersistence persistence, Snapshot snapshot,
            Map<Long, Set<String>> rows) {
        return persistence.reservePending(new NativeIdentityPersistence.CreationPlan(snapshot, rows));
    }

    private NativeHeaderApi() {}
}
