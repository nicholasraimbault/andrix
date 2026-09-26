// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import java.io.File;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Immutable negative recovery view published by live PMS under its state lock.
 * Readers may run on scan, storage, preparation and keystore threads. This is
 * neither installed state nor an identity/grant decision. Names and actual kept
 * scan/settings paths only prevent destructive work; they never authorize code
 * or restore a package at a UID. No path here is a process-lifetime lease.
 *
 * A new view replaces the old one atomically. Deferred names and kept paths
 * accumulate until an explicit, separately owned maintenance/recovery operation
 * rebuilds the view. Holds are supplied from the actual PMS reservation union;
 * only its exact retirement protocol may remove a hold.
 */
final class NativePrincipalRecovery {
    private final Set<Integer> heldAppIds;
    private final Set<String> protectedNames;
    private final Set<String> deferredNames;
    private final Set<Path> keptCodePaths;
    private final boolean unidentifiedCode;

    NativePrincipalRecovery(Collection<Integer> heldAppIds, Collection<String> protectedNames,
            Collection<String> deferredNames, Collection<File> keptCodePaths,
            boolean unidentifiedCode) {
        TreeSet<Integer> ids = new TreeSet<>(Objects.requireNonNull(heldAppIds));
        for (int id : ids) if (id < 10000 || id > 19999) {
            throw new IllegalArgumentException("Native app ID outside platform app range");
        }
        this.heldAppIds = Collections.unmodifiableSet(ids);
        this.protectedNames = names(protectedNames);
        this.deferredNames = names(deferredNames);
        TreeSet<Path> paths = new TreeSet<>();
        for (File file : Objects.requireNonNull(keptCodePaths)) paths.add(path(file));
        this.keptCodePaths = Collections.unmodifiableSet(paths);
        this.unidentifiedCode = unidentifiedCode;
    }

    static NativePrincipalRecovery empty() {
        return new NativePrincipalRecovery(Set.of(), Set.of(), Set.of(), Set.of(), false);
    }

    NativePrincipalRecovery withHolds(Collection<Integer> held) {
        return new NativePrincipalRecovery(held, protectedNames, deferredNames,
                files(keptCodePaths), unidentifiedCode);
    }

    NativePrincipalRecovery protectNames(Collection<String> more) {
        TreeSet<String> names = new TreeSet<>(protectedNames);
        names.addAll(names(more));
        return new NativePrincipalRecovery(heldAppIds, names,
                deferredNames, files(keptCodePaths), unidentifiedCode);
    }

    NativePrincipalRecovery defer(String packageName, File codePath) {
        TreeSet<String> protectedCopy = new TreeSet<>(protectedNames);
        TreeSet<String> deferredCopy = new TreeSet<>(deferredNames);
        if (packageName != null) {
            if (packageName.isEmpty()) throw new IllegalArgumentException("Empty name");
            protectedCopy.add(packageName);
            deferredCopy.add(packageName);
        }
        TreeSet<Path> paths = new TreeSet<>(keptCodePaths);
        if (codePath != null) paths.add(path(codePath));
        return new NativePrincipalRecovery(heldAppIds,
                protectedCopy, deferredCopy, files(paths),
                unidentifiedCode);
    }

    NativePrincipalRecovery retainCode(File codePath) {
        return defer(null, Objects.requireNonNull(codePath));
    }

    NativePrincipalRecovery withUnidentifiedCode() {
        return new NativePrincipalRecovery(heldAppIds, protectedNames, deferredNames,
                files(keptCodePaths), true);
    }

    boolean holdsAppId(int appId) { return heldAppIds.contains(appId); }
    boolean hasHolds() { return !heldAppIds.isEmpty(); }
    boolean protectsName(String packageName) {
        return packageName != null && protectedNames.contains(packageName);
    }
    boolean defersName(String packageName) {
        return packageName != null && deferredNames.contains(packageName);
    }
    boolean hasUnidentifiedCode() { return unidentifiedCode && hasHolds(); }
    boolean hasUnresolvedHolds() {
        return hasHolds() && (unidentifiedCode || !deferredNames.isEmpty());
    }

    /** An observed directory UID is only a reason to withhold deletion or re-ownership. */
    boolean protectsObservedUid(int uid) {
        return uid >= 0 && heldAppIds.contains(uid % 100000);
    }

    /** First adapter is conservative across users; this is not positive UID ownership. */
    boolean protectsKeystore(int appId) { return holdsAppId(appId); }

    boolean keepsCodePath(File candidate) {
        Path value = path(candidate);
        for (Path kept : keptCodePaths) {
            // Keep both an exact object and an enclosing deletion candidate.
            // Component boundaries matter: /pkg/a does not cover /pkg/ab.
            if (value.startsWith(kept) || kept.startsWith(value)) return true;
        }
        return false;
    }

    /**
     * Only the caller's actual data-app scan/orphan root gets the broad unknown
     * preservation rule. It is not a general exemption for staging or paths
     * selected by an app. The caller records each retained candidate explicitly.
     */
    boolean preservesUnidentifiedCode(File candidate, File dataAppRoot) {
        Path value = path(candidate), parent = path(dataAppRoot);
        return hasUnidentifiedCode() && !value.equals(parent) && value.startsWith(parent);
    }

    private static Collection<File> files(Collection<Path> paths) {
        java.util.List<File> files = new java.util.ArrayList<>(paths.size());
        for (Path path : paths) files.add(path.toFile());
        return files;
    }

    private static Set<String> names(Collection<String> input) {
        TreeSet<String> names = new TreeSet<>();
        for (String name : Objects.requireNonNull(input)) {
            if (Objects.requireNonNull(name).isEmpty()) throw new IllegalArgumentException("Empty name");
            names.add(name);
        }
        return Collections.unmodifiableSet(names);
    }

    private static Path path(File file) {
        Objects.requireNonNull(file);
        if (!file.isAbsolute()) throw new IllegalArgumentException("Expected actual absolute code path");
        // No realpath, traversal, filesystem scan or guessed package directory.
        return file.toPath().normalize();
    }
}
