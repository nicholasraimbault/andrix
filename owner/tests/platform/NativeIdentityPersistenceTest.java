// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.system.Os;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativePrincipalPins.Phase;
import com.android.server.pm.NativePrincipalPins.Pin;
import com.android.server.pm.NativePrincipalPins.Record;
import com.android.server.pm.NativePrincipalPins.Snapshot;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Actual per target transactions over the actual store, the strict writer fixture, real core
 * pins and Android API facades. Injected directory sync failures model refused or lost
 * acknowledgements at every sync point. This is not PMS integration, Android I/O or power
 * loss qualification.
 */
public final class NativeIdentityPersistenceTest {
    private static final String LINEAGE = "0123456789abcdef0123456789abcdef";
    private static final String OTHER_LINEAGE = "fedcba9876543210fedcba9876543210";
    private static final Set<String> SIGNERS = Set.of("a".repeat(64));
    private static final Set<String> OTHER_SIGNERS = Set.of("a".repeat(64), "b".repeat(64));
    private static final String PKG = "dev.andrix.account";
    private static final String PKG_B = "dev.andrix.second";
    private static final String PKG_C = "dev.andrix.unrelated";
    private static final String PKG_D = "dev.andrix.damaged";
    private static final String PKG_E = "dev.andrix.stale";
    private static final int APP = 10123, APP_B = 10124, APP_C = 10200, APP_D = 10201;
    private static final int APP_E = 10202;
    private static final long SERIAL = 7;
    private static final int LIMIT = 400; // Bound on injected failure points per operation.
    private static Path base;

    private static final class Env {
        final Path root;
        final NativeIdentityStore store;
        final NativeIdentityPersistence persistence;

        Env(String name, boolean initialize) throws Exception {
            root = Files.createDirectory(base.resolve(name)).resolve("store");
            store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
            persistence = new NativeIdentityPersistence(store);
            // Explicit test setup. The helper itself never initializes a store.
            if (initialize && !store.initializeNew(LINEAGE)) throw new AssertionError(name);
        }

        Header header() {
            NativeIdentityStore.Loaded loaded = store.load();
            assert loaded.header.status == NativeIdentityStore.Status.VALID;
            return loaded.header.value;
        }

        Path slot(int appId) {
            return root.resolve("slots").resolve(Integer.toString(appId));
        }

        // New store and helper objects over the same files. No memory survives.
        NativeIdentityPersistence restarted() {
            return new NativeIdentityPersistence(new NativeIdentityStore(root.toFile(),
                    NativeIdentityStore.Format.V1));
        }
    }

    // Target retiring with a durable marker, plus an intact unrelated slot, an unrelated slot
    // whose body cannot be decoded and a stale reservation that never got a directory.

    // The core's retiring target and the unrelated slots beside it.
    private static final class Retiring {
        final NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin;
        Record record;
        Map<String, String> unrelated;
    }

    public static void main(String[] args) throws Exception {
        if (!NativeIdentityPersistenceTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        base = Files.createDirectory(Path.of(args[0]).resolve("native-identity-persistence"));
        String group = args.length > 1 ? args[1] : "all";
        if (!Set.of("all", "basic", "reserve", "publish", "mark", "release").contains(group)) {
            throw new IllegalArgumentException("Unknown test group");
        }
        if (group.equals("all") || group.equals("basic")) {
            run("no initialization", NativeIdentityPersistenceTest::noInitialization);
            run("creation", NativeIdentityPersistenceTest::createConfirmAndRestart);
            run("pending order", NativeIdentityPersistenceTest::pendingReservedTogether);
            run("refusals", NativeIdentityPersistenceTest::refusals);
            run("retirement", NativeIdentityPersistenceTest::retirementMonotonic);
            run("header damage", NativeIdentityPersistenceTest::headerOnlyDamage);
            run("creating retirement", NativeIdentityPersistenceTest::creatingEntryCompletesBeforeOmission);
            run("no inferred deletion", NativeIdentityPersistenceTest::noSnapshotDerivedDeletion);
            run("release refusals", NativeIdentityPersistenceTest::releaseRefusals);
            run("directory guards", NativeIdentityPersistenceTest::creationDirectoryGuards);
        }
        if (group.equals("all") || group.equals("reserve")) run("reserve faults",
                NativeIdentityPersistenceTest::reserveWithUnknownOutcomes);
        if (group.equals("all") || group.equals("publish")) run("publish faults",
                NativeIdentityPersistenceTest::publishWithUnknownOutcomes);
        if (group.equals("all") || group.equals("mark")) run("marker faults",
                NativeIdentityPersistenceTest::markWithUnknownOutcomes);
        if (group.equals("all") || group.equals("release")) run("release faults",
                NativeIdentityPersistenceTest::releaseWithUnknownOutcomes);
        assert Os.allClosed();
        System.out.println("Native identity persistence transactions passed; Android unqualified");
    }

    // The version 1 format's reservation plan with an owned signer row for every record, as
    // the manager supplies for its own issuances. Rows never change version 1 bytes.
    private static NativeIdentityPersistence.CreationPlan plan(Snapshot snapshot) {
        Map<Long, Set<String>> rows = new TreeMap<>();
        for (Record record : snapshot.records) rows.put(record.id, SIGNERS);
        return new NativeIdentityPersistence.CreationPlan(snapshot, rows);
    }

    private interface Check { void run() throws Exception; }
    private static void run(String name, Check check) throws Exception {
        long start = System.nanoTime();
        System.out.println("Starting " + name);
        check.run();
        System.out.println("Passed " + name + " in " + (System.nanoTime() - start) / 1_000_000 + "ms");
    }

    private static void noInitialization() throws Exception {
        Env env = new Env("absent", false);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(4);
        Record r = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL).record();
        assert !p.load().enumerationComplete && !p.load().creationReady();
        assert !p.reservePending(plan(pins.snapshotForWrite()));
        assert !p.publish(r, SIGNERS) && p.binding(r) == null;
        assert !p.markRetiring(r, SIGNERS, block(r));
        assert !Files.exists(env.root) && env.store.pendingInitializationNames().isEmpty();
        // A present but headerless layout is not a fresh lineage either.
        Files.createDirectories(env.root.resolve("slots"));
        Map<String, String> before = tree(env.root);
        assert p.load().header.status == NativeIdentityStore.Status.MISSING;
        assert !p.reservePending(plan(pins.snapshotForWrite())) && !p.publish(r, SIGNERS);
        assert !p.markRetiring(r, SIGNERS, block(r));
        assert tree(env.root).equals(before) && env.store.pendingInitializationNames().isEmpty();
    }

    private static void createConfirmAndRestart() throws Exception {
        Env env = new Env("create", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Record r = pin.record();
        Snapshot pending = pins.snapshotForWrite();
        // Publication needs its own earlier reservation. It allocates and creates nothing.
        assert !p.publish(r, SIGNERS) && !Files.exists(env.slot(APP));
        assert p.reservePending(plan(pending));
        Header reserved = header(1, creating(APP, 1, PKG));
        assert env.header().equals(reserved) && !Files.exists(env.slot(APP));
        assert p.binding(r) == null; // No body or activation yet.
        assert p.reservePending(plan(pending)) && env.header().equals(reserved); // Exact retry.
        assert p.publish(r, SIGNERS);
        Slot published = body(r, 1, false);
        assert p.binding(r).equals(published) && env.header().equals(header(1, live(APP)));
        pins.commit(pin);
        assert p.publish(r, SIGNERS); // Exact retry: confirmation, no new ID or generation.
        assert p.binding(r).equals(published) && env.header().equals(header(1, live(APP)));
        assert p.reservePending(plan(pins.snapshotForWrite()));
        assert env.header().equals(header(1, live(APP)));

        // Restart. The core restores PENDING from the durable slot and counter, and explicit
        // rebinding confirms the same binding.
        NativeIdentityPersistence again = env.restarted();
        NativeIdentityStore.Loaded loaded = again.load();
        Slot stored = loaded.slots.get(APP).value;
        UserEntry user = stored.users.get(0);
        NativePrincipalPins restored = new NativePrincipalPins(8);
        restored.restore(new Snapshot(loaded.header.value.lastId, List.of(new Record(user.id,
                stored.packageName, stored.appId, user.userId, user.userSerial))));
        Pin back = restored.find(PKG, 0);
        assert back.phase() == Phase.PENDING && back.record().equals(r);
        assert again.binding(back.record()).signerSha256.equals(SIGNERS);
        assert again.publish(back.record(), SIGNERS);
        restored.commit(back);
        assert NativePinTestSupport.prepare(restored, PKG_B, APP_B, 0, SERIAL).record().id == 2; // Counter survives.
        assert again.binding(r).equals(published) && env.header().equals(header(1, live(APP)));
    }

    private static void pendingReservedTogether() throws Exception {
        Env env = new Env("order", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin first = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Pin second = NativePinTestSupport.prepare(pins, PKG_B, APP_B, 0, SERIAL);
        assert p.reservePending(plan(pins.snapshotForWrite()));
        assert env.header().equals(header(2, creating(APP, 1, PKG), creating(APP_B, 2, PKG_B)));
        assert p.publish(second.record(), SIGNERS); // 2 commits before 1.
        pins.commit(second);
        assert env.header().equals(header(2, creating(APP, 1, PKG), live(APP_B)));
        assert p.binding(first.record()) == null;
        assert p.publish(first.record(), SIGNERS);
        pins.commit(first);
        assert env.header().equals(header(2, live(APP), live(APP_B)));
        assert p.binding(first.record()).equals(body(first.record(), 1, false));
        assert p.binding(second.record()).equals(body(second.record(), 1, false));

        // Control: a partial snapshot moves the counter past pending 1 without its entry.
        // 1 is then refused, never reserved below the durable counter.
        Env partial = new Env("order-partial", true);
        NativePrincipalPins core = new NativePrincipalPins(8);
        Pin one = NativePinTestSupport.prepare(core, PKG, APP, 0, SERIAL);
        Pin two = NativePinTestSupport.prepare(core, PKG_B, APP_B, 0, SERIAL);
        assert partial.persistence.reservePending(plan(new Snapshot(2, List.of(two.record()))));
        Header passed = header(2, creating(APP_B, 2, PKG_B));
        assert partial.header().equals(passed);
        assert !partial.persistence.reservePending(plan(core.snapshotForWrite()));
        assert !partial.persistence.publish(one.record(), SIGNERS);
        assert partial.header().equals(passed) && !Files.exists(partial.slot(APP));
    }

    private static void refusals() throws Exception {
        Env env = new Env("refusals", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Record r = pin.record();
        assert p.reservePending(plan(pins.snapshotForWrite()));
        Map<String, String> reserved = tree(env.root);
        // A reserved creation publishes only for its own exact record.
        Record wrongPackage = new Record(1, PKG_B, APP, 0, SERIAL);
        Record wrongId = new Record(2, PKG, APP, 0, SERIAL);
        Record otherUser = new Record(1, PKG, APP, 10, SERIAL);
        Record otherApp = new Record(1, PKG, APP_B, 0, SERIAL);
        Record wrongSerial = new Record(1, PKG, APP, 0, SERIAL + 1);
        for (Record bad : List.of(wrongPackage, wrongId, otherUser, otherApp)) {
            assert !p.publish(bad, SIGNERS) && p.binding(bad) == null;
        }
        assert tree(env.root).equals(reserved);
        // A body published before a lost reply is continued only with its own signers.
        Header creatingHeader = env.header();
        assert env.store.resumeCreatingDirectory(creatingHeader, APP);
        assert env.store.publishCreatingSlot(creatingHeader, body(r, 1, false));
        assert !p.publish(r, OTHER_SIGNERS) && !p.publish(wrongSerial, SIGNERS);
        assert env.header().equals(creatingHeader);
        assert p.publish(r, SIGNERS) && env.header().equals(header(1, live(APP)));
        pins.commit(pin);
        Map<String, String> published = tree(env.root);
        // Existing bindings refuse every other principal, subject or signer set.
        for (Record bad : List.of(wrongPackage, wrongId, otherUser, otherApp, wrongSerial)) {
            assert p.binding(bad) == null && !p.publish(bad, SIGNERS);
            assert !p.markRetiring(bad, SIGNERS, block(bad));
        }
        assert !p.publish(r, OTHER_SIGNERS) && !p.markRetiring(r, OTHER_SIGNERS, block(r));
        assert !p.publish(r, Set.of("b".repeat(64)));
        assert tree(env.root).equals(published);

        // Malformed input throws before any effect.
        invalid(() -> p.publish(r, Set.of()));
        invalid(() -> p.markRetiring(r, Set.of("A".repeat(64)), block(r)));
        missing(() -> p.publish(null, SIGNERS));
        missing(() -> p.markRetiring(r, null, block(r)));
        missing(() -> p.binding(null));
        missing(() -> p.reservePending(null));
        Set<String> withNull = new HashSet<>();
        withNull.add(null);
        missing(() -> p.publish(r, withNull));
        invalid(() -> p.reservePending(plan(new Snapshot(0, List.of(r)))));
        invalid(() -> p.reservePending(plan(new Snapshot(-1, List.of()))));
        invalid(() -> p.reservePending(plan(new Snapshot(3,
                List.of(r, new Record(1, PKG_B, APP_B, 0, SERIAL))))));
        invalid(() -> p.reservePending(plan(new Snapshot(3,
                List.of(r, new Record(2, PKG, APP_B, 0, SERIAL))))));
        invalid(() -> p.reservePending(plan(new Snapshot(3,
                List.of(r, new Record(2, PKG_B, APP, 0, SERIAL))))));
        invalid(() -> p.reservePending(plan(new Snapshot(3, List.of(r), Set.of(3L)))));
        assert tree(env.root).equals(published);

        // A reservation never replaces another creation proof or admits another user.
        Pin next = NativePinTestSupport.prepare(pins, PKG_B, APP_B, 0, SERIAL);
        assert p.reservePending(plan(pins.snapshotForWrite()));
        assert env.header().equals(header(2, live(APP), creating(APP_B, 2, PKG_B)));
        Map<String, String> before = tree(env.root);
        assert !p.reservePending(plan(new Snapshot(3,
                List.of(new Record(3, PKG_B, APP_B, 0, SERIAL)))));
        assert !p.reservePending(plan(new Snapshot(3,
                List.of(new Record(2, PKG_C, APP_B, 0, SERIAL)))));
        // Refusal is whole: the otherwise valid APP_C reservation is not written either.
        assert !p.reservePending(plan(new Snapshot(4, List.of(new Record(3, PKG_C, APP_C, 0, SERIAL),
                new Record(4, PKG_D, APP_D, 10, SERIAL)))));
        assert tree(env.root).equals(before);
        assert p.publish(next.record(), SIGNERS);
    }

    // The reservation and publication of this flow stay; its marker and release refuse under the
    // version 1 format before any effect. Its positive half runs under the lifecycle format.
    private static void retirementMonotonic() throws Exception {
        Env env = new Env("retiring", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Record r = pin.record();
        assert p.reservePending(plan(pins.snapshotForWrite())) && p.publish(r, SIGNERS);
        pins.commit(pin);
        pins.beginRetire(pin); // The core closes admission; the marker then refuses.
        retirementRefused(env, r);
        assert p.binding(r).equals(body(r, 1, false));
        assert p.reservePending(plan(pins.snapshotForWrite())); // Its LIVE entry is not reallocated.
        assert env.header().equals(header(1, live(APP))) && p.binding(r).equals(body(r, 1, false));

        // Retirement can begin before the first publication. A RETIRING pin is reserved
        // exactly; advancing past that ID without reserving it would strand the account.
        Pin never = NativePinTestSupport.prepare(pins, PKG_B, APP_B, 0, SERIAL);
        pins.beginRetire(never);
        Pin pending = NativePinTestSupport.prepare(pins, PKG_C, APP_C, 0, SERIAL);
        assert p.reservePending(plan(pins.snapshotForWrite()));
        assert env.header().equals(header(3, live(APP), creating(APP_B, 2, PKG_B),
                creating(APP_C, 3, PKG_C)));
        retirementRefused(env, never.record());
        assert p.publish(never.record(), SIGNERS);
        assert never.phase() == Phase.RETIRING; // Publication is not activation.
        retirementRefused(env, never.record());
        assert Files.exists(env.slot(APP_B)) && p.binding(never.record()).equals(body(never.record(), 1, false));
        assert p.publish(pending.record(), SIGNERS);
    }

    // Intact bindings confirm beside damaged header copies and new issuance needs the counter; the
    // marker and release refuse under the version 1 format before any effect.
    private static void headerOnlyDamage() throws Exception {
        Env env = new Env("header-damage", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Pin peer = NativePinTestSupport.prepare(pins, PKG_B, APP_B, 0, SERIAL);
        Record r = pin.record(), rb = peer.record();
        assert p.reservePending(plan(pins.snapshotForWrite())) && p.publish(r, SIGNERS);
        pins.commit(pin);
        // B's body was published before its entry completed to LIVE.
        Header creatingHeader = env.header();
        assert env.store.resumeCreatingDirectory(creatingHeader, APP_B);
        assert env.store.publishCreatingSlot(creatingHeader, body(rb, 1, false));
        assert env.header().equals(header(2, live(APP), creating(APP_B, 2, PKG_B)));

        Path main = env.root.resolve("store.bin");
        Path reserve = env.root.resolve("store.bin.reservecopy");
        byte[] good = Files.readAllBytes(main), bad = {1, 2, 3};
        write(main, bad);
        write(reserve, bad);
        NativeIdentityStore.Loaded loaded = p.load();
        assert loaded.header.status == NativeIdentityStore.Status.DAMAGED
                && loaded.creationBlocked;
        assert loaded.bindingUsable(APP) && loaded.bindingUsable(APP_B);
        // Intact existing bindings confirm without the counter.
        assert p.publish(r, SIGNERS) && p.publish(rb, SIGNERS);
        pins.commit(peer);
        pins.beginRetire(pin);
        retirementRefused(env, r);
        assert p.binding(r).equals(body(r, 1, false)) && p.load().occupiedAppIds.contains(APP);
        // New issuance needs the counter.
        Pin fresh = NativePinTestSupport.prepare(pins, PKG_C, APP_C, 0, SERIAL);
        assert !p.reservePending(plan(pins.snapshotForWrite())) && !p.publish(fresh.record(), SIGNERS);
        assert !Files.exists(env.slot(APP_C));
        assert Arrays.equals(Files.readAllBytes(main), bad);
        assert Arrays.equals(Files.readAllBytes(reserve), bad);
        assert !Files.exists(Path.of(main + "-backup"));
        assert env.store.pendingInitializationNames().isEmpty();

        // With its header copies recovered, the retirement still refuses, and B completes.
        write(main, good);
        write(reserve, good);
        retirementRefused(env, r);
        assert env.header().equals(header(2, live(APP), creating(APP_B, 2, PKG_B)));
        assert p.publish(rb, SIGNERS) && env.header().equals(header(2, live(APP), live(APP_B)));
    }

    // A creation retired before its publication was confirmed: under the version 1 format its
    // marker, user drop and release refuse before any effect, and the CREATING entry stays.
    private static void creatingEntryCompletesBeforeOmission() throws Exception {
        Env env = new Env("creating-retirement", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Record r = pin.record();
        assert p.reservePending(plan(pins.snapshotForWrite()));
        Header creatingHeader = env.header();
        assert env.store.resumeCreatingDirectory(creatingHeader, APP);
        assert env.store.publishCreatingSlot(creatingHeader, body(r, 1, false));
        pins.beginRetire(pin); // Retired before its publication was ever confirmed.
        retirementRefused(env, r);
        assert env.header().equals(creatingHeader);
        // The user drop under CREATING would strand a tombstone; the store refuses it directly.
        Map<String, String> before = tree(env.root);
        assert !env.store.updateExistingSlot(body(r, 1, false), tombstone(r, 2));
        assert tree(env.root).equals(before);
        assert env.header().equals(creatingHeader) && p.binding(r).equals(body(r, 1, false));
    }

    // Nothing is deleted from an incomplete snapshot; the marker and release of the damaged, stale
    // and new accounts refuse under the version 1 format before any effect.
    private static void noSnapshotDerivedDeletion() throws Exception {
        Env env = new Env("preserve", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins before = new NativePrincipalPins(8);
        Pin c = NativePinTestSupport.prepare(before, PKG_C, APP_C, 0, SERIAL);
        Pin d = NativePinTestSupport.prepare(before, PKG_D, APP_D, 0, SERIAL);
        Pin e = NativePinTestSupport.prepare(before, PKG_E, APP_E, 0, SERIAL);
        assert p.reservePending(plan(before.snapshotForWrite()));
        assert p.publish(c.record(), SIGNERS) && p.publish(d.record(), SIGNERS);
        Path damaged = env.slot(APP_D).resolve("record.bin");
        write(damaged, new byte[] {1});
        write(Path.of(damaged + ".reservecopy"), new byte[] {2});
        // After a restart the core can restore only C. D's body is undecodable and E was
        // never published, but both stay held.
        NativeIdentityStore.Loaded loaded = p.load();
        assert loaded.bindingUsable(APP_C) && !loaded.bindingUsable(APP_D);
        assert !loaded.bindingUsable(APP_E) && loaded.creationReady();
        assert loaded.occupiedAppIds.equals(Set.of(APP_C, APP_D, APP_E));
        NativePrincipalPins core = new NativePrincipalPins(8);
        core.restore(new Snapshot(3, List.of(c.record())));
        Pin pin = NativePinTestSupport.prepare(core, PKG, APP, 0, SERIAL);
        Record r = pin.record();
        assert r.id == 4;
        Map<String, String> others = slots(env, APP_C, APP_D);
        assert p.reservePending(plan(core.snapshotForWrite()));
        Header expected = header(4, creating(APP, 4, PKG), live(APP_C), live(APP_D),
                creating(APP_E, 3, PKG_E));
        assert env.header().equals(expected);
        // An empty, older snapshot neither lowers the counter nor omits anything.
        assert p.reservePending(plan(new Snapshot(0, List.of()))) && env.header().equals(expected);
        assert slots(env, APP_C, APP_D).equals(others) && !Files.exists(env.slot(APP_E));
        // The damaged account stays unavailable and held. The stale reservation has no
        // generic CREATING abort. Neither takes a marker.
        assert p.binding(d.record()) == null && !p.publish(d.record(), SIGNERS);
        retirementRefused(env, d.record());
        assert p.binding(e.record()) == null;
        retirementRefused(env, e.record());
        assert env.header().equals(expected) && slots(env, APP_C, APP_D).equals(others);

        assert p.publish(r, SIGNERS);
        core.commit(pin);
        core.beginRetire(pin);
        retirementRefused(env, r);
        assert env.header().equals(header(4, live(APP), live(APP_C), live(APP_D),
                creating(APP_E, 3, PKG_E)));
        assert slots(env, APP_C, APP_D).equals(others) && !Files.exists(env.slot(APP_E));
        assert p.load().occupiedAppIds.equals(Set.of(APP, APP_C, APP_D, APP_E));
    }

    // Under the version 1 format no subject releases: the marker, the user drop, RELEASING and the
    // release of every subject refuse before any effect, and an unknown file is never deleted.
    private static void releaseRefusals() throws Exception {
        Env env = new Env("release-refusals", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Pin peer = NativePinTestSupport.prepare(pins, PKG_B, APP_B, 0, SERIAL);
        Record r = pin.record(), rb = peer.record();
        assert p.reservePending(plan(pins.snapshotForWrite()));
        assert p.publish(r, SIGNERS) && p.publish(rb, SIGNERS);
        pins.commit(pin);
        pins.commit(peer);
        pins.beginRetire(pin);
        retirementRefused(env, r);
        Map<String, String> held = tree(env.root);
        // Another principal, package, serial or signer set refuses too, as does the live peer. Another
        // user's block is outside the writer rules, refused before the format check.
        for (Record other : List.of(new Record(2, PKG, APP, 0, SERIAL), new Record(1, PKG_C, APP, 0, SERIAL),
                new Record(1, PKG, APP, 0, SERIAL + 1), rb)) {
            retirementRefused(env, other);
        }
        assert !p.markRetiring(r, OTHER_SIGNERS, block(r));
        Record otherUser = new Record(1, PKG, APP, 10, SERIAL);
        try {
            assert !p.markRetiring(otherUser, SIGNERS, block(otherUser));
        } catch (IllegalArgumentException outsideTheWriterRules) {
            // Refused before any effect, as the format refusal is.
        }
        assert tree(env.root).equals(held);
        // The user drop and the RELEASING write refuse in the store itself.
        assert !env.store.updateExistingSlot(body(r, 1, false), tombstone(r, 2));
        assert !env.store.writeHeader(header(2, live(APP), live(APP_B)), header(2, releasing(APP), live(APP_B)));
        assert tree(env.root).equals(held);
        // An unknown file in the slot is never deleted.
        Path foreign = env.slot(APP).resolve("owner-data");
        Files.writeString(foreign, "not store owned");
        retirementRefused(env, r);
        assert Files.exists(foreign) && Files.exists(env.slot(APP).resolve("record.bin"));
        assert env.header().equals(header(2, live(APP), live(APP_B)));
    }

    private static void creationDirectoryGuards() throws Exception {
        Env env = new Env("creation-directory", true);
        NativeIdentityPersistence p = env.persistence;
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Record r = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL).record();
        assert p.reservePending(plan(pins.snapshotForWrite()));
        Path dir = Files.createDirectory(env.slot(APP));
        Path foreign = dir.resolve("owner-data");
        Files.writeString(foreign, "unknown");
        assert !p.publish(r, SIGNERS) && Files.exists(foreign) && p.binding(r) == null;
        Files.delete(foreign);
        Path elsewhere = Files.createDirectory(env.root.getParent().resolve("elsewhere"));
        Files.createSymbolicLink(dir.resolve("record.bin"), elsewhere.resolve("target"));
        assert !p.publish(r, SIGNERS) && !Files.exists(elsewhere.resolve("target"));
        Files.delete(dir.resolve("record.bin"));
        // A staged body of another creation is not adopted or overwritten.
        Path seed = dir.resolve("record.bin-seed");
        byte[] other = NativeIdentityRecords.encodeSlot(
                body(new Record(1, PKG_B, APP, 0, SERIAL), 1, false));
        Files.write(seed, other);
        assert !p.publish(r, SIGNERS) && Arrays.equals(Files.readAllBytes(seed), other);
        // A torn seed is only unpublished staging of this same creation.
        write(seed, new byte[] {1, 2});
        assert p.publish(r, SIGNERS) && p.binding(r).equals(body(r, 1, false));
        assert env.header().equals(header(1, live(APP)));
    }

    private static void reserveWithUnknownOutcomes() throws Exception {
        Set<String> states = new TreeSet<>();
        Header empty = header(0);
        Header reserved = header(2, creating(APP, 1, PKG), creating(APP_B, 2, PKG_B));
        for (int k = 1; ; ++k) {
            assert k < LIMIT;
            Env env = new Env("reserve-" + k, true);
            NativePrincipalPins pins = new NativePrincipalPins(8);
            Pin first = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
            Pin second = NativePinTestSupport.prepare(pins, PKG_B, APP_B, 0, SERIAL);
            Snapshot snapshot = pins.snapshotForWrite();
            Os.syncCalls = 0;
            Os.failSyncAt = k;
            boolean result = env.persistence.reservePending(plan(snapshot));
            Os.failSyncAt = 0;
            if (result) {
                assert env.header().equals(reserved);
                assert states.equals(Set.of("old", "new")) : states;
                break;
            }
            Header seen = env.header();
            assert seen.equals(empty) || seen.equals(reserved) : "k=" + k;
            states.add(seen.equals(empty) ? "old" : "new");
            // Publication confirms an unacknowledged reservation before creating anything,
            // and never proceeds without one.
            NativeIdentityPersistence again = env.restarted();
            assert again.publish(second.record(), SIGNERS) == seen.equals(reserved);
            assert Files.exists(env.slot(APP_B)) == seen.equals(reserved);
            assert again.reservePending(plan(snapshot)) : "k=" + k;
            assert again.publish(second.record(), SIGNERS);
            assert again.publish(first.record(), SIGNERS);
            assert env.header().equals(header(2, live(APP), live(APP_B)));
        }
    }

    private static void publishWithUnknownOutcomes() throws Exception {
        Set<String> states = new TreeSet<>();
        for (int k = 1; ; ++k) {
            assert k < LIMIT;
            Env env = new Env("publish-" + k, true);
            NativePrincipalPins pins = new NativePrincipalPins(8);
            Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
            Pin other = NativePinTestSupport.prepare(pins, PKG_C, APP_C, 0, SERIAL);
            Record r = pin.record();
            assert env.persistence.reservePending(plan(pins.snapshotForWrite()));
            assert env.persistence.publish(other.record(), SIGNERS);
            Map<String, String> unrelated = slots(env, APP_C);
            Os.syncCalls = 0;
            Os.failSyncAt = k;
            boolean result = env.persistence.publish(r, SIGNERS);
            Os.failSyncAt = 0;
            if (result) {
                assert states.equals(Set.of("reserved", "directory", "body", "live")) : states;
                assert env.header().equals(header(2, live(APP), live(APP_C)));
                break;
            }
            // Unknown outcome: the pin stays PENDING. The ID and every hold remain.
            NativeIdentityStore.Loaded loaded = env.store.load();
            HeaderEntry entry = find(loaded.header.value, APP);
            assert loaded.header.value.lastId == 2 && loaded.occupiedAppIds.contains(APP);
            assert entry.equals(creating(APP, 1, PKG)) || entry.equals(live(APP));
            Slot bound = env.persistence.binding(r);
            assert bound == null || bound.equals(body(r, 1, false)) : "k=" + k;
            states.add(entry.phase == SlotPhase.LIVE ? "live" : bound != null ? "body"
                    : Files.exists(env.slot(APP)) ? "directory" : "reserved");
            assert pin.phase() == Phase.PENDING;
            assert env.restarted().publish(r, SIGNERS) : "k=" + k;
            assert env.persistence.binding(r).equals(body(r, 1, false));
            assert env.header().equals(header(2, live(APP), live(APP_C)));
            assert slots(env, APP_C).equals(unrelated);
            pins.commit(pin);
        }
    }

    // Under the version 1 format the marker refuses before its first sync, so no failure point
    // is reached and a restarted store reads the same unmarked body.
    private static void markWithUnknownOutcomes() throws Exception {
        Env env = new Env("mark", true);
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = NativePinTestSupport.prepare(pins, PKG, APP, 0, SERIAL);
        Record r = pin.record();
        assert env.persistence.reservePending(plan(pins.snapshotForWrite()));
        assert env.persistence.publish(r, SIGNERS);
        pins.commit(pin);
        pins.beginRetire(pin);
        Os.syncCalls = 0;
        Os.failSyncAt = 1;
        try {
            retirementRefused(env, r);
        } finally {
            Os.failSyncAt = 0;
        }
        assert Os.syncCalls == 0;
        assert env.persistence.binding(r).equals(body(r, 1, false));
        assert env.restarted().binding(r).equals(body(r, 1, false));
    }

    // Under the version 1 format the release refuses before its first sync: the principal ID stays
    // consumed, the core pin held and every unrelated slot unchanged.
    private static void releaseWithUnknownOutcomes() throws Exception {
        Env env = new Env("release", true);
        Retiring f = retiring(env);
        Os.syncCalls = 0;
        Os.failSyncAt = 1;
        try {
            retirementRefused(env, f.record);
        } finally {
            Os.failSyncAt = 0;
        }
        assert Os.syncCalls == 0;
        assert env.header().lastId == 4 && f.pin.phase() == Phase.RETIRING;
        assert f.pins.isAppIdPinned(APP);
        assert env.persistence.load().occupiedAppIds.contains(APP);
        assert env.persistence.binding(f.record).equals(body(f.record, 1, false));
        assert unrelated(env).equals(f.unrelated);
        assert env.restarted().binding(f.record).equals(body(f.record, 1, false));
    }

    // Target retiring in the core, plus an intact unrelated slot, an unrelated slot whose body
    // cannot be decoded and a stale reservation that never got a directory. Its marker refuses.
    private static Retiring retiring(Env env) throws Exception {
        Retiring f = new Retiring();
        NativeIdentityPersistence p = env.persistence;
        f.pin = NativePinTestSupport.prepare(f.pins, PKG, APP, 0, SERIAL);
        f.record = f.pin.record();
        Pin other = NativePinTestSupport.prepare(f.pins, PKG_C, APP_C, 0, SERIAL);
        Pin damaged = NativePinTestSupport.prepare(f.pins, PKG_D, APP_D, 0, SERIAL);
        NativePinTestSupport.prepare(f.pins, PKG_E, APP_E, 0, SERIAL);
        assert p.reservePending(plan(f.pins.snapshotForWrite()));
        for (Pin published : List.of(f.pin, other, damaged)) {
            assert p.publish(published.record(), SIGNERS);
            f.pins.commit(published);
        }
        Path body = env.slot(APP_D).resolve("record.bin");
        write(body, new byte[] {1, 2, 3});
        write(Path.of(body + ".reservecopy"), new byte[] {4, 5, 6});
        f.pins.beginRetire(f.pin);
        retirementRefused(env, f.record);
        f.unrelated = unrelated(env);
        return f;
    }

    private static Map<String, String> unrelated(Env env) throws Exception {
        assert !Files.exists(env.slot(APP_E));
        return slots(env, APP_C, APP_D, APP_E);
    }

    // Exact bytes of these slot directories.
    private static Map<String, String> slots(Env env, int... appIds) throws Exception {
        Map<String, String> result = new TreeMap<>();
        Map<String, String> all = tree(env.root);
        for (int appId : appIds) {
            String prefix = "slots/" + appId;
            for (Map.Entry<String, String> entry : all.entrySet()) {
                if (entry.getKey().equals(prefix) || entry.getKey().startsWith(prefix + "/")) {
                    result.put(entry.getKey(), entry.getValue());
                }
            }
        }
        return result;
    }

    // Every path under the root with its exact bytes, for "changed nothing" checks.
    private static Map<String, String> tree(Path root) throws Exception {
        TreeMap<String, String> result = new TreeMap<>();
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return result;
        List<Path> paths;
        try (Stream<Path> walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            result.put(root.relativize(path).toString(),
                    Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) ? "/"
                    : Base64.getEncoder().encodeToString(Files.readAllBytes(path)));
        }
        return result;
    }

    private static Header header(long lastId, HeaderEntry... entries) {
        return new Header(LINEAGE, lastId, List.of(entries));
    }

    private static HeaderEntry creating(int appId, long id, String packageName) {
        return new HeaderEntry(appId, SlotPhase.CREATING, id, packageName);
    }

    private static HeaderEntry live(int appId) {
        return new HeaderEntry(appId, SlotPhase.LIVE, 0, "");
    }

    private static HeaderEntry releasing(int appId) {
        return new HeaderEntry(appId, SlotPhase.RELEASING, 0, "");
    }

    private static HeaderEntry find(Header header, int appId) {
        for (HeaderEntry entry : header.entries) if (entry.appId == appId) return entry;
        return null;
    }

    private static Slot body(Record r, long generation, boolean retiring) {
        return new Slot(LINEAGE, r.appId, r.packageName, generation, SIGNERS,
                List.of(new UserEntry(r.id, r.userId, r.userSerial, retiring)));
    }

    private static Slot tombstone(Record r, long generation) {
        return new Slot(LINEAGE, r.appId, r.packageName, generation, SIGNERS, List.of());
    }

    // The retirement block of this user and serial's account user, every kind outstanding.
    private static NativeIdentityRecords.Retirement block(Record r) {
        List<NativeIdentityRecords.Obligation> outstanding = new java.util.ArrayList<>();
        for (NativeIdentityRecords.ObligationKind kind : NativeIdentityRecords.ObligationKind.values()) {
            outstanding.add(new NativeIdentityRecords.Obligation(kind,
                    NativeIdentityRecords.ObligationState.OUTSTANDING, NativeIdentityRecords.NO_REFERENCE, 0, 0));
        }
        return new NativeIdentityRecords.Retirement(NativeIdentityRecords.ActorClass.ACCOUNT_USER, r.userId,
                r.userSerial, NativeIdentityRecords.NO_REFERENCE, 1_700_000_000_100L, outstanding);
    }

    private static int twins;

    // Under the version 1 format the lifecycle record's retirement, the transaction that survives,
    // refuses before any effect: every byte of the store stays. So does it under Format.V2, which
    // reads this version 1 state as it is, over a copy of the same bytes.
    private static void retirementRefused(Env env, Record r) throws Exception {
        Map<String, String> before = tree(env.root);
        assert !env.persistence.markRetiring(r, SIGNERS, block(r));
        assert tree(env.root).equals(before);
        Path copy = env.root.resolveSibling("store-twin-" + ++twins);
        for (Map.Entry<String, String> entry : before.entrySet()) {
            Path target = copy.resolve(entry.getKey());
            if (entry.getValue().equals("/")) Files.createDirectories(target);
            else Files.write(target, Base64.getDecoder().decode(entry.getValue()));
        }
        NativeIdentityPersistence production = new NativeIdentityPersistence(
                new NativeIdentityStore(copy.toFile(), NativeIdentityStore.Format.V2));
        assert !production.markRetiring(r, SIGNERS, block(r));
        assert tree(copy).equals(before);
    }

    private static void write(Path file, byte[] bytes) throws Exception {
        Files.deleteIfExists(file);
        Files.write(file, bytes);
    }

    private static void invalid(Runnable action) {
        try { action.run(); } catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("accepted malformed input");
    }

    private static void missing(Runnable action) {
        try { action.run(); } catch (NullPointerException expected) { return; }
        throw new AssertionError("accepted null");
    }
}
