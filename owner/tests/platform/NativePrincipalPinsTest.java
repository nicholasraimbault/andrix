// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativePrincipalPins.Phase;
import com.android.server.pm.NativePrincipalPins.Pin;
import com.android.server.pm.NativePrincipalPins.Record;
import com.android.server.pm.NativePrincipalPins.Snapshot;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

// Host checks of the pin state alone. PMS persistence, allocator use and Android runtime
// behavior are outside this test.
public final class NativePrincipalPinsTest {
    private static final String APP = "dev.andrix.principal";
    private static final String OTHER = "dev.andrix.other";
    private static final String THIRD = "org.example.third";
    private static final String FOURTH = "org.example.fourth";
    private static final int RACERS = 16;

    private interface Racer<T> {
        T run(int index) throws Exception;
    }

    private static void requireAssertions() {
        if (!NativePrincipalPinsTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
    }

    private static void invalid(Runnable action) {
        try { action.run(); } catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("accepted invalid input");
    }

    private static void refused(Runnable action) {
        try { action.run(); } catch (IllegalStateException expected) { return; }
        throw new AssertionError("accepted a refused operation");
    }

    private static void missing(Runnable action) {
        try { action.run(); } catch (NullPointerException expected) { return; }
        throw new AssertionError("accepted null");
    }

    private static void unsupported(Runnable action) {
        try { action.run(); } catch (UnsupportedOperationException expected) { return; }
        throw new AssertionError("changed an immutable value");
    }

    // Everything a refused call could change, observed through the public API.
    private static List<Object> state(NativePrincipalPins pins, Pin... known) {
        List<Object> state = new ArrayList<>();
        state.add(pins.snapshotForWrite());
        for (Pin pin : known) {
            Record record = pin.record();
            state.add(pin.phase());
            state.add(pins.findId(record.id) == pin);
            state.add(pins.find(record.packageName, record.userId) == pin);
            state.add(pins.isPackagePinned(record.packageName));
            state.add(pins.isAppIdPinned(record.appId));
        }
        return state;
    }

    private static void retire(NativePrincipalPins pins, Pin pin) {
        pins.beginRetire(pin);
        pins.finishRetire(pin);
    }

    private static void phaseTransitions() {
        NativePrincipalPins pins = new NativePrincipalPins(4);
        Pin pin = pins.prepare(APP, 10123, 0, 0);
        assert pin.phase() == Phase.PENDING;
        assert pin.record().equals(new Record(1, APP, 10123, 0, 0));
        // The allocation is pinned at once, before any write or commit.
        assert pins.find(APP, 0) == pin && pins.findId(1) == pin;
        assert pins.isPackagePinned(APP) && pins.isAppIdPinned(10123);
        assert pins.snapshotForWrite().equals(new Snapshot(1, List.of(pin.record())));
        assert pin.toString().contains("PENDING");
        assert pins.snapshotForWrite().toString().contains(APP);
        refused(() -> pins.finishRetire(pin)); // Only RETIRING can finish.
        pins.commit(pin);
        assert pin.phase() == Phase.ACTIVE;
        pins.commit(pin); // The same ACTIVE handle again changes nothing.
        assert pin.phase() == Phase.ACTIVE;
        refused(() -> pins.finishRetire(pin));
        assert pins.snapshotForWrite().equals(new Snapshot(1, List.of(pin.record())));
        pins.beginRetire(pin);
        assert pin.phase() == Phase.RETIRING;
        pins.beginRetire(pin); // The same handle again changes nothing.
        refused(() -> pins.commit(pin)); // Irrevocable, no revival.
        assert pin.phase() == Phase.RETIRING;
        pins.finishRetire(pin);
        // The handle is terminal and no longer names a live pin.
        assert pin.phase() == Phase.RETIRED;
        assert pins.find(APP, 0) == null && pins.findId(1) == null;
        assert !pins.isPackagePinned(APP) && !pins.isAppIdPinned(10123);
        refused(() -> pins.commit(pin));
        refused(() -> pins.beginRetire(pin));
        refused(() -> pins.finishRetire(pin));
        assert pin.phase() == Phase.RETIRED;

        // PENDING can retire without ever becoming ACTIVE.
        Pin pending = pins.prepare(APP, 10123, 0, 0);
        assert pending != pin && pending.record().id == 2;
        pins.beginRetire(pending);
        refused(() -> pins.commit(pending));
        pins.finishRetire(pending);
        assert pending.phase() == Phase.RETIRED && pins.findId(2) == null;
        assert pins.snapshotForWrite().equals(new Snapshot(2, List.of()));
    }

    private static void exactRetryAndConflicts() {
        NativePrincipalPins pins = new NativePrincipalPins(8);
        Pin pin = pins.prepare(APP, 10123, 0, 7);
        assert pins.prepare(APP, 10123, 0, 7) == pin; // Exact retry while PENDING.
        List<Object> before = state(pins, pin);
        refused(() -> pins.prepare(APP, 10124, 0, 7)); // Another app ID for this package and user.
        refused(() -> pins.prepare(APP, 10123, 0, 8)); // Another incarnation of user 0.
        refused(() -> pins.prepare(APP, 10124, 10, 9)); // A pinned package keeps one app ID.
        refused(() -> pins.prepare(OTHER, 10123, 10, 9)); // A pinned app ID keeps one package.
        refused(() -> pins.prepare(OTHER, 10123, 0, 7));
        assert state(pins, pin).equals(before);
        pins.commit(pin);
        assert pins.prepare(APP, 10123, 0, 7) == pin && pin.phase() == Phase.ACTIVE;

        // The same package and app ID may be pinned for other users.
        Pin secondary = pins.prepare(APP, 10123, 10, 9);
        assert secondary != pin && secondary.record().equals(new Record(2, APP, 10123, 10, 9));
        assert pins.find(APP, 0) == pin && pins.find(APP, 10) == secondary;
        assert pins.prepare(APP, 10123, 10, 9) == secondary;
        pins.beginRetire(secondary);
        refused(() -> pins.prepare(APP, 10123, 10, 9)); // An exact binding cannot revive it.
        refused(() -> pins.prepare(APP, 10123, 10, 10)); // Nor can a new incarnation of user 10.
        Pin tertiary = pins.prepare(APP, 10123, 11, 12); // Other users are unaffected.
        assert tertiary.record().id == 3;
        pins.finishRetire(secondary);
        Pin recreated = pins.prepare(APP, 10123, 10, 10);
        assert recreated.record().id == 4 && recreated.phase() == Phase.PENDING;

        // The pair is released only when no user keeps a pin.
        retire(pins, pin);
        retire(pins, tertiary);
        assert pins.isPackagePinned(APP) && pins.isAppIdPinned(10123);
        refused(() -> pins.prepare(OTHER, 10123, 0, 7));
        refused(() -> pins.prepare(APP, 10124, 0, 7));
        retire(pins, recreated);
        assert !pins.isPackagePinned(APP) && !pins.isAppIdPinned(10123);
        assert pins.prepare(OTHER, 10123, 0, 7).record().id == 5;
        assert pins.prepare(APP, 10124, 0, 7).record().id == 6;
    }

    private static void validation() {
        invalid(() -> new NativePrincipalPins(0));
        invalid(() -> new NativePrincipalPins(-1));
        invalid(() -> new NativePrincipalPins(Integer.MIN_VALUE));
        NativePrincipalPins pins = new NativePrincipalPins(Integer.MAX_VALUE); // No eager storage.
        String longest = "a." + "b".repeat(253);
        assert longest.length() == 255;
        String[] malformed = {
            "", "a", "android", ".", "..", "a.", ".a", ".a.b", "a..b", "a.b.", "1a.b", "a.1b",
            "_a.b", "a._b", "a-b.c", "a.b-c", "a b.c", "a.b ", "a/b.c", "a.b:c", "a.b\n", "a.b\0",
            "\u00e9.b", "a.\u0430", longest + "b",
        };
        for (String name : malformed) {
            invalid(() -> pins.prepare(name, 10123, 0, 0));
            invalid(() -> new Record(1, name, 10123, 0, 0));
        }
        missing(() -> pins.prepare(null, 10123, 0, 0));
        missing(() -> new Record(1, null, 10123, 0, 0));
        int[] appIds = {Integer.MIN_VALUE, -1, 0, 1000, 9999, 20000, 99999, Integer.MAX_VALUE};
        for (int appId : appIds) {
            invalid(() -> pins.prepare(APP, appId, 0, 0));
            invalid(() -> new Record(1, APP, appId, 0, 0));
        }
        // 21474 is the largest user whose UIDs fit in an int for every valid app ID.
        int[] userIds = {Integer.MIN_VALUE, -10000, -2, -1, 21475, Integer.MAX_VALUE};
        for (int userId : userIds) {
            invalid(() -> pins.prepare(APP, 10000, userId, 0));
            invalid(() -> new Record(1, APP, 10000, userId, 0));
        }
        for (long serial : new long[] {Long.MIN_VALUE, -1}) {
            invalid(() -> pins.prepare(APP, 10123, 0, serial));
            invalid(() -> new Record(1, APP, 10123, 0, serial));
        }
        for (long id : new long[] {Long.MIN_VALUE, -1, 0}) {
            invalid(() -> new Record(id, APP, 10123, 0, 0));
        }
        assert pins.snapshotForWrite().equals(new Snapshot(0, List.of()));
        assert !pins.isPackagePinned(APP) && !pins.isAppIdPinned(10123) && pins.findId(1) == null;

        // Every boundary value is accepted.
        Pin lowest = pins.prepare("a.b", 10000, 0, 0);
        Pin highest = pins.prepare(longest, 19999, 21474, Long.MAX_VALUE);
        Pin mixed = pins.prepare("Z9_.y_1.x", 10001, 1, 1);
        assert lowest.record().id == 1 && highest.record().id == 2 && mixed.record().id == 3;
        assert highest.record().userId * 100_000 + highest.record().appId == 2_147_419_999;
        assert new Record(Long.MAX_VALUE, APP, 10123, 0, 0).id == Long.MAX_VALUE;

        // Queries report values that can never be pinned as unpinned instead of failing.
        assert pins.find("android", 0) == null && !pins.isPackagePinned("android");
        assert pins.find(APP, -1) == null && pins.find("a.b", -1) == null;
        assert pins.findId(0) == null && pins.findId(-1) == null;
        assert pins.findId(Long.MIN_VALUE) == null;
        assert !pins.isAppIdPinned(1000) && !pins.isAppIdPinned(-1);
        missing(() -> pins.find(null, 0));
        missing(() -> pins.isPackagePinned(null));
        missing(() -> pins.commit(null));
        missing(() -> pins.beginRetire(null));
        missing(() -> pins.finishRetire(null));
        missing(() -> new NativePrincipalPins(4).restore(null));
    }

    private static void capacityAndCounters() {
        NativePrincipalPins pins = new NativePrincipalPins(2);
        Pin a = pins.prepare(APP, 10001, 0, 0);
        Pin b = pins.prepare(OTHER, 10002, 0, 0);
        List<Object> full = state(pins, a, b);
        refused(() -> pins.prepare(THIRD, 10003, 0, 0));
        assert state(pins, a, b).equals(full); // No ID or reservation consumed.
        assert pins.prepare(APP, 10001, 0, 0) == a; // An exact retry needs no capacity.
        pins.beginRetire(a);
        refused(() -> pins.prepare(THIRD, 10003, 0, 0)); // RETIRING still counts.
        pins.finishRetire(a);
        assert pins.prepare(THIRD, 10003, 0, 0).record().id == 3;
        refused(() -> pins.prepare(FOURTH, 10004, 0, 0));

        NativePrincipalPins high = new NativePrincipalPins(4);
        assert high.restore(new Snapshot(Long.MAX_VALUE - 1, List.of())).isEmpty();
        Pin last = high.prepare(APP, 10123, 0, 0);
        assert last.record().id == Long.MAX_VALUE;
        List<Object> exhausted = state(high, last);
        refused(() -> high.prepare(OTHER, 10124, 0, 0)); // Never wraps or reuses an ID.
        assert state(high, last).equals(exhausted);
        assert high.prepare(APP, 10123, 0, 0) == last; // Exact retries still work.
        retire(high, last);
        refused(() -> high.prepare(APP, 10123, 0, 0)); // A released ID does not come back.
        assert high.snapshotForWrite().equals(new Snapshot(Long.MAX_VALUE, List.of()));

        NativePrincipalPins top = new NativePrincipalPins(4);
        Record max = new Record(Long.MAX_VALUE, APP, 10123, 0, 0);
        Pin restored = top.restore(new Snapshot(Long.MAX_VALUE, List.of(max))).get(0);
        assert top.findId(Long.MAX_VALUE) == restored && restored.phase() == Phase.PENDING;
        refused(() -> top.prepare(OTHER, 10124, 0, 0));
        assert top.prepare(APP, 10123, 0, 0) == restored;
    }

    private static void foreignAndStaleHandles() {
        NativePrincipalPins first = new NativePrincipalPins(4);
        NativePrincipalPins second = new NativePrincipalPins(4);
        Pin mine = first.prepare(APP, 10123, 0, 0);
        Pin theirs = second.prepare(APP, 10123, 0, 0);
        assert mine != theirs && mine.record().equals(theirs.record()); // Equal, not owned.
        List<Object> before = state(first, mine);
        refused(() -> first.commit(theirs));
        refused(() -> first.beginRetire(theirs));
        second.beginRetire(theirs);
        refused(() -> first.finishRetire(theirs));
        assert state(first, mine).equals(before) && theirs.phase() == Phase.RETIRING;
        second.finishRetire(theirs);
        refused(() -> first.commit(theirs));
        assert state(first, mine).equals(before);

        // A stale handle cannot act on the new pin for the same binding.
        retire(first, mine);
        Pin current = first.prepare(APP, 10123, 0, 0);
        assert current != mine && current.record().id == 2;
        refused(() -> first.commit(mine));
        refused(() -> first.beginRetire(mine));
        refused(() -> first.finishRetire(mine));
        assert current.phase() == Phase.PENDING && mine.phase() == Phase.RETIRED;
        assert first.find(APP, 0) == current && first.findId(1) == null;
        assert first.findId(2) == current;
    }

    private static void restoreValidationAndAtomicity() {
        Record first = new Record(1, APP, 10123, 0, 0);
        Record second = new Record(2, APP, 10123, 10, 5);
        Record third = new Record(3, OTHER, 10200, 0, 0);
        NativePrincipalPins pins = new NativePrincipalPins(3);
        List<Snapshot> malformed = List.of(
                new Snapshot(-1, List.of()),
                new Snapshot(Long.MIN_VALUE, List.of()),
                new Snapshot(0, List.of(first)), // lastId below an ID.
                new Snapshot(2, List.of(first, second, third)), // Only the last record fails.
                new Snapshot(3, List.of(first, second, new Record(2, THIRD, 10300, 0, 0))),
                new Snapshot(3, List.of(first, second, new Record(3, APP, 10123, 0, 0))),
                new Snapshot(3, List.of(first, second, new Record(3, APP, 10123, 10, 6))),
                new Snapshot(3, List.of(first, second, new Record(3, THIRD, 10123, 11, 0))),
                new Snapshot(3, List.of(first, second, new Record(3, APP, 10124, 11, 0))));
        for (Snapshot snapshot : malformed) {
            invalid(() -> pins.restore(snapshot));
            // Earlier valid records must not remain installed.
            assert pins.snapshotForWrite().equals(new Snapshot(0, List.of()));
            assert pins.findId(1) == null && pins.find(APP, 0) == null;
            assert !pins.isPackagePinned(APP) && !pins.isAppIdPinned(10123);
        }
        Record fourth = new Record(4, THIRD, 10300, 0, 0);
        refused(() -> pins.restore(new Snapshot(4, List.of(first, second, third, fourth))));
        missing(() -> pins.restore(null));
        missing(() -> new Snapshot(0, null));
        missing(() -> new Snapshot(1, Arrays.asList(first, null)));
        assert pins.snapshotForWrite().equals(new Snapshot(0, List.of()));

        // Still fresh. Record order does not matter, and every handle is PENDING.
        List<Pin> restored = pins.restore(new Snapshot(9, List.of(third, first, second)));
        assert restored.size() == 3 && restored.get(0).record().equals(third);
        assert restored.get(1).record().equals(first) && restored.get(2).record().equals(second);
        for (Pin pin : restored) {
            assert pin.phase() == Phase.PENDING && pins.findId(pin.record().id) == pin;
        }
        unsupported(() -> restored.clear());
        assert pins.snapshotForWrite().equals(new Snapshot(9, List.of(first, second, third)));
        refused(() -> pins.restore(new Snapshot(9, List.of(first, second, third))));
        refused(() -> pins.restore(new Snapshot(0, List.of())));
        retire(pins, restored.get(0));
        // New IDs continue after lastId, not after the highest remaining record.
        assert pins.prepare(THIRD, 10300, 0, 0).record().id == 10;

        NativePrincipalPins failed = new NativePrincipalPins(3);
        invalid(() -> failed.prepare("android", 10123, 0, 0));
        invalid(() -> failed.restore(new Snapshot(-1, List.of())));
        assert failed.restore(new Snapshot(5, List.of())).isEmpty(); // Failures kept it fresh.
        assert failed.prepare(APP, 10123, 0, 0).record().id == 6;

        NativePrincipalPins used = new NativePrincipalPins(3);
        Pin sole = used.prepare(APP, 10123, 0, 0);
        refused(() -> used.restore(new Snapshot(0, List.of())));
        retire(used, sole);
        refused(() -> used.restore(new Snapshot(0, List.of()))); // Empty again, but not fresh.
        NativePrincipalPins restoredEmpty = new NativePrincipalPins(3);
        assert restoredEmpty.restore(new Snapshot(0, List.of())).isEmpty();
        refused(() -> restoredEmpty.restore(new Snapshot(0, List.of())));
    }

    private static void retirementMarkersAndTargetOmission() {
        NativePrincipalPins pins = new NativePrincipalPins(3);
        Pin leaving = pins.prepare(APP, 10123, 0, 0);
        Pin otherRetiring = pins.prepare(OTHER, 10200, 0, 0);
        Pin pending = pins.prepare(THIRD, 10300, 0, 0);
        refused(() -> pins.snapshotWithout(leaving));
        pins.commit(leaving);
        refused(() -> pins.snapshotWithout(leaving));
        pins.beginRetire(leaving);
        pins.beginRetire(otherRetiring);
        Snapshot marked = pins.snapshotForWrite();
        assert marked.records.equals(List.of(leaving.record(), otherRetiring.record(), pending.record()));
        assert marked.retiringIds.equals(Set.of(leaving.record().id, otherRetiring.record().id));
        NativePrincipalPins afterMarker = new NativePrincipalPins(3);
        afterMarker.restore(marked);
        for (String name : List.of(APP, OTHER)) {
            Pin pin = afterMarker.find(name, 0);
            assert pin.phase() == Phase.RETIRING;
            refused(() -> afterMarker.commit(pin));
            refused(() -> afterMarker.prepare(name, pin.record().appId, 0, 0));
        }
        assert afterMarker.find(THIRD, 0).phase() == Phase.PENDING;
        Snapshot omission = pins.snapshotWithout(leaving);
        assert omission.records.equals(List.of(otherRetiring.record(), pending.record()));
        assert omission.retiringIds.equals(Set.of(otherRetiring.record().id));
        assert pins.snapshotForWrite().equals(marked); // Candidate did not change held state.
        assert pins.reservedAppIds().equals(Set.of(10123, 10200, 10300));
        refused(() -> pins.prepare(FOURTH, 10400, 0, 0));
        NativePrincipalPins afterFinalWrite = new NativePrincipalPins(3);
        afterFinalWrite.restore(omission);
        assert afterFinalWrite.find(APP, 0) == null;
        assert afterFinalWrite.find(OTHER, 0).phase() == Phase.RETIRING;
        assert afterFinalWrite.isAppIdPinned(10200);
        refused(() -> afterFinalWrite.commit(afterFinalWrite.find(OTHER, 0)));
        pins.finishRetire(leaving);
        assert pins.snapshotForWrite().equals(omission);
        assert pins.prepare(FOURTH, 10123, 0, 0).record().id == 4;
        refused(() -> pins.snapshotWithout(leaving));
        refused(() -> pins.snapshotWithout(afterFinalWrite.find(OTHER, 0)));
        missing(() -> pins.snapshotWithout(null));
    }

    private static void reservedAppIdsBarrier() {
        NativePrincipalPins pins = new NativePrincipalPins(8);
        assert pins.reservedAppIds().isEmpty();
        Pin owner = pins.prepare(APP, 10123, 0, 0);
        Pin secondary = pins.prepare(APP, 10123, 10, 5);
        Pin other = pins.prepare(OTHER, 10200, 0, 0);
        Pin low = pins.prepare(THIRD, 10050, 0, 0);
        Set<Integer> reserved = pins.reservedAppIds();
        // Each app ID appears once, however many users pin its package, in ascending order.
        assert new ArrayList<>(reserved).equals(List.of(10050, 10123, 10200));
        unsupported(() -> reserved.add(10999));
        unsupported(() -> reserved.remove(10123));
        unsupported(() -> reserved.clear());
        unsupported(() -> reserved.removeIf(appId -> true));
        unsupported(() -> reserved.iterator().remove());
        assert reserved.equals(Set.of(10050, 10123, 10200));

        // RETIRING pins retain both their app IDs and durable markers.
        pins.commit(owner);
        pins.beginRetire(owner);
        pins.beginRetire(other);
        assert pins.reservedAppIds().equals(Set.of(10050, 10123, 10200));
        assert pins.snapshotForWrite().equals(new Snapshot(4,
                List.of(owner.record(), secondary.record(), other.record(), low.record()),
                Set.of(owner.record().id, other.record().id)));
        // An app ID leaves only with the last pin that holds it.
        pins.finishRetire(owner);
        assert pins.reservedAppIds().equals(Set.of(10050, 10123, 10200)); // Held for user 10.
        pins.finishRetire(other);
        assert pins.reservedAppIds().equals(Set.of(10050, 10123));
        retire(pins, secondary);
        assert pins.reservedAppIds().equals(Set.of(10050));
        Pin fourth = pins.prepare(FOURTH, 10400, 0, 0);
        assert reserved.equals(Set.of(10050, 10123, 10200)); // A copy, not a live view.

        // It agrees with isAppIdPinned over the whole application range.
        pins.beginRetire(low);
        Set<Integer> current = pins.reservedAppIds();
        assert current.equals(Set.of(10050, 10400));
        for (int appId = 10_000; appId <= 19_999; appId++) {
            assert pins.isAppIdPinned(appId) == current.contains(appId);
        }
        // A restart preserves the RETIRING pin; no implicit release or activation.
        NativePrincipalPins rebooted = new NativePrincipalPins(8);
        rebooted.restore(pins.snapshotForWrite());
        assert rebooted.reservedAppIds().equals(Set.of(low.record().appId, fourth.record().appId));
        assert rebooted.findId(low.record().id).phase() == Phase.RETIRING;
    }

    private static void restoreNeverActivates() {
        NativePrincipalPins before = new NativePrincipalPins(4);
        Pin active = before.prepare(APP, 10123, 0, 0);
        before.commit(active);
        Pin pending = before.prepare(OTHER, 10200, 0, 0);
        Snapshot durable = before.snapshotForWrite();
        assert durable.equals(new Snapshot(2, List.of(active.record(), pending.record())));

        NativePrincipalPins after = new NativePrincipalPins(4);
        List<Pin> restored = after.restore(durable);
        assert restored.size() == 2;
        for (Pin pin : restored) {
            assert pin.phase() == Phase.PENDING; // Including the formerly ACTIVE record.
        }
        Pin again = after.find(APP, 0);
        assert again == restored.get(0) && again.record().equals(active.record());
        assert after.prepare(APP, 10123, 0, 0) == again && again.phase() == Phase.PENDING;
        after.commit(again); // Only an explicit commit after revalidation activates it.
        assert again.phase() == Phase.ACTIVE && restored.get(1).phase() == Phase.PENDING;
        assert after.snapshotForWrite().equals(durable);
        refused(() -> after.commit(active)); // A handle from before the restart is foreign.
    }

    private static void emptySnapshotKeepsCounter() {
        NativePrincipalPins pins = new NativePrincipalPins(4);
        Pin first = pins.prepare(APP, 10123, 0, 0);
        retire(pins, first);
        Pin second = pins.prepare(APP, 10123, 0, 0);
        assert second.record().id == 2 && pins.findId(1) == null; // A released ID is not reused.
        pins.beginRetire(second);
        Snapshot empty = pins.snapshotWithout(second);
        assert empty.equals(new Snapshot(2, List.of()));
        pins.finishRetire(second);
        assert pins.snapshotForWrite().equals(empty);

        NativePrincipalPins rebooted = new NativePrincipalPins(4);
        assert rebooted.restore(empty).isEmpty();
        assert rebooted.snapshotForWrite().equals(empty); // lastId survives without records.
        assert rebooted.prepare(APP, 10123, 0, 0).record().id == 3;
    }

    private static void immutableValues() {
        Record first = new Record(1, APP, 10123, 0, 0);
        Record second = new Record(2, OTHER, 10200, 0, 0);
        List<Record> source = new ArrayList<>(List.of(first));
        Snapshot snapshot = new Snapshot(1, source);
        source.add(second);
        source.set(0, second);
        assert snapshot.records.equals(List.of(first)); // Copied, not shared.
        unsupported(() -> snapshot.records.add(second));
        unsupported(() -> snapshot.records.set(0, second));
        unsupported(() -> snapshot.records.remove(0));
        unsupported(() -> snapshot.records.clear());

        NativePrincipalPins pins = new NativePrincipalPins(4);
        Pin pin = pins.prepare(APP, 10123, 0, 0);
        Snapshot written = pins.snapshotForWrite();
        pins.commit(pin);
        pins.prepare(OTHER, 10200, 0, 0);
        pins.beginRetire(pin);
        assert written.equals(new Snapshot(1, List.of(pin.record()))); // Not a live view.
        unsupported(() -> written.records.clear());

        Record same = new Record(1, APP, 10123, 0, 0);
        assert first.equals(same) && first.hashCode() == same.hashCode();
        List<Record> different = List.of(new Record(2, APP, 10123, 0, 0),
                new Record(1, OTHER, 10123, 0, 0), new Record(1, APP, 10124, 0, 0),
                new Record(1, APP, 10123, 1, 0), new Record(1, APP, 10123, 0, 1));
        for (Record record : different) {
            assert !first.equals(record) && !record.equals(first);
        }
        Snapshot equal = new Snapshot(1, List.of(same));
        assert snapshot.equals(equal) && snapshot.hashCode() == equal.hashCode();
        assert !snapshot.equals(new Snapshot(2, List.of(first)));
        assert !snapshot.equals(new Snapshot(1, List.of()));
    }

    private static void markerValidationAndCopies() {
        Record record = new Record(1, APP, 10123, 0, 0);
        NativePrincipalPins pins = new NativePrincipalPins(3);
        for (Set<Long> bad : List.of(Set.of(0L), Set.of(-1L), Set.of(2L), Set.of(Long.MAX_VALUE))) {
            invalid(() -> pins.restore(new Snapshot(1, List.of(record), bad)));
            assert pins.snapshotForWrite().equals(new Snapshot(0, List.of()));
        }
        missing(() -> new Snapshot(0, List.of(), null));
        Set<Long> source = new HashSet<>(Set.of(1L));
        Snapshot snapshot = new Snapshot(1, List.of(record), source);
        source.clear();
        assert snapshot.retiringIds.equals(Set.of(1L));
        unsupported(() -> snapshot.retiringIds.clear());
        unsupported(() -> snapshot.retiringIds.add(2L));
        assert !snapshot.equals(new Snapshot(1, List.of(record)));
        pins.restore(snapshot);
        assert pins.findId(1).phase() == Phase.RETIRING;
        refused(() -> pins.commit(pins.findId(1)));
    }

    private static Set<String> publicMethods(Class<?> type) {
        Set<String> names = new HashSet<>();
        for (Method method : type.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers())) names.add(method.getName());
        }
        return names;
    }

    // No clearing, UID change, authority flag or other way around the phases is public.
    private static void closedSurface() {
        Set<String> methods = publicMethods(NativePrincipalPins.class);
        assert methods.equals(Set.of("prepare", "find", "findId", "isPackagePinned",
                "isAppIdPinned", "reservedAppIds", "snapshotForWrite", "snapshotWithout", "commit", "beginRetire",
                "finishRetire", "restore", "restoreBindingsWithoutCounter", "hasKnownCounter")) : methods;
        assert publicMethods(Pin.class).equals(Set.of("record", "phase", "toString"));
        assert Arrays.asList(Phase.values())
                .equals(List.of(Phase.PENDING, Phase.ACTIVE, Phase.RETIRING, Phase.RETIRED));
        assert Pin.class.getConstructors().length == 0; // Only an instance creates handles.
        assert NativePrincipalPins.class.getFields().length == 0;
        for (Class<?> type : List.of(NativePrincipalPins.class, Pin.class, Record.class,
                Snapshot.class)) {
            assert Modifier.isFinal(type.getModifiers()) : type; // No subclass can widen it.
            for (Field field : type.getFields()) {
                assert Modifier.isFinal(field.getModifiers()) : field;
            }
        }
    }

    private static void lostWritesKeepHandles() {
        NativePrincipalPins pins = new NativePrincipalPins(4);
        Pin pin = pins.prepare(APP, 10123, 0, 0);
        Snapshot attempt = pins.snapshotForWrite();
        // The write outcome is unknown. Nothing is released, and the retry uses the same handle.
        assert pins.find(APP, 0) == pin && pins.prepare(APP, 10123, 0, 0) == pin;
        assert pins.snapshotForWrite().equals(attempt) && pin.phase() == Phase.PENDING;
        pins.commit(pin);
        pins.beginRetire(pin);
        Snapshot marker = pins.snapshotForWrite();
        Snapshot omission = pins.snapshotWithout(pin);
        // Either write can be lost. The pin stays RETIRING and reserved.
        pins.beginRetire(pin);
        assert pins.snapshotForWrite().equals(marker) && pin.phase() == Phase.RETIRING;
        assert pins.snapshotWithout(pin).equals(omission);
        assert pins.findId(1) == pin && pins.isAppIdPinned(10123);
        pins.finishRetire(pin);
        assert !pins.isAppIdPinned(10123);
    }

    private static long prepareAndDrop(NativePrincipalPins pins) {
        return pins.prepare(APP, 10123, 0, 0).record().id;
    }

    private static void noAutomaticRelease() throws InterruptedException {
        NativePrincipalPins pins = new NativePrincipalPins(4);
        long id = prepareAndDrop(pins);
        // Invite a collection. Pins are strong state, so the outcome must not depend on it.
        WeakReference<Object> probe = new WeakReference<>(new Object());
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (probe.get() != null && System.nanoTime() - deadline < 0) {
            System.gc();
            Thread.sleep(10);
        }
        Pin pin = pins.findId(id);
        assert pin != null && pin.phase() == Phase.PENDING;
        assert pins.isPackagePinned(APP) && pins.isAppIdPinned(10123);
    }

    private static Thread daemon(Runnable body) {
        Thread thread = new Thread(body, "pin-monitor-check");
        thread.setDaemon(true);
        return thread;
    }

    private static void awaitBlocked(Thread thread) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (thread.getState() != Thread.State.BLOCKED) {
            assert thread.isAlive() && System.nanoTime() - deadline < 0
                    : "call did not wait for the component monitor";
            Thread.sleep(1);
        }
        Thread.sleep(50);
        assert thread.getState() == Thread.State.BLOCKED;
    }

    private static void callsWaitForTheMonitor() throws InterruptedException {
        NativePrincipalPins pins = new NativePrincipalPins(4);
        AtomicReference<Pin> prepared = new AtomicReference<>();
        Thread preparing = daemon(() -> prepared.set(pins.prepare(APP, 10123, 0, 0)));
        synchronized (pins) {
            preparing.start();
            awaitBlocked(preparing);
            assert prepared.get() == null && pins.findId(1) == null;
        }
        preparing.join(TimeUnit.SECONDS.toMillis(10));
        Pin pin = prepared.get();
        assert !preparing.isAlive() && pin != null && pins.findId(1) == pin;

        Thread retiring = daemon(() -> pins.beginRetire(pin));
        synchronized (pins) {
            retiring.start();
            awaitBlocked(retiring);
            assert pin.phase() == Phase.PENDING;
        }
        retiring.join(TimeUnit.SECONDS.toMillis(10));
        assert !retiring.isAlive() && pin.phase() == Phase.RETIRING;

        // The allocator barrier read takes the same monitor, so it sees a single state.
        AtomicReference<Set<Integer>> observed = new AtomicReference<>();
        Thread reading = daemon(() -> observed.set(pins.reservedAppIds()));
        synchronized (pins) {
            reading.start();
            awaitBlocked(reading);
            assert observed.get() == null;
        }
        reading.join(TimeUnit.SECONDS.toMillis(10));
        assert !reading.isAlive() && observed.get().equals(Set.of(10123));
    }

    // Starts every racer at one barrier and returns their results in index order.
    private static <T> List<T> race(int threads, Racer<T> racer) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads, body -> {
            Thread thread = new Thread(body, "pin-race");
            thread.setDaemon(true);
            return thread;
        });
        try {
            CyclicBarrier start = new CyclicBarrier(threads);
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                int index = i;
                futures.add(pool.submit(() -> {
                    start.await(10, TimeUnit.SECONDS);
                    return racer.run(index);
                }));
            }
            List<T> results = new ArrayList<>();
            for (Future<T> future : futures) {
                results.add(future.get(30, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private static Pin only(List<Pin> results) {
        Pin found = null;
        for (Pin pin : results) {
            if (pin == null) continue;
            assert found == null : "two winners";
            found = pin;
        }
        assert found != null : "no winner";
        return found;
    }

    private static void concurrentPreparesAndRetirement() throws Exception {
        NativePrincipalPins same = new NativePrincipalPins(4);
        List<Pin> exact = race(RACERS, index -> same.prepare(APP, 10123, 0, 0));
        for (Pin pin : exact) {
            assert pin == exact.get(0);
        }
        assert same.snapshotForWrite().equals(new Snapshot(1, List.of(exact.get(0).record())));

        NativePrincipalPins conflicting = new NativePrincipalPins(4);
        List<Pin> serials = race(RACERS, index -> {
            try {
                return conflicting.prepare(APP, 10123, 0, index);
            } catch (IllegalStateException conflict) {
                return null;
            }
        });
        Pin winner = only(serials);
        assert serials.indexOf(winner) == winner.record().userSerial; // Its own input, intact.
        assert conflicting.snapshotForWrite().equals(new Snapshot(1, List.of(winner.record())));

        NativePrincipalPins bounded = new NativePrincipalPins(5);
        List<Pin> admitted = race(RACERS, index -> {
            try {
                return bounded.prepare("dev.andrix.p" + index, 10100 + index, 0, 0);
            } catch (IllegalStateException full) {
                return null;
            }
        });
        Set<Long> ids = new HashSet<>();
        Set<Integer> appIds = new HashSet<>();
        int winners = 0;
        for (Pin pin : admitted) {
            if (pin == null) continue;
            ++winners;
            ids.add(pin.record().id);
            appIds.add(pin.record().appId);
        }
        assert winners == 5 && ids.equals(Set.of(1L, 2L, 3L, 4L, 5L)) : ids;
        Snapshot bound = bounded.snapshotForWrite();
        assert bound.lastId == 5 && bound.records.size() == 5;
        assert bounded.reservedAppIds().equals(appIds);

        NativePrincipalPins shared = new NativePrincipalPins(RACERS);
        Pin holder = only(race(RACERS, index -> {
            try {
                return shared.prepare("dev.andrix.p" + index, 10500, 0, 0);
            } catch (IllegalStateException taken) {
                return null;
            }
        }));
        assert shared.snapshotForWrite().equals(new Snapshot(1, List.of(holder.record())));
        assert shared.reservedAppIds().equals(Set.of(10500));

        // Commit racing retirement always ends RETIRING. A commit came first or was refused.
        NativePrincipalPins racing = new NativePrincipalPins(4);
        Pin contested = racing.prepare(APP, 10123, 0, 0);
        race(RACERS, index -> {
            if (index % 2 == 0) {
                racing.beginRetire(contested);
                return Boolean.TRUE;
            }
            try {
                racing.commit(contested);
                return Boolean.TRUE;
            } catch (IllegalStateException retiring) {
                return Boolean.FALSE;
            }
        });
        assert contested.phase() == Phase.RETIRING;
        assert racing.snapshotForWrite().equals(new Snapshot(1, List.of(contested.record()), Set.of(1L)));
        List<Boolean> finished = race(RACERS, index -> {
            try {
                racing.finishRetire(contested);
                return Boolean.TRUE;
            } catch (IllegalStateException stale) {
                return Boolean.FALSE;
            }
        });
        assert Collections.frequency(finished, Boolean.TRUE) == 1;
        assert contested.phase() == Phase.RETIRED && racing.findId(1) == null;
        assert racing.reservedAppIds().isEmpty();

        // Exact retries racing one retirement see the old pin, then refusals, then one new pin.
        NativePrincipalPins cycle = new NativePrincipalPins(4);
        Pin old = cycle.prepare(APP, 10123, 0, 0);
        cycle.commit(old);
        Set<Pin> replacements = Collections.synchronizedSet(
                Collections.newSetFromMap(new IdentityHashMap<Pin, Boolean>()));
        List<String> histories = race(RACERS, index -> {
            if (index == 0) {
                retire(cycle, old);
                return "";
            }
            StringBuilder history = new StringBuilder();
            for (int attempt = 0; attempt < 2_000; attempt++) {
                try {
                    Pin seen = cycle.prepare(APP, 10123, 0, 0);
                    if (seen == old) {
                        history.append('O');
                    } else {
                        replacements.add(seen);
                        history.append('N');
                    }
                } catch (IllegalStateException retiring) {
                    history.append('R');
                }
            }
            return history.toString();
        });
        Pattern order = Pattern.compile("O*R*N*");
        for (String history : histories) {
            assert order.matcher(history).matches() : history;
        }
        Pin current = cycle.prepare(APP, 10123, 0, 0);
        assert current != old && current.record().id == 2 && current.phase() == Phase.PENDING;
        assert replacements.isEmpty()
                || (replacements.size() == 1 && replacements.contains(current));
        assert old.phase() == Phase.RETIRED && cycle.findId(1) == null;
        assert cycle.reservedAppIds().equals(Set.of(10123));
        assert cycle.snapshotForWrite().equals(new Snapshot(2, List.of(current.record())));
    }

    private static void existingBindingsWithoutCounter() {
        NativePrincipalPins pins = new NativePrincipalPins(4);
        assert pins.hasKnownCounter();
        Record a = new Record(17, APP, 10123, 0, 7);
        Record b = new Record(Long.MAX_VALUE, "dev.andrix.other", 10124, 0, 8);
        List<Pin> restored = pins.restoreBindingsWithoutCounter(List.of(a, b), Set.of(b.id));
        Pin first = restored.get(0), last = restored.get(1);
        assert !pins.hasKnownCounter();
        assert first.phase() == Phase.PENDING && last.phase() == Phase.RETIRING;
        assert pins.findId(a.id) == first && pins.findId(b.id) == last;
        assert pins.prepare(APP, 10123, 0, 7) == first;
        assert pins.reservedAppIds().equals(Set.of(10123, 10124));
        refused(pins::snapshotForWrite);
        refused(() -> pins.snapshotWithout(last));
        refused(() -> pins.prepare("dev.andrix.new", 10125, 0, 9));
        refused(() -> pins.prepare("dev.andrix.other", 10124, 0, 8));
        refused(() -> pins.commit(last));
        // The separate slot transaction, not a guessed global snapshot, must
        // provide the real durability and current-identity acknowledgement.
        pins.commit(first);
        assert first.phase() == Phase.ACTIVE;
        pins.beginRetire(first);
        pins.finishRetire(first); pins.finishRetire(last);
        assert pins.reservedAppIds().isEmpty() && !pins.hasKnownCounter();
        refused(() -> pins.prepare(APP, 10123, 0, 7));
        refused(pins::snapshotForWrite);
        refused(() -> pins.restore(new Snapshot(Long.MAX_VALUE, List.of())));
        refused(() -> pins.restoreBindingsWithoutCounter(List.of(), Set.of()));

        NativePrincipalPins empty = new NativePrincipalPins(1);
        empty.restoreBindingsWithoutCounter(List.of(), Set.of());
        assert !empty.hasKnownCounter();
        refused(() -> empty.prepare(APP, 10123, 0, 7));
        refused(empty::snapshotForWrite);

        NativePrincipalPins invalidInput = new NativePrincipalPins(2);
        invalid(() -> invalidInput.restoreBindingsWithoutCounter(List.of(a, a), Set.of()));
        invalid(() -> invalidInput.restoreBindingsWithoutCounter(List.of(a), Set.of(18L)));
        assert invalidInput.hasKnownCounter();
        assert invalidInput.snapshotForWrite().equals(new Snapshot(0, List.of()));
        assert invalidInput.prepare(APP, 10123, 0, 7).record().id == 1;
    }

    public static void main(String[] args) throws Exception {
        requireAssertions();
        phaseTransitions();
        exactRetryAndConflicts();
        validation();
        capacityAndCounters();
        foreignAndStaleHandles();
        restoreValidationAndAtomicity();
        retirementMarkersAndTargetOmission();
        reservedAppIdsBarrier();
        restoreNeverActivates();
        existingBindingsWithoutCounter();
        emptySnapshotKeepsCounter();
        immutableValues();
        markerValidationAndCopies();
        closedSurface();
        lostWritesKeepHandles();
        noAutomaticRelease();
        callsWaitForTheMonitor();
        concurrentPreparesAndRetirement();
        System.out.println("Native principal pin phases/retry/restore/capacity/concurrency"
                + " passed; Android unqualified");
    }
}
