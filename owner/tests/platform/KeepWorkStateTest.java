// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import dev.andrix.server.KeepWorkState.Record;

public final class KeepWorkStateTest {
    private static final long INSTANCE = 71;

    private static OwnerLifecycleState ready() {
        OwnerLifecycleState state = new OwnerLifecycleState();
        state.ce(1, 1, true); state.user(true);
        return state;
    }

    private static Record<Object> begin(KeepWorkState<Object> state, Object binder,
            long work, OwnerLifecycleState platform) {
        return state.begin(binder, new Object(), work, INSTANCE,
                platform.snapshot().generation, platform.snapshot(), "nonce");
    }

    private static void bindingAndCompletion() {
        OwnerLifecycleState platform = ready();
        KeepWorkState<Object> state = new KeepWorkState<>(INSTANCE);
        Object binder = new Object();
        Record<Object> first = begin(state, binder, 1, platform);
        assert first != null && first.binderIdentity == binder;
        assert state.active(platform.snapshot()) == null;
        assert !state.commit(first, platform.snapshot()); // Link not yet completed.
        assert begin(state, binder, 1, platform) == null; // No idempotent second consent.
        assert begin(state, binder, 2, platform) == null;
        assert begin(state, new Object(), 2, platform) == null;
        state.abort(first);
        Record<Object> next = begin(state, binder, 2, platform);
        assert next != null && next.registration > first.registration;
        assert !first.token.equals(next.token);
        assert !state.linked(first, platform.snapshot());
        assert !state.commit(first, platform.snapshot());
        state.died(first); // Delayed callback from an unlinked old registration.
        assert state.isBound(next);
        assert state.linked(next, platform.snapshot());
        assert state.commit(next, platform.snapshot());
        assert !state.commit(next, platform.snapshot());
        assert state.active(platform.snapshot()) == next;
        assert state.stop(first.token) == null;
        assert state.active(platform.snapshot()) == next;
        state.died(next);
        assert state.active(platform.snapshot()) == null;
        assert state.retiring() == null;
    }

    private static void pendingStopAndRetirement() {
        OwnerLifecycleState platform = ready();
        KeepWorkState<Object> state = new KeepWorkState<>(INSTANCE);
        Record<Object> first = begin(state, new Object(), 1, platform);
        assert state.stop(first.token) == first; // Stop before link/commit is effective.
        assert !state.linked(first, platform.snapshot());
        assert !state.commit(first, platform.snapshot());
        state.abort(first); // Failed completion cannot erase concurrent Stop.
        assert state.retiring() == first && state.isBound(first);
        assert state.stop(first.token) == null;
        assert begin(state, new Object(), 2, platform) == null;
        assert state.beginStop(first) && state.canStop(first);
        state.died(first);
        assert !state.canStop(first);
        assert begin(state, new Object(), 2, platform) == null; // In-flight callback fence.
        state.finishStop(first);
        Record<Object> next = begin(state, new Object(), 2, platform);
        assert next != null;
        assert !state.beginStop(first); // Delayed old task cannot acquire new authority.
        state.finishStop(first); state.died(first);
        assert state.isBound(next);
    }

    private static void epochsAndGlobalGating() {
        OwnerLifecycleState platform = ready();
        KeepWorkState<Object> state = new KeepWorkState<>(INSTANCE);
        Record<Object> first = begin(state, new Object(), 1, platform);
        assert state.linked(first, platform.snapshot());
        assert state.commit(first, platform.snapshot());
        platform.ce(3, 2, true); // New positive overtook the negative delivery.
        assert platform.snapshot().available;
        assert platform.snapshot().generation != first.generation;
        assert state.active(platform.snapshot()) == null; // Query itself fences epochs.
        assert state.retiring() == first;
        assert begin(state, new Object(), 2, platform) == null;
        state.died(first);
        Record<Object> next = begin(state, new Object(), 2, platform);
        assert next != null;
        platform.user(false);
        assert !state.linked(next, platform.snapshot());
        platform.user(true);
        assert platform.snapshot().available;
        assert !state.commit(next, platform.snapshot());
        state.died(next);
        Record<Object> third = begin(state, new Object(), 3, platform);
        platform.ce(4, 2, false);
        state.observe(platform.snapshot());
        assert state.retiring() == third;
        platform.fail();
        assert state.active(platform.snapshot()) == null;
        state.died(third);
        assert begin(state, new Object(), 4, platform) == null;
    }

    private static void validationAndOverflow() throws Exception {
        OwnerLifecycleState platform = ready();
        KeepWorkState<Object> state = new KeepWorkState<>(INSTANCE);
        Object binder = new Object(), lifetime = new Object();
        long generation = platform.snapshot().generation;
        assert state.begin(null, lifetime, 1, INSTANCE, generation, platform.snapshot(), "x") == null;
        assert state.begin(binder, null, 1, INSTANCE, generation, platform.snapshot(), "x") == null;
        assert state.begin(binder, lifetime, 0, INSTANCE, generation, platform.snapshot(), "x") == null;
        assert state.begin(binder, lifetime, -1, INSTANCE, generation, platform.snapshot(), "x") == null;
        assert state.begin(binder, lifetime, 1, INSTANCE + 1, generation, platform.snapshot(), "x") == null;
        assert state.begin(binder, lifetime, 1, INSTANCE, generation + 1, platform.snapshot(), "x") == null;
        assert state.begin(binder, lifetime, 1, INSTANCE, 0, platform.snapshot(), "x") == null;
        assert state.begin(binder, lifetime, 1, INSTANCE, generation, platform.snapshot(), "") == null;
        var counter = KeepWorkState.class.getDeclaredField("lastRegistration");
        counter.setAccessible(true); counter.setLong(state, Long.MAX_VALUE - 1);
        Record<Object> last = begin(state, binder, Long.MAX_VALUE, platform);
        assert last != null && last.registration == Long.MAX_VALUE;
        state.died(last);
        assert begin(state, binder, 1, platform) == null;
        assert counter.getLong(state) == Long.MAX_VALUE; // Never wraps or reuses a registration.
        assert platform.snapshot().available; // Keep exhaustion cannot invent global CE/user state.
    }

    public static void main(String[] args) throws Exception {
        bindingAndCompletion(); pendingStopAndRetirement(); epochsAndGlobalGating();
        validationAndOverflow();
        System.out.println("Keep state binding/completion/retirement/epoch/overflow passed; Android unqualified");
    }
}
