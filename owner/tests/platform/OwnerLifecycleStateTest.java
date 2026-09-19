// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

public final class OwnerLifecycleStateTest {
    public static void main(String[] args) throws Exception {
        OwnerLifecycleState state = new OwnerLifecycleState();
        assert !state.snapshot().available;
        long bootstrap = state.userRevision();
        state.ce(1, 1, true);
        assert !state.snapshot().available;
        state.bootstrapUser(bootstrap, true);
        assert state.snapshot().available;
        long first = state.snapshot().generation;
        state.ce(2, 2, false);
        assert !state.snapshot().available && state.snapshot().generation > first;
        long revoked = state.snapshot().generation;
        state.ce(3, 2, true);
        assert state.snapshot().available;
        // Grant belongs to the new revocation epoch; it need not increment again.
        assert state.snapshot().generation == revoked;
        long second = state.snapshot().generation;
        state.ce(1, 1, true); // Stale initial snapshot must not undo a newer event.
        assert state.snapshot().generation == second;
        // A newer positive can overtake the intermediate negative delivery. Its
        // revocation generation must still force old native work to end.
        state.ce(5, 3, true);
        assert state.snapshot().available && state.snapshot().generation > second;
        long beforeStopping = state.snapshot().generation;
        state.user(false);
        assert !state.snapshot().available && state.snapshot().generation > beforeStopping;
        state.ce(6, 3, true);
        assert !state.snapshot().available; // CE does not override Android's user lifecycle.
        state.bootstrapUser(bootstrap, true); // Bootstrap began before the stop callback.
        assert !state.snapshot().available;
        state.user(true);
        assert state.snapshot().available;
        state.ce(0, 0, true);
        assert !state.snapshot().available; // Malformed source metadata fails permanently.
        state.user(true); state.ce(7, 4, true);
        assert !state.snapshot().available;

        OwnerLifecycleState exhausted = new OwnerLifecycleState();
        var field = OwnerLifecycleState.class.getDeclaredField("generation");
        field.setAccessible(true); field.setLong(exhausted, Long.MAX_VALUE - 1);
        exhausted.user(false); exhausted.user(true); exhausted.ce(1, 1, true);
        assert exhausted.snapshot().generation == Long.MAX_VALUE;
        assert !exhausted.snapshot().available;
        System.out.println("Android lifecycle composition/epoch model passed; runtime unqualified");
    }
}
