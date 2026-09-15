// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import android.content.Context;
import android.os.Binder;
import android.os.Build;
import android.os.ResultReceiver;
import android.os.ShellCommand;
import android.os.SystemClock;
import android.os.storage.StorageManager;

import dev.andrix.lifecycle.PlatformState;

public final class LifecycleFaultBinderTest {
    private static final class Adapter extends OwnerLifecycleBinder {
        final Object stateLock = new Object();
        final Object gate;
        long work = 31;
        boolean available = true, changeOnSecondCapture;
        int captures;
        ResultReceiver lastReceiver;
        Adapter(Context context) throws ReflectiveOperationException {
            super(context);
            var field = OwnerLifecycleBinder.class.getDeclaredField("faults");
            field.setAccessible(true); gate = field.get(this);
        }
        @Override protected PlatformState captureState() {
            assert !Thread.holdsLock(gate);
            synchronized (stateLock) {
                if (++captures == 2 && changeOnSecondCapture) ++work;
                PlatformState state = new PlatformState();
                state.instance = 11; state.generation = 2; state.available = available;
                state.keptWorkId = work; state.keepRegistration = 1;
                return state;
            }
        }
        int command(String... args) {
            lastReceiver = new ResultReceiver();
            onShellCommand(null, null, null, args, null, lastReceiver);
            return lastReceiver.result;
        }
        void assertOutsideLocks() {
            assert !Thread.holdsLock(gate) && !Thread.holdsLock(stateLock);
        }
    }

    private static void reset() {
        Binder.uid = 2000; Binder.pid = 200; Binder.clears = Binder.restores = 0;
        Build.IS_DEBUGGABLE = true; SystemClock.time = 100; SystemClock.sleeps = 0;
        SystemClock.onSleep = null; StorageManager.calls = 0; StorageManager.unlocked = true;
        StorageManager.throwOnLock = false; StorageManager.onLock = null;
    }
    private static void assertIdentityRestored() {
        assert Binder.uid == 2000 && Binder.pid == 200 && Binder.clears == Binder.restores;
    }

    public static void main(String[] args) throws Exception {
        reset(); Adapter a = new Adapter(new Context());
        for (int uid : new int[]{0, 1000, 7500, 10146, 102000}) {
            Binder.uid = uid;
            try { a.command("lock-ce-user0"); throw new AssertionError("caller accepted"); }
            catch (SecurityException expected) {
                assert StorageManager.calls == 0 && Binder.clears == 0
                        && a.lastReceiver.result == -1 && a.lastReceiver.sends == 1;
            }
        }
        Binder.uid = 2000; Binder.pid = 1;
        try { a.command("delay-next-snapshot"); throw new AssertionError("PID1 accepted"); }
        catch (SecurityException expected) { assert SystemClock.sleeps == 0; }
        Binder.pid = 200; Build.IS_DEBUGGABLE = false;
        try { a.command("lock-ce-user0"); throw new AssertionError("non-debug image accepted"); }
        catch (SecurityException expected) { assert StorageManager.calls == 0; }
        Build.IS_DEBUGGABLE = true;
        assert a.command("unknown") == 1;
        assert a.command("lock-ce-user0", "10") == 1;
        assert a.command("delay-next-snapshot", "900000") == 1;
        assert a.command("help") == 0 && ShellCommand.lastOut.contains("LAB ONLY");
        assert a.command() == 0;
        assert StorageManager.calls == 0 && Binder.clears == 0;
        StorageManager.onLock = a::assertOutsideLocks;
        assert a.command("lock-ce-user0") == 0;
        assert StorageManager.calls == 1 && !StorageManager.unlocked;
        assert ShellCommand.lastOut.contains("framework_ce_cache_after=false");
        assert ShellCommand.lastOut.contains("busy/errors");
        assertIdentityRestored();
        StorageManager.unlocked = true;
        assert a.command("lock-ce-user0") == 1 && StorageManager.calls == 1;

        reset(); a = new Adapter(new Context()); StorageManager.throwOnLock = true;
        StorageManager.onLock = a::assertOutsideLocks;
        assert a.command("lock-ce-user0") == 1 && StorageManager.calls == 1;
        assertIdentityRestored();
        StorageManager.throwOnLock = false;
        assert a.command("lock-ce-user0") == 1 && StorageManager.calls == 1;

        reset(); a = new Adapter(new Context()); a.changeOnSecondCapture = true;
        assert a.command("lock-ce-user0") == 1 && StorageManager.calls == 0;
        assertIdentityRestored();
        reset(); Context missing = new Context(); missing.storage = null; a = new Adapter(missing);
        assert a.command("lock-ce-user0") == 1 && StorageManager.calls == 0;
        assertIdentityRestored();
        reset(); a = new Adapter(new Context()); a.available = false;
        assert a.command("lock-ce-user0") == 1 && a.command("delay-next-snapshot") == 1;
        assert Binder.clears == 0;

        reset(); final Adapter delayed = new Adapter(new Context());
        assert delayed.command("delay-next-snapshot") == 0;
        assert delayed.command("delay-next-snapshot") == 1;
        assert delayed.command("lock-ce-user0") == 1 && Binder.clears == 0;
        PlatformState captured = delayed.captureState();
        SystemClock.onSleep = () -> {
            delayed.assertOutsideLocks();
            assert delayed.command("lock-ce-user0") == 1;
            delayed.available = false; // Simulate a real later change, not rewriting the old reply.
        };
        // Direct hook invocation isolates adapter ordering. Actual native caller
        // authorization remains in the separately inspected service entry point;
        // this facade is not Binder identity or key-authority proof.
        delayed.beforeReply(captured);
        assert SystemClock.sleeps == 1 && SystemClock.time == 2600;
        assert captured.available && captured.keptWorkId == 31; // Genuine old positive retained.
        delayed.beforeReply(captured); assert SystemClock.sleeps == 1;
        assert Binder.clears == 0;

        reset(); a = new Adapter(new Context()); assert a.command("delay-next-snapshot") == 0;
        SystemClock.time = 5100; a.beforeReply(a.captureState()); assert SystemClock.sleeps == 0;
        assert a.command("delay-next-snapshot") == 1;
        assert a.command("lock-ce-user0") == 0; // Expired arm holds no lock.
        assertIdentityRestored();

        reset(); a = new Adapter(new Context()); assert a.command("delay-next-snapshot") == 0;
        ++a.work; a.beforeReply(a.captureState()); --a.work; a.beforeReply(a.captureState());
        assert SystemClock.sleeps == 0 && a.command("delay-next-snapshot") == 1;

        reset(); a = new Adapter(new Context()); assert a.command("delay-next-snapshot") == 0;
        SystemClock.onSleep = () -> { throw new IllegalStateException("host delay failure"); };
        try { a.beforeReply(a.captureState()); throw new AssertionError("failure swallowed"); }
        catch (IllegalStateException expected) { /* The lab gate still releases its in-flight slot. */ }
        assert a.command("lock-ce-user0") == 0;
        assertIdentityRestored();
        System.out.println("Actual lab Binder adapter methods passed host facades; Android identity/key behavior unqualified");
    }
}
