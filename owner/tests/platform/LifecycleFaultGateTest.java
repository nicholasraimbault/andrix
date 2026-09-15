// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

public final class LifecycleFaultGateTest {
    private static LifecycleFaultGate.Target target(long instance, long generation,
            boolean available, long work, long registration) {
        return new LifecycleFaultGate.Target(instance, generation, available, work, registration);
    }
    private static LifecycleFaultGate.Target live() { return target(11, 2, true, 31, 1); }
    public static void main(String[] args) throws InterruptedException {
        LifecycleFaultGate gate = new LifecycleFaultGate();
        for (LifecycleFaultGate.Target invalid : new LifecycleFaultGate.Target[]{null,
                target(0, 2, true, 31, 1), target(11, 0, true, 31, 1),
                target(11, 2, false, 31, 1), target(11, 2, true, 0, 1),
                target(11, 2, true, 31, 0)}) {
            assert !gate.armDelay(invalid, 1);
            assert gate.beginKeyLock(invalid, 1) == null;
        }
        assert !gate.armDelay(live(), -1);
        assert !gate.armDelay(live(), Long.MAX_VALUE - 4999);
        assert gate.armDelay(live(), 100);
        assert !gate.armDelay(live(), 101);
        assert gate.beginKeyLock(live(), 101) == null;
        LifecycleFaultGate.Target ticket = gate.takeDelay(live(), 5099);
        assert ticket != null && gate.takeDelay(live(), 5099) == null;
        gate.finishDelay(live()); // Same values, wrong completion object.
        assert gate.beginKeyLock(live(), 5100) == null;
        gate.finishDelay(ticket);
        assert !gate.armDelay(live(), 5100); // One accepted delay per lifetime.
        LifecycleFaultGate.Target key = gate.beginKeyLock(live(), 5100);
        assert key != null;
        gate.finishKeyLock(live());
        assert gate.beginKeyLock(live(), 5101) == null;
        gate.finishKeyLock(key);
        assert gate.beginKeyLock(live(), 5101) == null; // No reuse after success/failure.

        for (LifecycleFaultGate.Target changed : new LifecycleFaultGate.Target[]{
                target(12, 2, true, 31, 1), target(11, 3, true, 31, 1),
                target(11, 2, true, 32, 1), target(11, 2, true, 31, 2),
                target(11, 2, false, 31, 1)}) {
            gate = new LifecycleFaultGate();
            assert gate.armDelay(live(), 100);
            assert gate.takeDelay(changed, 101) == null;
            assert gate.takeDelay(live(), 102) == null; // No trap left for a later target.
            assert !gate.armDelay(live(), 103);
        }
        for (long expired : new long[]{99, 5100, Long.MAX_VALUE, Long.MIN_VALUE}) {
            gate = new LifecycleFaultGate();
            assert gate.armDelay(live(), 100);
            assert gate.takeDelay(live(), expired) == null;
            assert !gate.armDelay(live(), 5101);
        }
        gate = new LifecycleFaultGate();
        assert gate.armDelay(live(), Long.MAX_VALUE - 5000);
        assert gate.takeDelay(live(), Long.MAX_VALUE - 1) != null;
        gate = new LifecycleFaultGate();
        assert gate.armDelay(live(), 0);
        assert gate.beginKeyLock(live(), 5000) != null; // Expired arm does not retain a lock.
        assert gate.takeDelay(live(), 5000) == null;
        gate = new LifecycleFaultGate();
        assert gate.beginKeyLock(live(), -1) == null;
        key = gate.beginKeyLock(live(), 0);
        assert key != null && !gate.armDelay(live(), 1);
        gate.finishKeyLock(key);
        assert gate.armDelay(live(), 1);

        final LifecycleFaultGate racing = new LifecycleFaultGate();
        var start = new java.util.concurrent.CountDownLatch(1);
        boolean[] armed = new boolean[2];
        Thread[] threads = new Thread[2];
        for (int i = 0; i < 2; ++i) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try { start.await(); }
                catch (InterruptedException error) { throw new AssertionError(error); }
                armed[index] = racing.armDelay(live(), 10);
            });
            threads[i].start();
        }
        start.countDown();
        for (Thread thread : threads) { thread.join(2000); assert !thread.isAlive(); }
        assert armed[0] != armed[1]; // Only one concurrent arm can consume the budget.
        assert racing.takeDelay(live(), 11) != null;
        assert racing.takeDelay(live(), 11) == null;
        System.out.println("Lab fault gate ordering passed; Android authority unqualified");
    }
}
