// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.os.Binder;
import android.os.Build;
import android.system.Os;
import com.android.server.LocalServices;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/** Actual manager/store below host PMS facades. Not Android authority or filesystem qualification. */
@SuppressWarnings("try")
public final class NativePrincipalWriterFixtureTest {
    // Legacy version 1 writer runs: Format.V1 explicitly, never the facade's production default.
    private static final NativeIdentityStore.Format LEGACY = NativeIdentityStore.Format.V1;
    private static final String SUBJECT = "dev.andrix.proof.principalclosed";
    private static final String INSTANCE = "a".repeat(32), NEXT = "b".repeat(32), NONCE = "c".repeat(32);
    private static final Set<String> SIGNERS = Set.of(
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
    private static void contains(String text, String value) { assert text.contains(value) : text; }
    private static void refused(Runnable call) {
        try { call.run(); } catch (IllegalArgumentException | IllegalStateException expected) { return; }
        throw new AssertionError("request unexpectedly accepted");
    }
    private static NativePrincipalWriterFixture fixture(NativePrincipalManager manager, String instance) {
        return new NativePrincipalWriterFixture(manager, instance, SIGNERS);
    }
    public static void main(String[] args) throws Exception {
        if (!NativePrincipalWriterFixtureTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        UserManagerInternal users = new UserManagerInternal();
        LocalServices.addService(UserManagerInternal.class, users);
        PackageManagerService pm = new PackageManagerService(null, true, LEGACY);
        PackageSetting subject = pm.mSettings.add(SUBJECT, 10148);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        LocalServices.addService(NativePrincipalManager.class, manager);
        NativePrincipalWriterFixture probe = fixture(manager, INSTANCE);
        StringWriter output = new StringWriter(), errors = new StringWriter();
        Binder.callerUid = 2000;
        assert NativePrincipalWriterFixture.command(new PrintWriter(output), new PrintWriter(errors), new String[]{"info"}) == 1;
        assert output.toString().isEmpty();
        Binder.callerUid = 0; Build.IS_DEBUGGABLE = false;
        assert NativePrincipalWriterFixture.command(new PrintWriter(output), new PrintWriter(errors), new String[]{"info"}) == 1;
        Build.IS_DEBUGGABLE = true;
        assert NativePrincipalWriterFixture.command(new PrintWriter(output), new PrintWriter(errors), new String[]{"info"}) == 0;
        contains(output.toString(), "\"execution_authorized\":false");
        assert pm.mSettings.pins.reservedAppIds().isEmpty();
        java.util.regex.Matcher server = java.util.regex.Pattern.compile("\"instance\":\"([0-9a-f]{32})\"").matcher(output.toString());
        assert server.find();
        StringWriter wrongCertificate = new StringWriter();
        assert NativePrincipalWriterFixture.command(new PrintWriter(wrongCertificate), new PrintWriter(errors),
                new String[]{"select-new", server.group(1), NONCE}) == 0;
        contains(wrongCertificate.toString(), "\"state\":\"selection-refused\"");
        assert pm.mSettings.pins.reservedAppIds().isEmpty(); // Default certificate check was reached.
        StringWriter staleReply = new StringWriter();
        assert NativePrincipalWriterFixture.command(new PrintWriter(staleReply), new PrintWriter(errors),
                new String[]{"status", "0".repeat(32), NONCE}) == 1;
        contains(staleReply.toString(), "STALE_INSTANCE"); contains(staleReply.toString(), server.group(1));

        refused(() -> probe.execute("prepare", INSTANCE, NONCE));
        refused(() -> probe.execute("status", INSTANCE, NONCE));
        refused(() -> probe.execute("select-new", NEXT, NONCE));
        refused(() -> probe.execute("select-new", INSTANCE, "malformed"));
        refused(() -> probe.execute("release", INSTANCE, NONCE));
        contains(probe.execute("select-new", INSTANCE, NONCE), "\"state\":\"selected\"");
        assert pm.mSettings.pins.reservedAppIds().isEmpty();
        refused(() -> probe.execute("select-new", INSTANCE, "d".repeat(32)));
        refused(() -> probe.execute("select-rebind", INSTANCE, NONCE));
        refused(() -> probe.execute("commit", INSTANCE, NONCE));
        contains(probe.execute("prepare", INSTANCE, NONCE), "\"pin_phase\":\"PENDING\"");
        long id = manager.identity(manager.find(SUBJECT, 0)).id;
        assert pm.mSettings.pins.reservedAppIds().equals(Set.of(10148));
        contains(probe.execute("prepare", INSTANCE, NONCE), "\"principal_id\":\"" + id + "\"");
        Os.forbiddenMonitor = pm.mLock;
        Os.failSync = true;
        contains(probe.execute("commit", INSTANCE, NONCE), "\"last_commit_result\":\"false\"");
        contains(probe.execute("status", INSTANCE, NONCE), "\"state\":\"uncertain\"");
        assert manager.identity(manager.find(SUBJECT, 0)).id == id;
        Os.failSync = false;
        // Ignore this acknowledged response, then reconcile the SAME request.
        probe.execute("commit", INSTANCE, NONCE);
        contains(probe.execute("status", INSTANCE, NONCE), "\"commit_acknowledged\":true");
        String retried = probe.execute("commit", INSTANCE, NONCE);
        contains(retried, "\"principal_id\":\"" + id + "\"");
        contains(retried, "\"last_commit_result\":\"true\"");
        long counter = pm.mSettings.mNativeIdentityLoaded.header.value.lastId;
        assert counter == id;

        // A later uncertain confirmation must not erase the earlier acknowledgement.
        Os.failSync = true;
        String uncertain = probe.execute("commit", INSTANCE, NONCE);
        contains(uncertain, "\"last_commit_result\":\"false\"");
        contains(uncertain, "\"commit_acknowledged\":true");
        Os.failSync = false;
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<String> workerReply = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try { workerReply.set(probe.execute("commit", INSTANCE, NONCE)); } catch (Throwable error) { failure.set(error); }
        });
        worker.setDaemon(true);
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            worker.start();
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (!probe.snapshot("status").contains("\"busy\":true") && System.nanoTime() < deadline) {
                Thread.sleep(1);
            }
            contains(probe.execute("status", INSTANCE, NONCE), "\"busy\":true");
            contains(probe.execute("commit", INSTANCE, NONCE), "\"result\":\"in-flight\"");
        }
        worker.join(5000);
        assert !worker.isAlive() && failure.get() == null;
        contains(workerReply.get(), "\"last_commit_result\":\"true\"");
        contains(workerReply.get(), "\"busy\":false");
        assert pm.mSettings.mNativeIdentityLoaded.header.value.lastId == counter;
        refused(() -> probe.execute("prepare", INSTANCE, NONCE));
        java.util.Set<Long> attempts = java.util.concurrent.ConcurrentHashMap.newKeySet();
        Thread[] racing = new Thread[2];
        for (int index = 0; index < racing.length; index++) {
            racing[index] = new Thread(() -> {
                try {
                    for (int turn = 0; turn < 20; turn++) {
                        String response = probe.execute("commit", INSTANCE, NONCE);
                        if (response.contains("\"result\":\"recorded\"")) {
                            contains(response, "\"busy\":false");
                            contains(response, "\"last_commit_result\":\"true\"");
                            java.util.regex.Matcher attempt = java.util.regex.Pattern.compile("\"attempt\":([0-9]+)").matcher(response);
                            assert attempt.find() && attempts.add(Long.parseLong(attempt.group(1)));
                        } else contains(response, "\"result\":\"in-flight\"");
                    }
                } catch (Throwable error) { failure.compareAndSet(null, error); }
            });
            racing[index].setDaemon(true); racing[index].start();
        }
        for (Thread thread : racing) { thread.join(10000); assert !thread.isAlive(); }
        assert failure.get() == null && !attempts.isEmpty() : failure.get();
        assert pm.mSettings.mNativeIdentityLoaded.header.value.lastId == counter;

        // A returned true and current authority are different. Failed revalidation
        // keeps both the prior acknowledgement and the original uncertain request.
        subject.version++;
        contains(probe.execute("commit", INSTANCE, NONCE), "\"last_commit_result\":\"exception\"");
        contains(probe.snapshot("status"), "\"commit_acknowledged\":true");
        refused(() -> probe.execute("select-new", INSTANCE, "d".repeat(32)));
        subject.version--;

        PackageManagerService rebooted = new PackageManagerService(pm.mSettings.root, false, LEGACY);
        rebooted.mSettings.add(SUBJECT, 10148);
        rebooted.mSettings.restoreAfterPackageSettings();
        NativePrincipalManager recovered = new NativePrincipalManager(rebooted);
        Os.forbiddenMonitor = rebooted.mLock;
        NativePrincipalManager.Handle stored = recovered.find(SUBJECT, 0);
        assert recovered.phase(stored) == NativePrincipalPins.Phase.PENDING;
        refused(() -> recovered.commit(stored)); // Metadata recovery is not designation.
        NativePrincipalWriterFixture wrongIntent = fixture(recovered, NEXT);
        refused(() -> wrongIntent.execute("commit", INSTANCE, NONCE));
        contains(wrongIntent.execute("select-new", NEXT, NONCE), "\"state\":\"selection-refused\"");
        refused(() -> wrongIntent.execute("prepare", NEXT, NONCE));
        NativePrincipalWriterFixture rebind = fixture(recovered, "e".repeat(32));
        contains(rebind.execute("select-rebind", "e".repeat(32), NONCE), "\"state\":\"selected\"");
        contains(rebind.execute("prepare", "e".repeat(32), NONCE), "\"principal_id\":\"" + id + "\"");
        assert recovered.find(SUBJECT, 0) == stored;
        contains(rebind.execute("commit", "e".repeat(32), NONCE), "\"commit_acknowledged\":true");
        assert rebooted.mSettings.mNativeIdentityLoaded.header.value.lastId == counter;
        Os.forbiddenMonitor = null;
        System.out.println("Writer fixture ownership and original-handle checks passed; Android route unqualified");
    }
}
