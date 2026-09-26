// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.os.Binder;
import com.android.server.LocalServices;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

/** Host-only bridge from actual fixture replies to the independent Python observer. */
public final class NativePrincipalWriterFixtureTranscript {
    private static final String INSTANCE = "a".repeat(32), NONCE = "b".repeat(32);
    private static final Set<String> SIGNERS = Set.of(
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
    private static void installHostFixture(NativePrincipalWriterFixture fixture) throws Exception {
        // This file is never copied into Android. Reflection is forbidden in the actual helper.
        var field = NativePrincipalWriterFixture.class.getDeclaredField("service");
        field.setAccessible(true); field.set(null, fixture);
    }
    private static void call(String label, String... args) {
        StringWriter output = new StringWriter(), errors = new StringWriter();
        int code = NativePrincipalWriterFixture.command(new PrintWriter(output), new PrintWriter(errors), args);
        System.out.println(label + "\t" + code + "\t"
                + Base64.getEncoder().encodeToString(output.toString().getBytes(StandardCharsets.UTF_8)) + "\t"
                + Base64.getEncoder().encodeToString(errors.toString().getBytes(StandardCharsets.UTF_8)));
    }
    public static void main(String[] args) throws Exception {
        if (!NativePrincipalWriterFixtureTranscript.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        PackageManagerService pm = new PackageManagerService();
        pm.mSettings.add("dev.andrix.proof.principalclosed", 10148);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        installHostFixture(new NativePrincipalWriterFixture(manager, INSTANCE, SIGNERS));
        Binder.callerUid = 2000; call("denied", "info");
        Binder.callerUid = 0; call("info", "info");
        call("stale", "status", "c".repeat(32), NONCE);
        call("select", "select-new", INSTANCE, NONCE);
        call("prepare", "prepare", INSTANCE, NONCE);
        call("commit", "commit", INSTANCE, NONCE);
        call("status", "status", INSTANCE, NONCE);
        NativePrincipalWriterFixture.Calls actual = new NativePrincipalWriterFixture.ManagerCalls(manager);
        NativePrincipalWriterFixture.Calls aborted = new NativePrincipalWriterFixture.Calls() {
            public NativePrincipalManager.Selection select() { throw new AssertionError("test detail must not reach reply"); }
            public NativePrincipalManager.Handle find() { return null; }
            public NativePrincipalManager.Handle prepare(NativePrincipalManager.Selection selection) { return actual.prepare(selection); }
            public boolean commit(NativePrincipalManager.Handle handle) { return actual.commit(handle); }
            public NativePrincipalPins.Record identity(NativePrincipalManager.Handle handle) { return actual.identity(handle); }
            public NativePrincipalPins.Phase phase(NativePrincipalManager.Handle handle) { return actual.phase(handle); }
        };
        installHostFixture(new NativePrincipalWriterFixture(aborted, INSTANCE, SIGNERS));
        call("unknown", "select-new", INSTANCE, NONCE);
    }
}
