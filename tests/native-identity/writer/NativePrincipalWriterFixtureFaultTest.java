// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.LocalServices;
import java.util.Set;

/** Wrapper fault injection over actual manager handles. No Android runtime claim. */
public final class NativePrincipalWriterFixtureFaultTest {
    private static final String SUBJECT = "dev.andrix.proof.principalclosed";
    private static final String INSTANCE = "a".repeat(32), NONCE = "b".repeat(32);
    private static final Set<String> SIGNERS = Set.of(
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
    private static void has(String text, String value) { assert text.contains(value) : text; }
    private static void refusal(String code, Runnable action) {
        try { action.run(); } catch (NativePrincipalWriterFixture.Refused error) {
            assert code.equals(error.code) : error.code; return;
        }
        throw new AssertionError("expected " + code);
    }
    private static final class InjectedError extends Error {
        private static final long serialVersionUID = 1L;
        InjectedError(String message) { super(message); }
    }
    private static void error(Runnable action) {
        try { action.run(); } catch (InjectedError expected) { return; }
        throw new IllegalStateException("expected injected Error");
    }
    static final class Inject implements NativePrincipalWriterFixture.Calls {
        final NativePrincipalManager manager;
        final NativePrincipalWriterFixture.Calls actual;
        NativePrincipalManager.Selection firstSelection, overrideSelection;
        NativePrincipalManager.Handle overrideHandle;
        NativePrincipalManager foreign;
        boolean prepareException, prepareError, commitError, selectError;
        boolean observationAfterPrepare, observationAfterCommit, mismatchRecord, prepared;
        boolean failIdentity;
        int prepareCount, commitCount;
        Inject(NativePrincipalManager manager) {
            this.manager = manager; actual = new NativePrincipalWriterFixture.ManagerCalls(manager);
        }
        public NativePrincipalManager.Selection select() {
            if (selectError) throw new InjectedError("injected selection abort");
            return overrideSelection != null ? overrideSelection : actual.select();
        }
        public NativePrincipalManager.Handle find() { return actual.find(); }
        public NativePrincipalManager.Handle prepare(NativePrincipalManager.Selection selection) {
            prepareCount++;
            if (firstSelection == null) firstSelection = selection;
            else assert firstSelection == selection : "selection changed during continuation";
            NativePrincipalManager.Handle result = actual.prepare(selection);
            if (prepareException) { prepareException = false; throw new IllegalStateException("lost prepare result"); }
            if (prepareError) { prepareError = false; throw new InjectedError("aborted prepare result"); }
            prepared = true; failIdentity = observationAfterPrepare;
            return overrideHandle != null ? overrideHandle : result;
        }
        public boolean commit(NativePrincipalManager.Handle handle) {
            commitCount++;
            boolean result = actual.commit(handle);
            if (commitError) { commitError = false; throw new InjectedError("aborted commit result"); }
            failIdentity = observationAfterCommit;
            return result;
        }
        public NativePrincipalPins.Record identity(NativePrincipalManager.Handle handle) {
            if (failIdentity) { failIdentity = false; throw new IllegalStateException("observation unavailable"); }
            NativePrincipalPins.Record value = handle == overrideHandle && foreign != null
                    ? foreign.identity(handle) : actual.identity(handle);
            return prepared && mismatchRecord ? new NativePrincipalPins.Record(value.id + 100,
                    value.packageName, value.appId, value.userId, value.userSerial) : value;
        }
        public NativePrincipalPins.Phase phase(NativePrincipalManager.Handle handle) {
            return handle == overrideHandle && foreign != null ? foreign.phase(handle) : actual.phase(handle);
        }
    }
    static final class Case {
        final PackageManagerService pm = new PackageManagerService();
        final PackageSetting subject = pm.mSettings.add(SUBJECT, 10148);
        final NativePrincipalManager manager = new NativePrincipalManager(pm);
        final Inject calls = new Inject(manager);
        final NativePrincipalWriterFixture probe = new NativePrincipalWriterFixture(calls, INSTANCE, SIGNERS);
        String call(String op) { return probe.execute(op, INSTANCE, NONCE); }
    }
    private static Case committed() {
        Case value = new Case();
        NativePrincipalManager.Handle pin = value.manager.prepare(value.manager.select(SUBJECT, 0));
        assert value.manager.commit(pin);
        return value;
    }
    private static void missingPrepareResult(boolean fatal) {
        Case value = new Case(); value.call("select-new");
        if (fatal) { value.calls.prepareError = true; error(() -> value.call("prepare")); }
        else { value.calls.prepareException = true; has(value.call("prepare"), "\"state\":\"uncertain\""); }
        assert value.pm.mSettings.pins.reservedAppIds().contains(10148);
        has(value.call("status"), "\"prepare_acknowledged\":false");
        refusal("ORIGINAL_HANDLE_REQUIRED", () -> value.call("commit"));
        refusal("OTHER_REQUEST_RETAINED", () -> value.probe.execute("select-new", INSTANCE, "c".repeat(32)));
        has(value.call("prepare"), "\"prepare_acknowledged\":true");
        assert value.calls.prepareCount == 2;
        has(value.call("commit"), "\"last_commit_result\":\"true\"");
    }
    public static void main(String[] args) {
        if (!NativePrincipalWriterFixtureFaultTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        UserManagerInternal users = new UserManagerInternal(); LocalServices.addService(UserManagerInternal.class, users);
        missingPrepareResult(false); missingPrepareResult(true);
        Case selectionAbort = new Case(); selectionAbort.calls.selectError = true;
        error(() -> selectionAbort.call("select-new"));
        has(selectionAbort.call("status"), "aborted-selection");
        assert selectionAbort.pm.mSettings.pins.reservedAppIds().isEmpty();
        has(selectionAbort.call("select-new"), "\"attempt\":1"); // No silent new selection.

        Case commitAbort = new Case(); commitAbort.call("select-new"); commitAbort.call("prepare");
        commitAbort.calls.commitError = true; error(() -> commitAbort.call("commit"));
        has(commitAbort.call("status"), "\"last_commit_result\":\"exception\"");
        assert commitAbort.pm.mSettings.loaded.header.value.lastId == 1;
        refusal("COMMIT_ALREADY_ATTEMPTED", () -> commitAbort.call("prepare"));
        has(commitAbort.call("commit"), "\"last_commit_result\":\"true\"");
        assert commitAbort.pm.mSettings.loaded.header.value.lastId == 1;

        Case observation = new Case(); observation.call("select-new"); observation.call("prepare");
        observation.calls.observationAfterCommit = true;
        String reply = observation.call("commit");
        has(reply, "\"last_commit_result\":\"true\""); has(reply, "\"commit_ack_attempt\":3");
        has(reply, "\"observation_attempt\":2"); has(reply, "\"attempt\":3");
        has(reply, "\"observation_error_class\":\"java.lang.IllegalStateException\"");
        has(reply, "\"state\":\"durable-pin\"");

        // An intervening reservation cannot be silently adopted as this new operation.
        Case appeared = new Case(); appeared.call("select-new");
        appeared.manager.prepare(appeared.manager.select(SUBJECT, 0));
        has(appeared.call("prepare"), "\"intent_violated\":true");
        assert appeared.calls.prepareCount == 0;
        refusal("INTENT_VIOLATION_RETAINED", () -> appeared.call("commit"));

        Case swapped = new Case(); swapped.call("select-new"); swapped.call("prepare");
        NativePrincipalManager.Handle original = swapped.manager.find(SUBJECT, 0);
        Case stranger = new Case(); swapped.calls.foreign = stranger.manager;
        swapped.calls.overrideHandle = stranger.manager.prepare(stranger.manager.select(SUBJECT, 0));
        String swappedReply = swapped.call("prepare");
        has(swappedReply, "\"unexpected_handle_retained\":true");
        has(swappedReply, "\"intent_violated\":true");
        assert swapped.manager.find(SUBJECT, 0) == original;
        refusal("INTENT_VIOLATION_RETAINED", () -> swapped.call("commit"));

        for (String mismatch : new String[]{"version", "signer", "package"}) {
            Case wrong = new Case();
            if (mismatch.equals("version")) wrong.subject.version = 2;
            if (mismatch.equals("signer")) wrong.subject.signing = new android.content.pm.SigningDetails(
                    new android.content.pm.Signature(new byte[]{9}));
            if (mismatch.equals("package")) {
                wrong.pm.mSettings.add("dev.andrix.other", 10149);
                wrong.calls.overrideSelection = wrong.manager.select("dev.andrix.other", 0);
            }
            has(wrong.call("select-new"), "\"state\":\"selection-refused\"");
            assert wrong.pm.mSettings.pins.reservedAppIds().isEmpty();
        }
        Case none = new Case(); has(none.call("select-rebind"), "\"state\":\"selection-refused\"");
        Case active = committed(); has(active.call("select-rebind"), "\"state\":\"selection-refused\"");

        for (String fault : new String[]{"observation", "record", "handle", "serial", "post-commit-record"}) {
            Case prior = committed();
            PackageManagerService boot = new PackageManagerService(prior.pm.mSettings.root, false);
            boot.mSettings.add(SUBJECT, 10148); boot.mSettings.restoreAfterPackageSettings();
            NativePrincipalManager manager = new NativePrincipalManager(boot);
            Inject calls = new Inject(manager);
            NativePrincipalWriterFixture probe = new NativePrincipalWriterFixture(calls, INSTANCE, SIGNERS);
            if (fault.equals("serial")) users.info.serialNumber++;
            String selected = probe.execute("select-rebind", INSTANCE, NONCE);
            if (fault.equals("serial")) {
                has(selected, "\"state\":\"selection-refused\""); assert calls.prepareCount == 0;
                users.info.serialNumber--; continue;
            }
            has(selected, "\"state\":\"selected\"");
            calls.observationAfterPrepare = fault.equals("observation"); calls.mismatchRecord = fault.equals("record");
            if (fault.equals("handle")) {
                Case foreign = new Case(); calls.foreign = foreign.manager;
                calls.overrideHandle = foreign.manager.prepare(foreign.manager.select(SUBJECT, 0));
            }
            String prepared = probe.execute("prepare", INSTANCE, NONCE);
            has(prepared, "\"prepare_acknowledged\":true");
            if (fault.equals("post-commit-record")) {
                has(prepared, "\"rebind_verified\":true");
                calls.mismatchRecord = true;
                String committed = probe.execute("commit", INSTANCE, NONCE);
                has(committed, "\"last_commit_result\":\"true\"");
                has(committed, "\"first_commit_ack_attempt\":3");
                has(committed, "\"intent_violated\":true");
                has(committed, "\"state\":\"uncertain\"");
                refusal("INTENT_VIOLATION_RETAINED", () -> probe.execute("commit", INSTANCE, NONCE));
            } else if (fault.equals("observation")) {
                refusal("REBIND_NOT_VERIFIED", () -> probe.execute("commit", INSTANCE, NONCE));
                calls.observationAfterPrepare = false;
                has(probe.execute("prepare", INSTANCE, NONCE), "\"rebind_verified\":true");
                has(probe.execute("commit", INSTANCE, NONCE), "\"last_commit_result\":\"true\"");
            } else {
                has(prepared, "\"intent_violated\":true");
                if (fault.equals("handle")) {
                    has(prepared, "\"unexpected_handle_retained\":true"); has(prepared, "unexpected_principal_id");
                }
                refusal("INTENT_VIOLATION_RETAINED", () -> probe.execute("commit", INSTANCE, NONCE));
                assert calls.commitCount == 0;
            }
        }
        System.out.println("Writer wrapper fault controls passed; Android route unqualified");
    }
}
