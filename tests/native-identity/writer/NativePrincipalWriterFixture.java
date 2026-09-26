// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.os.Binder;
import android.os.Build;
import android.os.Process;
import com.android.server.LocalServices;

import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.Set;
import org.json.JSONException;
import org.json.JSONObject;

/** Optional lab route. No initialization, grants, execution, deletion or release. */
public final class NativePrincipalWriterFixture {
    private static final String SUBJECT = "dev.andrix.proof.principalclosed";
    private static final String FIXTURE_SIGNER =
            "874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3";
    private static NativePrincipalWriterFixture service;

    /** Test seam for wrapper failures, not a substitute manager or UID allocator. */
    interface Calls {
        NativePrincipalManager.Selection select();
        NativePrincipalManager.Handle find();
        NativePrincipalManager.Handle prepare(NativePrincipalManager.Selection selection);
        boolean commit(NativePrincipalManager.Handle handle);
        NativePrincipalPins.Record identity(NativePrincipalManager.Handle handle);
        NativePrincipalPins.Phase phase(NativePrincipalManager.Handle handle);
    }
    static final class ManagerCalls implements Calls {
        private final NativePrincipalManager manager;
        ManagerCalls(NativePrincipalManager manager) { this.manager = manager; }
        public NativePrincipalManager.Selection select() { return manager.select(SUBJECT, 0); }
        public NativePrincipalManager.Handle find() { return manager.find(SUBJECT, 0); }
        public NativePrincipalManager.Handle prepare(NativePrincipalManager.Selection selection) {
            return manager.prepare(selection);
        }
        public boolean commit(NativePrincipalManager.Handle handle) { return manager.commit(handle); }
        public NativePrincipalPins.Record identity(NativePrincipalManager.Handle handle) { return manager.identity(handle); }
        public NativePrincipalPins.Phase phase(NativePrincipalManager.Handle handle) { return manager.phase(handle); }
    }
    static final class Refused extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        final String code;
        Refused(String code) { super(code); this.code = code; }
    }

    private final Calls calls;
    private final String instance;
    private final Set<String> allowedSigners;
    private String nonce;
    private boolean busy, attemptedPrepare, attemptedCommit, intentViolated, rebindVerified;
    private String selectionIntent = "", state = "empty", errorClass = "", observationErrorClass = "";
    private String lastOperation = "", lastCommitResult = "not-called";
    private long attempt, observationAttempt, prepareAckAttempt, commitAckAttempt;
    private long firstPrepareAckAttempt, firstCommitAckAttempt;
    private NativePrincipalManager.Selection selection;
    private NativePrincipalManager.Handle handle, expectedStoredHandle, unexpectedHandle;
    private NativePrincipalPins.Record record, expectedStoredRecord, unexpectedRecord;
    private NativePrincipalPins.Phase pinPhase;

    NativePrincipalWriterFixture(NativePrincipalManager manager, String instance, Set<String> signers) {
        this(new ManagerCalls(manager), instance, signers);
    }
    NativePrincipalWriterFixture(Calls calls, String instance, Set<String> signers) {
        if (calls == null || instance == null || !instance.matches("[0-9a-f]{32}")
                || signers == null || signers.size() != 1
                || !signers.iterator().next().matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("fixture service identity");
        }
        this.calls = calls; this.instance = instance; allowedSigners = Set.copyOf(signers);
    }

    private static synchronized NativePrincipalWriterFixture service() {
        if (service == null) {
            NativePrincipalManager manager = LocalServices.getService(NativePrincipalManager.class);
            if (manager == null) throw new Refused("SERVICE_UNAVAILABLE");
            byte[] bytes = new byte[16]; new SecureRandom().nextBytes(bytes);
            StringBuilder value = new StringBuilder(32);
            for (byte item : bytes) {
                value.append(Character.forDigit((item & 255) >>> 4, 16));
                value.append(Character.forDigit(item & 15, 16));
            }
            service = new NativePrincipalWriterFixture(manager, value.toString(), Set.of(FIXTURE_SIGNER));
        }
        return service;
    }

    public static int command(PrintWriter output, PrintWriter errors, String[] args) {
        // Caller authorization is separate from compile-time lab image selection.
        if (Binder.getCallingUid() != Process.ROOT_UID || !Build.IS_DEBUGGABLE) {
            errors.println("native writer fixture refused: CALLER_DENIED"); return 1;
        }
        NativePrincipalWriterFixture fixture = null;
        try {
            fixture = service();
            if (args.length == 1 && args[0].equals("info")) {
                output.println(fixture.snapshot("info")); return 0;
            }
            if (args.length != 3) throw new Refused("ARGUMENTS");
            output.println(fixture.execute(args[0], args[1], args[2])); return 0;
        } catch (Refused refusal) {
            output.println(refusal(fixture == null ? "" : fixture.instance, refusal.code)); return 1;
        } catch (RuntimeException | Error error) {
            // Even reply construction can fail after a writer effect. Do not
            // pass a stack trace to the shell or call this a no-effect refusal.
            errors.println("native writer fixture outcome unknown: REPLY_UNAVAILABLE"); return 1;
        }
    }

    private static String refusal(String instance, String code) {
        try {
            return new JSONObject().put("version", 1).put("instance", instance)
                    .put("result", "refused").put("code", code).toString();
        } catch (JSONException impossible) { throw new IllegalStateException("fixture JSON", impossible); }
    }

    String execute(String operation, String expectedInstance, String requestNonce) {
        if (!instance.equals(expectedInstance)) throw new Refused("STALE_INSTANCE");
        if (requestNonce == null || !requestNonce.matches("[0-9a-f]{32}")) throw new Refused("NONCE_FORMAT");
        if (!Set.of("select-new", "select-rebind", "prepare", "commit", "status").contains(operation)) {
            throw new Refused("OPERATION");
        }
        boolean selecting = operation.equals("select-new") || operation.equals("select-rebind");
        synchronized (this) {
            if (nonce == null) {
                if (!selecting) throw new Refused("SELECTION_REQUIRED");
                nonce = requestNonce; selectionIntent = operation;
            } else if (!nonce.equals(requestNonce)) throw new Refused("OTHER_REQUEST_RETAINED");
            else if (selecting && !selectionIntent.equals(operation)) throw new Refused("INTENT_CHANGED");
            if (operation.equals("status") || busy || (selecting && !state.equals("empty"))) {
                return snapshot(busy ? "in-flight" : "recorded");
            }
            if (intentViolated) throw new Refused("INTENT_VIOLATION_RETAINED");
            if (!selecting && selection == null) throw new Refused("SELECTION_UNAVAILABLE");
            if (operation.equals("prepare") && attemptedCommit) throw new Refused("COMMIT_ALREADY_ATTEMPTED");
            if (operation.equals("commit") && handle == null) throw new Refused("ORIGINAL_HANDLE_REQUIRED");
            if (operation.equals("commit") && selectionIntent.equals("select-rebind") && !rebindVerified) {
                throw new Refused("REBIND_NOT_VERIFIED");
            }
            if (attempt == Long.MAX_VALUE) throw new Refused("ATTEMPT_CAPACITY");
            attempt++; lastOperation = operation; busy = true;
            errorClass = ""; observationErrorClass = "";
            if (operation.equals("commit")) { attemptedCommit = true; lastCommitResult = "in-flight"; }
            state = selecting ? "selecting" : operation.equals("prepare") ? "preparing" : "committing";
        }
        String response;
        // No fixture/PMS state monitor or native Stop lane is held during manager calls.
        try {
            if (selecting) select(operation);
            else if (operation.equals("prepare")) prepare();
            else {
                boolean durable = calls.commit(handle);
                synchronized (this) {
                    lastCommitResult = durable ? "true" : "false";
                    if (durable) {
                        commitAckAttempt = attempt;
                        if (firstCommitAckAttempt == 0) firstCommitAckAttempt = attempt;
                    }
                    state = durable ? "durable-pin" : "uncertain";
                }
                observe(handle, false, false);
            }
        } catch (RuntimeException error) {
            synchronized (this) {
                state = attemptedPrepare ? "uncertain" : selecting ? "selection-refused" : "prepare-refused";
                errorClass = error.getClass().getName();
                if (operation.equals("commit") && lastCommitResult.equals("in-flight")) lastCommitResult = "exception";
            }
        } finally {
            synchronized (this) {
                // Also retain unknown effects when an Error propagates, rather
                // than leaving the pre-call snapshot as a no-effect claim.
                if (state.equals("preparing") || state.equals("committing")) {
                    state = "uncertain"; errorClass = "aborted-operation";
                    if (lastCommitResult.equals("in-flight")) lastCommitResult = "exception";
                } else if (state.equals("selecting")) {
                    state = "selection-refused"; errorClass = "aborted-selection";
                }
                busy = false;
                response = snapshot("recorded"); // Capture THIS attempt before admitting another.
            }
        }
        return response;
    }

    private void select(String operation) {
        NativePrincipalManager.Handle stored = calls.find();
        NativePrincipalPins.Record prior = stored == null ? null : calls.identity(stored);
        if ((operation.equals("select-new") && stored != null)
                || (operation.equals("select-rebind") && (stored == null
                || calls.phase(stored) != NativePrincipalPins.Phase.PENDING))) {
            throw new IllegalStateException("selection intent does not match recorded state");
        }
        NativePrincipalManager.Selection chosen = calls.select();
        if (!chosen.packageName.equals(SUBJECT) || chosen.userId != 0 || chosen.versionCode != 1
                || !chosen.currentSignerSha256.equals(allowedSigners)
                || (prior != null && (!prior.packageName.equals(chosen.packageName)
                || prior.appId != chosen.appId || prior.userId != chosen.userId || prior.userSerial != chosen.userSerial))) {
            throw new IllegalStateException("unexpected fixture subject");
        }
        synchronized (this) {
            selection = chosen; expectedStoredHandle = stored; expectedStoredRecord = prior; state = "selected";
        }
    }

    private void prepare() {
        if (!attemptedPrepare && selectionIntent.equals("select-new") && calls.find() != null) {
            synchronized (this) { intentViolated = true; }
            throw new IllegalStateException("binding appeared before first prepare");
        }
        synchronized (this) { attemptedPrepare = true; rebindVerified = false; }
        NativePrincipalManager.Handle prepared = calls.prepare(selection);
        if (prepared == null) throw new IllegalStateException("missing returned handle; outcome unknown");
        boolean mismatch;
        synchronized (this) {
            prepareAckAttempt = attempt;
            if (firstPrepareAckAttempt == 0) firstPrepareAckAttempt = attempt;
            mismatch = (handle != null && handle != prepared)
                    || (expectedStoredHandle != null && expectedStoredHandle != prepared);
            if (handle == null) handle = expectedStoredHandle == null ? prepared : expectedStoredHandle;
            if (mismatch) unexpectedHandle = prepared; // Never discard either returned object.
            state = mismatch ? "uncertain" : "prepared";
            intentViolated |= mismatch;
        }
        observe(prepared, true, mismatch && prepared != handle);
    }

    private static boolean sameRecord(NativePrincipalPins.Record a, NativePrincipalPins.Record b) {
        return a.id == b.id && a.packageName.equals(b.packageName) && a.appId == b.appId
                && a.userId == b.userId && a.userSerial == b.userSerial;
    }

    private void observe(NativePrincipalManager.Handle observed, boolean afterPrepare, boolean unexpected) {
        try {
            NativePrincipalPins.Record identity = calls.identity(observed);
            NativePrincipalPins.Phase phase = calls.phase(observed);
            synchronized (this) {
                if (unexpected) unexpectedRecord = identity;
                else { record = identity; pinPhase = phase; observationAttempt = attempt; }
                if (expectedStoredRecord != null && !sameRecord(identity, expectedStoredRecord)) {
                    state = "uncertain"; intentViolated = true; observationErrorClass = "rebind-record-mismatch";
                } else if (afterPrepare && expectedStoredHandle != null && !intentViolated) rebindVerified = true;
            }
        } catch (RuntimeException error) {
            // An observation failure cannot erase the separately captured acknowledgement.
            synchronized (this) { observationErrorClass = error.getClass().getName(); }
        }
    }

    synchronized String snapshot(String result) {
        try {
            JSONObject value = new JSONObject().put("version", 1).put("instance", instance)
                    .put("subject", SUBJECT).put("request", nonce == null ? "" : nonce)
                    .put("state", state).put("selection_intent", selectionIntent)
                    .put("intent_violated", intentViolated).put("rebind_verified", rebindVerified)
                    .put("busy", busy).put("result", result).put("attempt", attempt).put("operation", lastOperation)
                    .put("observation_attempt", observationAttempt).put("error_class", errorClass)
                    .put("observation_error_class", observationErrorClass)
                    .put("prepare_acknowledged", prepareAckAttempt != 0).put("prepare_ack_attempt", prepareAckAttempt)
                    .put("first_prepare_ack_attempt", firstPrepareAckAttempt)
                    .put("commit_acknowledged", commitAckAttempt != 0).put("commit_ack_attempt", commitAckAttempt)
                    .put("first_commit_ack_attempt", firstCommitAckAttempt)
                    .put("last_commit_result", lastCommitResult)
                    .put("unexpected_handle_retained", unexpectedHandle != null)
                    .put("execution_authorized", false).put("retirement_complete", false);
            if (selection != null) {
                value.put("app_id", selection.appId).put("user_id", selection.userId)
                        .put("user_serial", selection.userSerial).put("version_code", selection.versionCode)
                        .put("signer_sha256", selection.currentSignerSha256.iterator().next());
            }
            if (expectedStoredRecord != null) value.put("expected_principal_id", Long.toString(expectedStoredRecord.id));
            if (record != null) value.put("principal_id", Long.toString(record.id)).put("pin_phase", pinPhase.name());
            if (unexpectedRecord != null) value.put("unexpected_principal_id", Long.toString(unexpectedRecord.id));
            return value.toString();
        } catch (JSONException impossible) { throw new IllegalStateException("fixture metadata serialization", impossible); }
    }
}
