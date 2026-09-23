// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SigningRequestTest {
    private static final String CERT = "a".repeat(64);
    private static void need(boolean value) { if (!value) throw new AssertionError(); }
    private static SigningRequest request() {
        return new SigningRequest("instance.1", 2000, 0, "sign-probe", CERT, new byte[]{1, 0, 2});
    }
    private static void invalid(Runnable operation) {
        try { operation.run(); throw new AssertionError("expected refusal"); }
        catch (IllegalArgumentException expected) { }
    }
    private static void await(CountDownLatch latch) {
        try { latch.await(); } catch (InterruptedException e) { throw new AssertionError(e); }
    }
    public static void main(String[] args) throws Exception {
        byte[] bytes = {1, 0, 2};
        SigningRequest copy = new SigningRequest("instance.1", 2000, 0, "sign-probe", CERT, bytes);
        bytes[0] = 9;
        need(Arrays.equals(copy.payload(), new byte[]{1, 0, 2}));
        byte[] read = copy.payload(); read[1] = 9;
        need(Arrays.equals(copy.payload(), new byte[]{1, 0, 2}));
        need(copy.payloadSha256().equals("16305a6b2292e931665a34089864ee3fcc24171c81551f152cf4d1db0dd6122d"));
        need(copy.id().equals("instance.1") && copy.requesterUid() == 2000 && copy.androidUser() == 0);
        need(copy.purpose().equals("sign-probe") && copy.certificateSha256().equals(CERT));
        need(!copy.claimSigning() && !copy.complete(null));
        need(copy.beginAuthentication() && !copy.beginAuthentication());
        need(copy.claimSigning() && !copy.claimSigning());
        invalid(() -> copy.complete(new byte[0]));
        need(copy.state() == SigningRequest.State.SIGNING);
        byte[] signature = {3, 4}; need(copy.complete(signature)); signature[0] = 5;
        need(Arrays.equals(copy.signature(), new byte[]{3, 4}));
        read = copy.signature(); read[1] = 5;
        need(Arrays.equals(copy.signature(), new byte[]{3, 4}));
        need(!copy.cancel() && !copy.fail() && !copy.complete(null));
        need(!copy.cancellationRequested() && copy.state() == SigningRequest.State.COMPLETE);

        for (int stage = 0; stage < 3; stage++) {
            SigningRequest r = request();
            if (stage >= 1) need(r.beginAuthentication());
            if (stage >= 2) need(r.claimSigning());
            need(r.cancel() && !r.cancel() && r.cancellationRequested() && r.signature() == null);
            if (stage == 2) {
                need(r.state() == SigningRequest.State.SIGNING);
                need(r.complete(new byte[]{1}));
            }
            need(r.state() == SigningRequest.State.CANCELLED);
            need(!r.beginAuthentication() && !r.claimSigning() && !r.complete(null) && !r.fail());
        }
        SigningRequest failed = request(); need(failed.fail());
        need(failed.state() == SigningRequest.State.FAILED && !failed.fail() && !failed.cancel());
        SigningRequest cancelledFailure = request();
        need(cancelledFailure.beginAuthentication() && cancelledFailure.claimSigning()
                && cancelledFailure.cancel() && cancelledFailure.fail());
        need(cancelledFailure.state() == SigningRequest.State.CANCELLED);

        invalid(() -> new SigningRequest(null, 2000, 0, "p", CERT, bytes));
        invalid(() -> new SigningRequest(" ", 2000, 0, "p", CERT, bytes));
        invalid(() -> new SigningRequest("x".repeat(129), 2000, 0, "p", CERT, bytes));
        invalid(() -> new SigningRequest("id", -1, 0, "p", CERT, bytes));
        invalid(() -> new SigningRequest("id", 2000, -1, "p", CERT, bytes));
        invalid(() -> new SigningRequest("id", 2000, 0, "", CERT, bytes));
        invalid(() -> new SigningRequest("id", 2000, 0, "p".repeat(1025), CERT, bytes));
        invalid(() -> new SigningRequest("id", 2000, 0, "p", "A".repeat(64), bytes));
        invalid(() -> new SigningRequest("id", 2000, 0, "p", "0".repeat(63), bytes));
        invalid(() -> new SigningRequest("id", 2000, 0, "p", CERT, null));
        invalid(() -> new SigningRequest("id", 2000, 0, "p", CERT, new byte[0]));
        invalid(() -> new SigningRequest("id", 2000, 0, "p", CERT, new byte[65537]));
        SigningRequest bound = request(); need(bound.beginAuthentication() && bound.claimSigning());
        invalid(() -> bound.complete(new byte[16385]));
        need(bound.state() == SigningRequest.State.SIGNING && bound.fail());

        for (int round = 0; round < 200; round++) {
            SigningRequest r = request(); need(r.beginAuthentication());
            CountDownLatch start = new CountDownLatch(1); AtomicBoolean claimed = new AtomicBoolean();
            Thread claim = new Thread(() -> { await(start); claimed.set(r.claimSigning()); });
            Thread cancel = new Thread(() -> { await(start); r.cancel(); });
            claim.start(); cancel.start(); start.countDown(); claim.join(); cancel.join();
            if (claimed.get()) {
                need(r.state() == SigningRequest.State.SIGNING && r.cancellationRequested());
                need(r.complete(new byte[]{1}));
            }
            need(r.state() == SigningRequest.State.CANCELLED && r.signature() == null);
        }
        for (int round = 0; round < 200; round++) {
            SigningRequest r = request(); need(r.beginAuthentication() && r.claimSigning());
            CountDownLatch start = new CountDownLatch(1); AtomicBoolean consumed = new AtomicBoolean();
            Thread finish = new Thread(() -> { await(start); consumed.set(r.complete(new byte[]{1})); });
            Thread cancel = new Thread(() -> { await(start); r.cancel(); });
            finish.start(); cancel.start(); start.countDown(); finish.join(); cancel.join();
            need(consumed.get());
            need(r.state() == SigningRequest.State.COMPLETE || r.state() == SigningRequest.State.CANCELLED);
            need((r.signature() != null) == (r.state() == SigningRequest.State.COMPLETE));
        }
        SigningRequest next = new SigningRequest("instance.2", 2000, 0, "sign-probe", CERT, bytes);
        need(!copy.complete(new byte[]{1}) && !copy.claimSigning());
        need(next.state() == SigningRequest.State.PENDING);
        need(SigningRequest.mayReplacePresentation(null, next));
        need(SigningRequest.mayReplacePresentation(next, next));
        need(!SigningRequest.mayReplacePresentation(next, null));
        need(!SigningRequest.mayReplacePresentation(next, copy)); // pending
        need(next.beginAuthentication());
        need(!SigningRequest.mayReplacePresentation(next, copy));
        need(next.claimSigning());
        need(!SigningRequest.mayReplacePresentation(next, copy));
        need(next.cancel());
        need(!SigningRequest.mayReplacePresentation(next, copy)); // cancellation is not retirement
        need(next.complete(new byte[]{1}));
        need(SigningRequest.mayReplacePresentation(next, copy)); // now terminal
        need(SigningRequest.mayReplacePresentation(copy, next)); // published signature retained
        need(copy.state() == SigningRequest.State.COMPLETE && next.state() == SigningRequest.State.CANCELLED);
        System.out.println("SIGNING_REQUEST_MODEL_PASS races=400 presentation_not_authorization no_Android_authentication_claim");
    }
}
