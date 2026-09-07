package dev.andrix.proof.webviewqualification;

/** Explicit same-signer instrumentation of the real provider UID, not ordinary authority. */
public final class ProviderInstrumentation extends QualificationInstrumentation {
    @Override
    boolean providerTarget() {
        return true;
    }
}
