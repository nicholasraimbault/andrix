package dev.andrix.proof.webviewqualification;

/** Own application UID, even if externally re-signed with the provider certificate. */
public final class SelfInstrumentation extends QualificationInstrumentation {
    @Override
    boolean providerTarget() {
        return false;
    }
}
