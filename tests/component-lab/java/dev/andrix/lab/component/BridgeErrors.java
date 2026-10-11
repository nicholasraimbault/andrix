// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

/** The ways a bridge operation ends without a result. */
public final class BridgeErrors {
    private BridgeErrors() {}

    /** The broker answered STOPPED: a fence tripped, and the generation sends no further request. */
    public static final class GenerationStopped extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public GenerationStopped(String reason) { super(reason); }
    }

    /**
     * The bridge refused to act, or the broker refused a request. Either is a defect or damage that no
     * reply can repair, so the generation ends as failed.
     */
    public static final class BridgeRefusal extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public BridgeRefusal(String reason) { super(reason); }

        public BridgeRefusal(String reason, Throwable cause) { super(reason, cause); }
    }
}
