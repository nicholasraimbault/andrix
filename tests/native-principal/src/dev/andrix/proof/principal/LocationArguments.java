// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

/**
 * Finite location fixture arguments: action, public nonce and optional duration.
 *
 * <p>This class parses arguments only. It does not request, check or grant any
 * Android permission. The provider is the fixed {@link #PROVIDER}, so a caller
 * cannot select GPS or another provider. Names and the nonce are diagnostics,
 * never authorization.
 */
public final class LocationArguments {
    /** The only provider name the fixture uses. Arguments cannot select another. */
    public static final String PROVIDER = "andrix_principal_test";

    private static final int DEFAULT_WATCH_MILLIS = 180000;
    private static final int MIN_WATCH_MILLIS = 1000;
    private static final int MAX_WATCH_MILLIS = 300000;

    /** Either {@code info} or {@code watch}. */
    public final String action;
    /** Public correlation value for diagnostics. It is not a secret or authorization. */
    public final String nonce;
    /** Zero for {@code info}. From 1000 to 300000 inclusive for {@code watch}. */
    public final int durationMillis;

    private LocationArguments(String action, String nonce, int durationMillis) {
        this.action = action;
        this.nonce = nonce;
        this.durationMillis = durationMillis;
    }

    /**
     * Parses {@code action nonce [durationMillis]}.
     *
     * <p>The action is {@code info} or {@code watch}. The nonce is 1 to 64 ASCII
     * letters, digits or underscores. The duration is 1 to 6 ASCII decimal digits.
     * It defaults to 0 for {@code info} and 180000 for {@code watch}. An explicit
     * {@code info} duration must be 0. A {@code watch} duration must be from 1000
     * to 300000 inclusive.
     *
     * @throws IllegalArgumentException if the input is null, malformed, too short,
     *     too long or outside the bounds. The message never repeats the input.
     */
    public static LocationArguments parse(String[] args) {
        if (args == null || args.length < 2 || args.length > 3) {
            throw new IllegalArgumentException(
                    "expected action, public nonce, optional duration milliseconds");
        }
        // Read each element once, so the value checked is the value stored.
        String requested = args[0];
        String nonce = args[1];
        boolean watch;
        if ("info".equals(requested)) {
            watch = false;
        } else if ("watch".equals(requested)) {
            watch = true;
        } else {
            throw new IllegalArgumentException("unknown location action");
        }
        if (nonce == null || !nonce.matches("[A-Za-z0-9_]{1,64}")) {
            throw new IllegalArgumentException("invalid public nonce");
        }
        int millis = watch ? DEFAULT_WATCH_MILLIS : 0;
        if (args.length == 3) {
            String duration = args[2];
            if (duration == null || !duration.matches("[0-9]{1,6}")) {
                throw new IllegalArgumentException("invalid duration milliseconds");
            }
            // Six ASCII digits at most, so the decimal value always fits in an int.
            millis = Integer.parseInt(duration, 10);
        }
        if (watch) {
            if (millis < MIN_WATCH_MILLIS || millis > MAX_WATCH_MILLIS) {
                throw new IllegalArgumentException(
                        "watch duration outside 1000..300000 milliseconds");
            }
        } else if (millis != 0) {
            throw new IllegalArgumentException("info duration must be 0 milliseconds");
        }
        return new LocationArguments(watch ? "watch" : "info", nonce, millis);
    }
}
