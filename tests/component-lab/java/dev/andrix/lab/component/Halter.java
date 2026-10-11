// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

/**
 * How a coordinator generation ends itself when the broker orders a halt. The broker records the
 * consumed fault cell before it gives the order, and records the generation's exit 99 as a
 * deliberate halt only when it gave that order.
 */
public interface Halter {
    /** The exit status of an ordered halt. */
    int STATUS = 99;

    /** Ends the generation at once. It never returns normally. */
    void halt(int status);

    /** The production halter: the JVM ends at once, without running shutdown hooks. */
    static Halter runtime() {
        return status -> Runtime.getRuntime().halt(status);
    }
}
