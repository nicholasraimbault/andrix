// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

/** Explicit experimental product opt-in; not a runtime/property switch. */
final class KeepBuild {
    static final boolean ENABLED = true;
    private KeepBuild() {}
}
