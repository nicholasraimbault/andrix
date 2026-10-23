// SPDX-License-Identifier: GPL-3.0-or-later
package dev.andrix.server;

/** Explicit experimental product opt-in; not a runtime/property switch. */
final class KeepBuild {
    static final boolean ENABLED = true;
    private KeepBuild() {}
}
