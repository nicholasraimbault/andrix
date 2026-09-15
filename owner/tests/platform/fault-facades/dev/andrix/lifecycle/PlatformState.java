// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package dev.andrix.lifecycle;
public class PlatformState {
    public long instance, generation, keptWorkId, keepRegistration;
    public boolean available;
}
