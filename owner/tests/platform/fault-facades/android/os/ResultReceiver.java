// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package android.os;
public class ResultReceiver {
    public int result = Integer.MIN_VALUE, sends;
    public void send(int value, Object ignored) { result = value; ++sends; }
}
