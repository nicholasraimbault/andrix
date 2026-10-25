// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.os;
/** Host identity and liveness fact, not a Binder driver. */
public interface IBinder { boolean isBinderAlive(); }
