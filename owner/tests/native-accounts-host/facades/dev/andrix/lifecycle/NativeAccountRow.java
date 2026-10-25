// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package dev.andrix.lifecycle;
/** Hand translated AIDL field/constant shape, not generated parceling. */
public final class NativeAccountRow {
    public static final int BODY=1, RESERVATION=2, PENDING=1, ACTIVE=2, RETIRING_PIN=3,
            NOT_PINNED=4, LIFECYCLE_NOT_OBSERVED=0, ELIGIBLE=1, RETIRING=2, RETIRED=3,
            SUSPENSION_NOT_OBSERVED=0, SUSPENSION_NONE=1, SUSPENSION_PRESENT=2;
    public long principalId;
    public int appId, source, phase, lifecycle, suspension;
    public String packageName, lineage;
}
