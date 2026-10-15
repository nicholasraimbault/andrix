// SPDX-License-Identifier: Apache-2.0
package android.system;

/** Host model stub of StructStat: the mode and size the model reads. */
public final class StructStat {
    public final int st_mode;
    public final long st_size;

    StructStat(int mode, long size) {
        st_mode = mode;
        st_size = size;
    }
}
