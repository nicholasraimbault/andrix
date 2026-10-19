// SPDX-License-Identifier: Apache-2.0
// Host stub of android.app.ApplicationExitInfo: the getters the helper reads, from one script row.
package android.app;

import android.os.UserHandle;

public final class ApplicationExitInfo {
    private final String[] f;

    // timestamp, pid, real UID, package UID, defining UID, user, process, reason, subreason, status
    public ApplicationExitInfo(String[] fields) {
        f = fields;
    }

    private String field(int i, String getter) {
        if (f.length > 10 && f[10].equals(getter)) throw new IllegalStateException("getter fails");
        return f[i];
    }

    public long getTimestamp() {
        return Long.parseLong(field(0, "getTimestamp"));
    }

    public int getPid() {
        return Integer.parseInt(field(1, "getPid"));
    }

    public int getRealUid() {
        return Integer.parseInt(field(2, "getRealUid"));
    }

    public int getPackageUid() {
        return Integer.parseInt(field(3, "getPackageUid"));
    }

    public int getDefiningUid() {
        return Integer.parseInt(field(4, "getDefiningUid"));
    }

    public UserHandle getUserHandle() {
        return new UserHandle(Integer.parseInt(field(5, "getUserHandle")));
    }

    public String getProcessName() {
        String name = field(6, "getProcessName");
        return name.equals("\u0000null") ? null : name;
    }

    public int getReason() {
        return Integer.parseInt(field(7, "getReason"));
    }

    public int getSubReason() {
        return Integer.parseInt(field(8, "getSubReason"));
    }

    public int getStatus() {
        return Integer.parseInt(field(9, "getStatus"));
    }
}
