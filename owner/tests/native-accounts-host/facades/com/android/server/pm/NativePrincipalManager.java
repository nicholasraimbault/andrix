// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package com.android.server.pm;
import java.util.List;
/** Intentionally narrow read capture. Production PMS/store/locks are NOT compiled in this phase.
 * The endpoint's actual caller checks and actual marshal are compiled unchanged. */
public final class NativePrincipalManager {
    public static final class Row {
        public final long principalId;
        public final int appId;
        public final String packageName, lineage, source, phase, lifecycle, suspension;
        public Row(long id, int appId, String name, String lineage, String source, String phase,
                String lifecycle, String suspension) {
            principalId=id; this.appId=appId; packageName=name; this.lineage=lineage;
            this.source=source; this.phase=phase; this.lifecycle=lifecycle; this.suspension=suspension;
        }
    }
    public static final class Inspection {
        public enum Status { AVAILABLE, UNAVAILABLE, UNSUPPORTED }
        public enum Store { READY, MISSING, DAMAGED, CONFLICT, UNSUPPORTED, UNAVAILABLE }
        public final int userId;
        public final long userSerial;
        public final Status status;
        public final Store store;
        public final boolean complete;
        public final List<Row> rows;
        private Inspection(int user, long serial, Status status, Store store,
                boolean complete, List<Row> rows) {
            userId=user; userSerial=serial; this.status=status; this.store=store;
            this.complete=complete; this.rows=List.copyOf(rows);
        }
        public static Inspection available(int user, long serial, List<Row> rows) {
            return new Inspection(user, serial, Status.AVAILABLE, Store.READY, true, rows);
        }
        public static Inspection unavailable(int user, long serial) {
            return new Inspection(user, serial, Status.UNAVAILABLE, Store.UNAVAILABLE,
                    false, List.of());
        }
        public static Inspection unsupported(int user, long serial) {
            return new Inspection(user, serial, Status.UNSUPPORTED, Store.UNAVAILABLE,
                    false, List.of());
        }
    }
    public int calls, lastUser=-1;
    public long lastSerial=-1;
    public Inspection next;
    public boolean throwUnavailable;
    public Inspection inspectUser(int user, long serial) {
        calls++; lastUser=user; lastSerial=serial;
        if (throwUnavailable) throw new IllegalStateException("host unavailable fact");
        return next == null ? Inspection.unsupported(user,serial) : next;
    }
}
