// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

/**
 * The activity's decisions, in plain Java: whether to present at all, and when its own callbacks
 * give the one candidate row.
 *
 * <p>A presentation needs the shell user as the activity's observed launching UID, which Android
 * reveals only when the launcher shared its identity, and the expected user and serial to be the
 * app's own. Its key must hold nothing yet or the same request: a conflicting, corrupt or
 * unreadable key refuses it before anything is shown or written. The candidate is the first frame
 * commit the app sees while its window has focus, after it resumed. It is recorded once per
 * activity. No focus or no committed frame gives no row.
 */
public final class Delivery {
    public static final int SHELL_UID = 2000;

    private final NoticeRequest request;
    private final int uid;
    private final long serial;
    private final int pid;
    private final long processStart;
    private long resumed = -1;
    private long focus = -1;
    private boolean recorded;

    /** Why the identity refuses a presentation, as one of NoticeRequest.REFUSALS, or null. */
    public static String refusal(int launchedFromUid, int uid, long serial, NoticeRequest request) {
        if (launchedFromUid != SHELL_UID) return "launcher";
        if (!Forms.applicationUid(uid)) return "uid";
        if (uid / Forms.PER_USER_RANGE != request.user) return "user";
        if (serial < 0 || serial != request.serial) return "serial";
        return null;
    }

    /**
     * The activity's one decision before anything is shown: NoticeRequest.PRESENTED, or
     * NoticeRequest.REFUSED and a reason. The identity comes first, then what the request's key
     * already holds. Only nothing or the same request may be shown.
     */
    public static String decide(int launchedFromUid, int uid, long serial, NoticeRequest request,
            ReceiptStore store) {
        String why = refusal(launchedFromUid, uid, serial, request);
        if (why == null) {
            ReceiptStore.Existing existing = store.existing(request, uid, serial);
            if (existing == ReceiptStore.Existing.CONFLICT) {
                why = "conflict";
            } else if (existing == ReceiptStore.Existing.CORRUPT) {
                why = "corrupt";
            } else if (existing == ReceiptStore.Existing.UNREADABLE) {
                why = "store";
            }
        }
        return why == null ? NoticeRequest.PRESENTED : NoticeRequest.REFUSED + why;
    }

    public Delivery(NoticeRequest request, int uid, long serial, int pid, long processStart) {
        this.request = request;
        this.uid = uid;
        this.serial = serial;
        this.pid = pid;
        this.processStart = processStart;
    }

    /** The activity resumed. Only the first resume counts. */
    public void resumed(long now) {
        if (resumed < 0) resumed = now;
    }

    /** The window gained focus. True when the activity should ask for a frame commit callback:
     * after a resume, until the row is recorded. */
    public boolean focused(long now) {
        if (resumed < 0 || recorded) return false;
        if (focus < 0) focus = now;
        return true;
    }

    /** A frame was committed. The candidate row once, while the window has focus; else null. */
    public ReceiptRow committed(long now, boolean hasFocus) {
        if (recorded || resumed < 0 || focus < 0 || !hasFocus) return null;
        recorded = true;
        return ReceiptRow.of(request, uid, serial, pid, processStart, resumed, focus, now);
    }
}
