// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

/**
 * What the receipt provider admits, in plain Java. The manifest guards the provider with DUMP;
 * every entry point first checks that the Binder caller is the shell user, before it reads any
 * argument and without clearing the calling identity. The one admitted operation is a whole read
 * of the listing: exactly the rows URI, no projection or exactly the listing's one column, and no
 * selection, sort or other query argument. Everything else is refused.
 */
public final class ProviderPolicy {
    public static final String AUTHORITY = "dev.andrix.lab.notice.receipts";
    public static final String ROWS = "content://" + AUTHORITY + "/rows";
    public static final String COLUMN = "line";

    private ProviderPolicy() {}

    /** Why a Binder caller is refused, or null for the shell user. */
    public static String caller(int callingUid) {
        return callingUid == Delivery.SHELL_UID ? null : "caller " + callingUid + " is not the shell user";
    }

    /** Why a query is refused, or null for the one whole read of the listing. */
    public static String query(String uri, String[] projection, boolean noArguments) {
        if (!ROWS.equals(uri)) return "only the rows URI is read";
        if (projection != null && (projection.length != 1 || !COLUMN.equals(projection[0]))) {
            return "the listing has one column";
        }
        if (!noArguments) return "no selection, sort or other query argument";
        return null;
    }

    /** The refusal of every other operation. */
    public static String refused(String operation) {
        return "the receipt provider is a whole read only: " + operation + " is refused";
    }
}
