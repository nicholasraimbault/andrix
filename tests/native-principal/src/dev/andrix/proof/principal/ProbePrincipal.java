// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

/** Local consistency checks for observations obtained from the real process and Package Manager.
 * This does not grant authority. Binder services must still validate the actual caller.
 */
public final class ProbePrincipal {
    private ProbePrincipal() {}

    public static String fixtureForUid(String[] packages) {
        if (packages == null || packages.length != 1) {
            throw new SecurityException("fixture requires one package for the actual UID");
        }
        String name = packages[0];
        if (!ProbeArguments.PRINCIPAL.equals(name) && !ProbeArguments.PEER.equals(name)
                && !ProbeArguments.CLOSED.equals(name)) {
            throw new SecurityException("actual UID does not identify a fixture package");
        }
        return name;
    }

    public static void requireOwnApplication(int uid, int applicationUid) {
        if (uid < 0 || uid % 100000 < 10000 || uid % 100000 > 19999 || uid != applicationUid) {
            throw new SecurityException("application metadata does not match the actual ordinary UID");
        }
    }

    public static void requireOwnContext(int uid, String principal, int applicationUid,
            String contextPackage, int attributionUid, String attributionPackage) {
        requireOwnApplication(uid, applicationUid);
        if (principal == null || !principal.equals(contextPackage) || attributionUid != uid
                || !principal.equals(attributionPackage)) {
            throw new SecurityException("context and operation attribution do not match the principal");
        }
    }
}
