// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

/** Host parser/guard checks, not Android identity or permission qualification. */
public final class ProbeModelTest {
    private static int checks;
    private static void need(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }
    private static void refused(Runnable operation) {
        checks++;
        try { operation.run(); }
        catch (IllegalArgumentException | SecurityException expected) { return; }
        throw new AssertionError("expected refusal " + checks);
    }
    private static String status(int uid) {
        return "Name:\tfixture\nUid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid
                + "\nGid:\t" + uid + " " + uid + " " + uid + " " + uid
                + "\nGroups:\t3003 50001\nCapInh:\t0000000000000000"
                + "\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000"
                + "\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000"
                + "\nNoNewPrivs:\t0\nSeccomp:\t2\n";
    }
    private static ProbeIdentity identity(int uid) {
        return ProbeIdentity.parse(status(uid), "u:r:runas_app:s0:c1,c257,c512,c768\n");
    }
    public static void main(String[] ignored) {
        for (String action : new String[] {"info", "post", "cancel", "observe"}) {
            ProbeArguments args = ProbeArguments.parse(new String[] {
                    action, ProbeArguments.PRINCIPAL, "request_01"});
            need(args.action.equals(action) && args.observeMillis == 1500);
        }
        for (String pkg : new String[] {ProbeArguments.PRINCIPAL,
                ProbeArguments.PEER, ProbeArguments.CLOSED}) {
            need(ProbeArguments.parse(new String[] {"info", pkg, "n", "0"}).targetPackage.equals(pkg));
        }
        need(ProbeArguments.parse(new String[] {"observe", ProbeArguments.PRINCIPAL,
                "n".repeat(64), "30000"}).observeMillis == 30000);
        refused(() -> ProbeArguments.parse(null));
        refused(() -> ProbeArguments.parse(new String[] {"info"}));
        refused(() -> ProbeArguments.parse(new String[] {"grant", ProbeArguments.PRINCIPAL, "n"}));
        refused(() -> ProbeArguments.parse(new String[] {"post", "android", "n"}));
        refused(() -> ProbeArguments.parse(new String[] {"post", ProbeArguments.PRINCIPAL, "n;id"}));
        refused(() -> ProbeArguments.parse(new String[] {"post", ProbeArguments.PRINCIPAL, ""}));
        refused(() -> ProbeArguments.parse(new String[] {"post", ProbeArguments.PRINCIPAL, "n".repeat(65)}));
        for (String bad : new String[] {"-1", "30001", "100000", "NaN", " 1", "1\n"}) {
            refused(() -> ProbeArguments.parse(new String[] {"observe", ProbeArguments.PRINCIPAL, "n", bad}));
        }
        for (int uid : new int[] {10000, 19999, 1010000, 1012345}) {
            identity(uid).requireOrdinaryRunAs(uid);
            need(identity(uid).fields().get("Uid").startsWith(Integer.toString(uid)));
        }
        for (int uid : new int[] {-1, 0, 1000, 1001, 2000, 7500, 20000, 1001000, 1007500}) {
            refused(() -> identity(uid).requireOrdinaryRunAs(uid));
        }
        refused(() -> identity(10001).requireOrdinaryRunAs(10002));
        refused(() -> ProbeIdentity.parse(status(10001).replace("Uid:\t10001", "Uid:\t0"),
                "u:r:runas_app:s0").requireOrdinaryRunAs(10001));
        refused(() -> ProbeIdentity.parse(status(10001).replace("Gid:\t10001", "Gid:\t0"),
                "u:r:runas_app:s0").requireOrdinaryRunAs(10001));
        for (String field : new String[] {"CapInh", "CapPrm", "CapEff", "CapAmb"}) {
            refused(() -> ProbeIdentity.parse(status(10001).replace(field + ":\t0000000000000000",
                    field + ":\t0000000000000001"), "u:r:runas_app:s0")
                    .requireOrdinaryRunAs(10001));
        }
        for (String label : new String[] {"u:r:shell:s0", "u:r:system_server:s0", "u:r:runas_app:s0:c1-other", ""}) {
            refused(() -> ProbeIdentity.parse(status(10001), label).requireOrdinaryRunAs(10001));
        }
        refused(() -> ProbeIdentity.parse(status(10001) + "Uid:\t10001\n", "u:r:runas_app:s0"));
        refused(() -> ProbeIdentity.parse(status(10001).replace("Seccomp:\t2\n", ""), "u:r:runas_app:s0"));
        refused(() -> ProbeIdentity.parse(status(10001).replace("Seccomp:\t2", "Seccomp:\t3"),
                "u:r:runas_app:s0").requireOrdinaryRunAs(10001));
        refused(() -> ProbeIdentity.parse(status(10001).replace("Groups:\t3003 50001", "Groups:\tunknown"),
                "u:r:runas_app:s0").requireOrdinaryRunAs(10001));
        try {
            identity(10001).fields().put("Uid", "0 0 0 0");
            throw new AssertionError("mutable observation map");
        } catch (UnsupportedOperationException expected) { checks++; }
        System.out.println("PRINCIPAL_MODEL_PASS checks=" + checks
                + " no_Android_runtime_or_permission_claim");
    }
}
