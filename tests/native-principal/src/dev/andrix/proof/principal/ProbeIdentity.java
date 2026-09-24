// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Parses the probe's own kernel observations. It grants no caller authority. */
public final class ProbeIdentity {
    private static final String[] FIELDS = {"Uid", "Gid", "Groups", "CapInh", "CapPrm",
            "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"};
    private final Map<String, String> fields;
    public final String securityContext;

    private ProbeIdentity(Map<String, String> fields, String securityContext) {
        this.fields = Collections.unmodifiableMap(fields);
        this.securityContext = securityContext;
    }

    public static ProbeIdentity parse(String status, String context) {
        if (status == null || status.length() > 32768 || context == null || context.length() > 256) {
            throw new IllegalArgumentException("invalid kernel observation");
        }
        Map<String, String> found = new LinkedHashMap<>();
        for (String line : status.split("\n")) {
            int colon = line.indexOf(':');
            if (colon < 0) continue;
            String key = line.substring(0, colon);
            for (String wanted : FIELDS) {
                if (!wanted.equals(key)) continue;
                if (found.put(key, line.substring(colon + 1).trim()) != null) {
                    throw new IllegalArgumentException("duplicate kernel identity field");
                }
            }
        }
        for (String key : FIELDS) {
            if (!found.containsKey(key)) throw new IllegalArgumentException("missing kernel identity field");
        }
        String label = context.trim();
        if (!label.matches("[a-zA-Z0-9_:,]+")) {
            throw new IllegalArgumentException("invalid security context");
        }
        return new ProbeIdentity(found, label);
    }

    public Map<String, String> fields() { return fields; }

    public void requireOrdinaryRunAs(int observedUid) {
        // Full secondary-user UIDs can be large even when the appId is privileged.
        int appId = observedUid % 100000;
        if (observedUid < 0 || appId < 10000 || appId > 19999) {
            throw new SecurityException("probe requires an ordinary application UID");
        }
        requireIds(fields.get("Uid"), observedUid);
        requireIds(fields.get("Gid"), observedUid);
        for (String key : new String[] {"CapInh", "CapPrm", "CapEff", "CapAmb"}) {
            if (!fields.get(key).matches("0{1,16}")) {
                throw new SecurityException("probe refuses process capabilities");
            }
        }
        if (!securityContext.equals("u:r:runas_app:s0")
                && !securityContext.matches("u:r:runas_app:s0:c[0-9]+(?:,c[0-9]+)*")) {
            throw new SecurityException("probe requires the observed runas_app domain");
        }
        if (!fields.get("Groups").matches("(?:[0-9]+(?:[ \t]+[0-9]+)*)?")) {
            throw new IllegalArgumentException("invalid supplementary groups");
        }
        if (!fields.get("CapBnd").matches("[0-9a-fA-F]{1,16}")
                || !fields.get("NoNewPrivs").matches("[01]")
                || !fields.get("Seccomp").matches("[012]")) {
            throw new IllegalArgumentException("invalid kernel policy fields");
        }
    }

    private static void requireIds(String value, int expected) {
        String[] ids = value.split("[ \t]+");
        if (ids.length != 4) throw new IllegalArgumentException("invalid credential tuple");
        for (String id : ids) {
            if (!id.matches("[0-9]{1,10}") || Long.parseLong(id) != expected) {
                throw new SecurityException("credential tuple does not match process UID");
            }
        }
    }
}
