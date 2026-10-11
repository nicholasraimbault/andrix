// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.State;
import java.util.Arrays;
import java.util.List;

/**
 * The deployment records' numeric codes, by name, as owner/deployment/README.md documents them. The
 * record enums keep their codes package private, so the bridge names them here. A test binds this
 * table to the canonical ticket encoding.
 */
final class RecordCodes {
    private RecordCodes() {}

    private static final List<String> STATES = Arrays.asList("PLANNED", "AUTHORIZED", "SIGNING", "SIGNED",
            "PUBLISHED", "SESSION_INTENT", "SESSION_BOUND", "WRITTEN", "COMMIT_INTENT", "READY", "READY_AGAIN",
            "REBOOT_INTENT", "ABANDON_INTENT", "BOOT_OBSERVED", "APPLIED_PROVISIONAL", "APPLIED", "HEALTH_WINDOW",
            "SIGN_FAILED", "NO_SESSION", "ABANDONED", "FAILED_NATIVE", "NATIVE_RECORD_LOST", "CLOSED_APPLIED",
            "CLOSED_FAILED", "CANCELLED", "VOID", "DIVERGED", "SUPERSEDED");
    private static final List<String> CROSSINGS = Arrays.asList("SIGN", "PUBLISH", "CREATE", "WRITE", "COMMIT",
            "ABANDON", "REBOOT", "NOTICE", "HANDOVER");
    private static final List<String> CAUSES = Arrays.asList("NONE", "CANCELLED", "VOID_SELECTION", "VOID_TRUST",
            "VOID_TARGET", "VOID_BASE", "OTHER_BYTES");

    static int state(State state) { return code(STATES, state.name(), 1); }

    static int crossing(Crossing crossing) { return code(CROSSINGS, crossing.name(), 1); }

    static int cause(Cause cause) { return code(CAUSES, cause.name(), 0); }

    static int actor(ActorClass actor) {
        return actor == ActorClass.GRANT_HOLDER ? LabProtocol.ACTOR_GRANT_HOLDER : LabProtocol.ACTOR_LAB_OPERATOR;
    }

    private static int code(List<String> names, String name, int first) {
        int at = names.indexOf(name);
        if (at < 0) throw new IllegalStateException("a code of no known name: " + name);
        return first + at;
    }
}
