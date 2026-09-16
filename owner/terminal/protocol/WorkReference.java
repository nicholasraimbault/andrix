// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal.protocol;

import dev.andrix.session.WorkInfo;

/** Immutable metadata bound to an exact service object and work identity, not an I/O capability. */
public final class WorkReference<T> {
    public final T service;
    public final Object serviceIdentity;
    public final long id;
    public final int state, lifetimePolicy, terminalRecovery;

    public WorkReference(T service, Object serviceIdentity, WorkInfo info) {
        if (service == null || serviceIdentity == null || info == null || info.workId <= 0
                || info.state < WorkInfo.IDLE || info.state > WorkInfo.STOPPING
                || (info.lifetimePolicy != WorkInfo.CONSOLE_BOUND && info.lifetimePolicy != WorkInfo.EXPLICIT_KEEP)
                || (info.terminalRecovery != WorkInfo.CONTINUOUS_TERMINAL
                    && info.terminalRecovery != WorkInfo.RECREATE_TERMINAL)) {
            throw new IllegalArgumentException("Invalid native work description");
        }
        this.service = service;
        this.serviceIdentity = serviceIdentity;
        id = info.workId; state = info.state; lifetimePolicy = info.lifetimePolicy;
        terminalRecovery = info.terminalRecovery;
    }

    public boolean hasWork() { return state != WorkInfo.IDLE; }
    public boolean canRequestStop() { return state == WorkInfo.PREPARING || state == WorkInfo.RUNNING; }
    public boolean retained() { return lifetimePolicy == WorkInfo.EXPLICIT_KEEP; }
    public boolean recreatesTerminal() { return terminalRecovery == WorkInfo.RECREATE_TERMINAL; }
    public boolean sameTarget(WorkReference<?> other) {
        return other != null && serviceIdentity == other.serviceIdentity && id == other.id;
    }
    public WorkReference<T> stopping() {
        WorkInfo info = new WorkInfo();
        info.workId = id; info.state = WorkInfo.STOPPING;
        info.lifetimePolicy = lifetimePolicy; info.terminalRecovery = terminalRecovery;
        return new WorkReference<>(service, serviceIdentity, info);
    }
}
