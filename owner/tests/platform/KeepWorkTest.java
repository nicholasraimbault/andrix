// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import dev.andrix.server.KeepWorkState.Record;
import java.util.ArrayDeque;
import java.util.ArrayList;

public final class KeepWorkTest {
    static final class Fixture {
        final OwnerLifecycleState platform = new OwnerLifecycleState();
        final Backend backend = new Backend(this);
        final KeepWork keep;
        Fixture(boolean enabled) {
            platform.ce(1, 1, true); platform.user(true);
            keep = new KeepWork(enabled, 71, platform, backend);
        }
        void outside() { assert !Thread.holdsLock(platform) : "external operation under lifecycle monitor"; }
        long grant(Lifetime life, long work) {
            return keep.keep(life, work, 71, platform.snapshot().generation);
        }
    }
    static final class Backend implements KeepWork.Backend {
        final Fixture f;
        final ArrayDeque<Runnable> commands = new ArrayDeque<>();
        final ArrayList<String> cancelled = new ArrayList<>();
        Record<KeepWork.Lifetime> last;
        boolean postOk = true, failExecute;
        int posts, errors;
        Runnable onPost = () -> { };
        Backend(Fixture fixture) { f = fixture; }
        @Override public boolean post(Record<KeepWork.Lifetime> record) {
            f.outside(); ++posts; last = record; onPost.run(); return postOk;
        }
        @Override public void cancel(Record<KeepWork.Lifetime> record) {
            f.outside(); cancelled.add(record.token);
        }
        @Override public void execute(Runnable command) {
            f.outside(); if (failExecute) throw new IllegalStateException("handler");
            commands.add(command);
        }
        @Override public void error(String message, Exception error) { f.outside(); ++errors; }
        void drain() { while (!commands.isEmpty()) commands.remove().run(); }
    }
    static final class Lifetime implements KeepWork.Lifetime {
        final Fixture f;
        final Object identity;
        Runnable death, onLink = () -> { }, onStop = () -> { };
        boolean alive = true, failLink;
        int links, unlinks, stops;
        long stoppedWork, stoppedRegistration;
        Lifetime(Fixture f) { this(f, new Object()); }
        Lifetime(Fixture f, Object identity) { this.f = f; this.identity = identity; }
        @Override public Object identity() { f.outside(); return identity; }
        @Override public void link(Runnable callback) throws Exception {
            f.outside(); ++links; death = callback; onLink.run();
            if (failLink) throw new Exception("link failed");
        }
        @Override public void unlink() { f.outside(); ++unlinks; }
        @Override public boolean isAlive() { f.outside(); return alive; }
        @Override public void stop(long work, long registration) {
            f.outside(); ++stops; stoppedWork = work; stoppedRegistration = registration;
            onStop.run();
        }
        void die() { alive = false; if (death != null) death.run(); }
    }

    public static void main(String[] args) {
        Fixture disabled = new Fixture(false); Lifetime none = new Lifetime(disabled);
        assert disabled.grant(none, 1) == 0 && none.links == 0 && disabled.backend.posts == 0;

        Fixture normal = new Fixture(true); Lifetime first = new Lifetime(normal);
        long registration = normal.grant(first, 3); assert registration > 0;
        assert normal.keep.snapshot().workId == 3 && normal.keep.snapshot().registration == registration;
        assert normal.grant(first, 3) == 0 && first.links == 1;
        String token = normal.backend.last.token;
        normal.keep.stop(token); assert normal.keep.snapshot().registration == 0;
        assert normal.grant(new Lifetime(normal), 4) == 0; // Retiring live group cannot be replaced.
        normal.backend.drain(); assert first.stops == 1 && first.stoppedWork == 3;
        assert first.stoppedRegistration == registration;
        first.die(); normal.backend.drain();
        Lifetime replacement = new Lifetime(normal);
        assert normal.grant(replacement, 4) > registration;
        String nextToken = normal.backend.last.token;
        normal.keep.stop(token); first.death.run(); normal.backend.drain();
        assert normal.keep.snapshot().workId == 4 && replacement.stops == 0;
        assert !normal.backend.cancelled.contains(nextToken);

        Fixture pending = new Fixture(true); Lifetime pendingLife = new Lifetime(pending);
        pending.backend.onPost = () -> pending.keep.stop(pending.backend.last.token);
        assert pending.grant(pendingLife, 5) == 0;
        assert pending.keep.snapshot().registration == 0 && pendingLife.unlinks == 0;
        pendingLife.onStop = pendingLife::die;
        pending.backend.drain(); assert pendingLife.stops == 1;
        pending.backend.onPost = () -> { };
        assert pending.grant(new Lifetime(pending), 6) > 0;

        Fixture failed = new Fixture(true); Lifetime failedLife = new Lifetime(failed);
        failed.backend.postOk = false;
        assert failed.grant(failedLife, 7) == 0 && failedLife.unlinks == 1;
        assert failed.keep.snapshot().registration == 0;
        failed.backend.postOk = true;
        Lifetime retry = new Lifetime(failed);
        assert failed.grant(retry, 8) > 0;
        failedLife.death.run(); failed.backend.drain();
        assert failed.keep.snapshot().workId == 8;

        Fixture died = new Fixture(true); Lifetime dying = new Lifetime(died);
        died.backend.onPost = dying::die;
        assert died.grant(dying, 9) == 0 && died.keep.snapshot().registration == 0;
        assert dying.unlinks == 1; died.backend.drain();

        Fixture link = new Fixture(true); Lifetime linkDeath = new Lifetime(link);
        linkDeath.onLink = linkDeath::die; linkDeath.failLink = true;
        assert link.grant(linkDeath, 10) == 0 && link.keep.snapshot().registration == 0;
        link.backend.drain(); assert link.backend.errors == 1;

        Fixture epoch = new Fixture(true); Lifetime obsolete = new Lifetime(epoch);
        epoch.backend.onPost = () -> {
            epoch.platform.ce(3, 2, true); // A new positive can overtake its negative.
            epoch.keep.platformChanged();
        };
        assert epoch.grant(obsolete, 11) == 0 && epoch.keep.snapshot().registration == 0;
        epoch.keep.cancelRevoked(); assert obsolete.unlinks == 0;
        obsolete.die(); epoch.backend.drain(); epoch.backend.onPost = () -> { };
        assert epoch.grant(new Lifetime(epoch), 12) > 0;
        epoch.platform.user(false); epoch.keep.platformChanged();
        assert !epoch.keep.snapshot().platform.available && epoch.keep.snapshot().registration == 0;

        Fixture staleTask = new Fixture(true); Lifetime old = new Lifetime(staleTask);
        assert staleTask.grant(old, 13) > 0;
        staleTask.keep.stop(staleTask.backend.last.token); // Task is queued, not executed.
        old.die();
        Lifetime newest = new Lifetime(staleTask);
        assert staleTask.grant(newest, 14) > 0;
        staleTask.backend.drain(); assert old.stops == 0 && newest.stops == 0;
        assert staleTask.keep.snapshot().workId == 14;

        Fixture callbackRace = new Fixture(true); Lifetime oldTarget = new Lifetime(callbackRace);
        Lifetime freshPlainTarget = new Lifetime(callbackRace); // Outside the Keep slot.
        assert callbackRace.grant(oldTarget, 15) > 0;
        oldTarget.onStop = oldTarget::die;
        callbackRace.keep.stop(callbackRace.backend.last.token); callbackRace.backend.drain();
        assert oldTarget.stops == 1 && freshPlainTarget.stops == 0; // No named-service retargeting.

        Fixture blocked = new Fixture(true); Lifetime channel = new Lifetime(blocked);
        assert blocked.grant(channel, 16) > 0;
        blocked.backend.failExecute = true; blocked.keep.notificationRevoked();
        assert blocked.keep.snapshot().registration == 0 && blocked.backend.errors > 0;
        assert blocked.grant(new Lifetime(blocked), 17) == 0;
        System.out.println("Keep orchestration/identity/Stop/notification failure tests passed; Android unqualified");
    }
}
