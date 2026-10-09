// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.DeploymentRecords.NO_ID;

import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore.Found;
import dev.andrix.server.deployment.DeploymentStore.Read;
import dev.andrix.server.deployment.Reconciler.Clock;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;

/**
 * A host model of the Android behavior the plan cites, for the deployment tests. Package Manager's
 * staged sessions with their lazily written session file, StagingManager at boot, the userdata
 * checkpoint with two tries, the GrapheneOS boot check of a data copy, image changes, storage
 * freeing, users and health probes. Two readback routes read it: the lab shell route, which sees
 * the listing and the dumpsys sections but never the referrer, and the device route, which reads
 * its own sessions as their installer with the referrer and without the stage directory. Faults
 * are injected by crossing ordinal. Every crossing first checks that the store already holds its
 * ledger entry.
 *
 * <p>A model of the plan's description, not of Android itself: it qualifies the reconciler's rules
 * against that description only.
 */
final class AndroidFacade {
    static final int SHELL_UID = 2000, SYSTEM_UID = 1000;
    static final long EIGHT_HOURS = 8L * 3600 * 1000;

    /** One APK's facts. */
    static final class Apk {
        final String digest;
        final long version;
        final String signer;
        final boolean verity;

        Apk(String digest, long version, String signer, boolean verity) {
            this.digest = digest;
            this.version = version;
            this.signer = signer;
            this.verity = verity;
        }
    }

    /** One staged session, in memory or in the session file. */
    static final class Session {
        final int id;
        final long created;
        final String stageDir;
        final int installer;
        final String referrer;
        Apk apk;
        boolean sealed, committed, ready, applied, failed, destroyed, verifying, abandonDeferred, refused;
        String error = "";

        Session(int id, long created, int installer, String referrer) {
            this.id = id;
            this.created = created;
            this.stageDir = "/data/app-staging/session_" + id;
            this.installer = installer;
            this.referrer = referrer;
        }

        Session copy() {
            Session s = new Session(id, created, installer, referrer);
            s.apk = apk; s.sealed = sealed; s.committed = committed; s.ready = ready; s.applied = applied;
            s.failed = failed; s.destroyed = destroyed; s.error = error;
            return s;
        }

        boolean live() { return !applied && !failed && !destroyed && !refused; }
    }

    // /data, which an aborted or unfinished checkpoint rolls back.
    private static final class Data {
        TreeMap<Integer, Session> file = new TreeMap<>();
        Apk dataCopy;

        Data copy() {
            Data d = new Data();
            for (Map.Entry<Integer, Session> e : file.entrySet()) d.file.put(e.getKey(), e.getValue().copy());
            d.dataCopy = dataCopy;
            return d;
        }
    }

    /** One Android user. */
    static final class User {
        final int id;
        final long serial;
        boolean running = true, unlocked = true, removed;
        Classification probe = Classification.HEALTH_HELD;
        int criteria = DeploymentRecords.Criterion.ALL;

        User(int id, long serial) {
            this.id = id;
            this.serial = serial;
        }
    }

    /** Faults injected into one crossing. */
    enum Fault { NONE, LOST, REFUSED, CRASH_BEFORE, CRASH_AFTER, RESTART_AFTER, STOP_AFTER, UNRECOGNIZED, NO_EFFECT }

    /** The coordinator stops at this point, as if its process died. */
    static final class Crash extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Crash() { super("coordinator lost"); }
    }

    /** One issued crossing, as the device or host saw it. */
    static final class Call {
        final Crossing crossing;
        final String ticket;
        final int index;
        int session;
        final Fault fault;
        final String boot;
        final long elapsed;
        /** Whether the session the crossing names was live in memory when it was issued. */
        final boolean liveAtIssue;

        Call(Crossing crossing, String ticket, int index, int session, Fault fault, String boot, long elapsed,
                boolean liveAtIssue) {
            this.crossing = crossing;
            this.ticket = ticket;
            this.index = index;
            this.session = session;
            this.fault = fault;
            this.boot = boot;
            this.elapsed = elapsed;
            this.liveAtIssue = liveAtIssue;
        }

        void sessionSet(int id) { session = id; }
    }

    final Random random;
    final Map<String, Apk> apks = new HashMap<>();
    String fingerprint;
    Apk factory;
    String nextFingerprint;
    Apk nextFactory;
    private Data data = new Data();
    private Data checkpointBase;
    boolean checkpointPending;
    int checkpointTries;
    // Whether this boot armed the checkpoint for the next boot, which its own commit keeps.
    private boolean armedThisBoot;
    private boolean checkpointAbort;
    private String metadataFailure;
    private int metadataFailureSession;
    final TreeMap<Integer, Session> live = new TreeMap<>();
    final List<Session> history = new ArrayList<>();
    private final Set<Integer> allocated = new HashSet<>();
    boolean fileDamaged;
    String boot;
    int boots;
    long instance = 1;
    long elapsed = 1000;
    long bootWall;
    boolean completed;
    boolean holdWrites, holdVerification, holdCheckpoint, verifyInCommit = true, failVerification;
    boolean uidChanged;
    final List<User> users = new ArrayList<>();
    final Map<Integer, Fault> faults = new HashMap<>();
    int ordinal;
    final List<Call> calls = new ArrayList<>();
    final List<String> violations = new ArrayList<>();
    final List<String> notices = new ArrayList<>();
    DeploymentStore store;
    private long observationCount;
    private int sequence;
    /** Observation IDs that fall with time, so the store's listing by ID is the reverse of time. */
    boolean fallingIds;

    AndroidFacade(long seed, Apk factory) {
        this.random = new Random(seed);
        this.factory = factory;
        this.fingerprint = Fixtures.FINGERPRINT;
        apks.put(factory.digest, factory);
        users.add(new User(0, 0));
        bootWall = Fixtures.TIME;
        boot = newBoot();
    }

    private String newBoot() {
        ++boots;
        return String.format("%016x%016x", 0xb007000000000000L | boots, random.nextLong() | 1);
    }

    long wall() { return bootWall + elapsed; }

    void advance(long millis) { elapsed += millis; }

    // ------------------------------------------------------------------ Package Manager

    Apk active() { return data.dataCopy != null ? data.dataCopy : factory; }

    boolean dataCopyActive() { return data.dataCopy != null; }

    private int allocate() {
        while (true) {
            int id = random.nextInt(Integer.MAX_VALUE - 1) + 1;
            if (allocated.add(id)) return id;
        }
    }

    int create(int installer, String referrer) {
        Session s = new Session(allocate(), wall(), installer, referrer);
        live.put(s.id, s);
        return s.id; // Creation reaches the session file only with a later write.
    }

    boolean write(int id, Apk apk) {
        Session s = live.get(id);
        if (s == null || s.sealed || !s.live()) return false;
        s.apk = apk;
        return true;
    }

    /** Commit: sealed at once, committed and ready only with later writes. Returns the reply class. */
    Classification commit(int id) {
        Session s = live.get(id);
        if (s == null || s.sealed || !s.live() || s.apk == null) return Classification.REPLY_REFUSED;
        if (s.apk.version <= active().version || s.apk.version <= factory.version) {
            // Refused at validation: the session leaves for the in memory history.
            s.refused = true;
            s.failed = true;
            s.error = "INSTALL_FAILED_VERSION_DOWNGRADE";
            live.remove(id);
            history.add(s);
            return Classification.REPLY_REFUSED;
        }
        s.sealed = true;
        boolean held = holdWrites;
        holdWrites = false;
        flush(); // The sealed flag is written at once, synchronously, before the committed flag is set.
        holdWrites = held;
        s.committed = true;
        s.verifying = true;
        if (!verifyInCommit || holdVerification) return Classification.REPLY_PENDING;
        verify(s);
        return s.ready ? Classification.REPLY_READY : Classification.REPLY_REFUSED;
    }

    private void verify(Session s) {
        if (!s.verifying) return;
        s.verifying = false;
        if (failVerification) {
            s.failed = true;
            s.error = "verification failed";
        } else {
            s.ready = true;
            checkpointTries = 2; // Arms the checkpoint with two tries, on /metadata.
            armedThisBoot = true;
        }
        if (s.abandonDeferred) destroy(s);
    }

    void verifyPending() {
        if (holdVerification) return;
        for (Session s : new ArrayList<>(live.values())) verify(s);
    }

    Classification abandon(int id) {
        Session s = live.get(id);
        if (s == null || s.destroyed || s.applied || s.failed) return Classification.REPLY_REFUSED;
        if (s.verifying) {
            s.abandonDeferred = true; // Android defers an abandon while verification runs.
            return Classification.REPLY_SUCCESS;
        }
        destroy(s);
        return Classification.REPLY_SUCCESS;
    }

    private void destroy(Session s) {
        s.destroyed = true; // Hidden as destroyed. It leaves the file with a later write.
        live.remove(s.id);
        history.add(s);
    }

    /** The background queue writes the session file. */
    void flush() {
        if (holdWrites) return;
        TreeMap<Integer, Session> file = new TreeMap<>();
        for (Session s : live.values()) file.put(s.id, s.copy());
        data.file = file;
    }

    void storageFreeing() {
        for (Session s : new ArrayList<>(live.values())) {
            if (!s.applied && !s.failed && wall() - s.created > EIGHT_HOURS) destroy(s);
        }
    }

    void otherInstaller(Apk apk) {
        apks.put(apk.digest, apk);
        data.dataCopy = apk;
    }

    void imageChange(String fingerprintValue, Apk factoryValue) {
        nextFingerprint = fingerprintValue;
        nextFactory = factoryValue;
        apks.put(factoryValue.digest, factoryValue);
    }

    // ------------------------------------------------------------------ restarts

    /** A system_server restart in the same kernel boot: memory reloads from the session file. */
    void frameworkRestart() {
        instance = Math.max(instance + 1, elapsed);
        elapsed += 10;
        reload();
    }

    private void reload() {
        live.clear();
        history.clear();
        allocated.clear();
        if (fileDamaged) {
            data.file.clear(); // Sessions that cannot be parsed are skipped and their directories deleted.
            fileDamaged = false;
        }
        for (Session s : data.file.values()) {
            Session copy = s.copy();
            live.put(copy.id, copy);
            allocated.add(copy.id);
        }
    }

    /** A kernel boot. A clean one is a requested reboot, which writes the session file first. */
    void kernelBoot(boolean clean) {
        if (clean) flush();
        if (checkpointPending) {
            data = checkpointBase; // The checkpoint never committed: /data rolls back.
            if (checkpointTries == 0) checkpointAbort = true;
        }
        checkpointPending = false;
        checkpointBase = null;
        long wall = wall();
        if (nextFactory != null) {
            fingerprint = nextFingerprint;
            factory = nextFactory;
            nextFactory = null;
            for (Session s : data.file.values()) {
                if (s.committed && !s.applied && !s.failed) {
                    s.failed = true;
                    s.error = "Build fingerprint has changed";
                }
            }
        }
        boot = newBoot();
        armedThisBoot = false;
        bootWall = wall + 5000;
        elapsed = 1000;
        instance = 1;
        completed = false;
        if (metadataFailure != null) {
            Session s = data.file.get(metadataFailureSession);
            if (s != null) {
                s.failed = true;
                s.error = metadataFailure;
            }
            metadataFailure = null;
        }
        if (data.dataCopy != null && !acceptedAtBoot(data.dataCopy)) data.dataCopy = null;
        if (checkpointAbort) {
            checkpointAbort = false;
            for (Session s : data.file.values()) {
                if (s.committed && s.ready && !s.applied && !s.failed) {
                    s.failed = true;
                    s.error = "Reverting back to safe state";
                }
            }
        } else if (checkpointTries > 0) {
            --checkpointTries;
            checkpointPending = true;
            checkpointBase = data.copy();
        }
        for (Session s : data.file.values()) {
            if (!s.committed || !s.ready || s.applied || s.failed || !checkpointPending) continue;
            if (acceptedAtBoot(s.apk)) {
                data.dataCopy = s.apk;
                s.applied = true;
            } else {
                // The reason goes to /metadata, the checkpoint aborts, and Android reboots.
                metadataFailure = "signature or verity rejected at boot";
                metadataFailureSession = s.id;
                data = checkpointBase;
                checkpointPending = false;
                checkpointBase = null;
                checkpointTries = 0;
                kernelBoot(false);
                return;
            }
        }
        reload();
    }

    // The GrapheneOS check of a data copy of a system package at boot.
    private boolean acceptedAtBoot(Apk apk) {
        return apk.version > factory.version && apk.verity && apk.signer.equals(factory.signer);
    }

    void bootComplete() {
        completed = true;
        for (Session s : live.values()) {
            // A committed session whose verification was cut short is verified again.
            if (s.committed && !s.ready && s.live()) s.verifying = true;
        }
        verifyPending();
    }

    void commitCheckpoint() {
        if (completed && checkpointPending && !holdCheckpoint) {
            checkpointPending = false;
            checkpointBase = null;
            if (!armedThisBoot) checkpointTries = 0; // Committing ends checkpoint mode.
        }
    }

    /** One step of time with the background work that follows it. */
    void tick(long millis) {
        advance(millis);
        flush();
        verifyPending();
        if (!completed) bootComplete();
        commitCheckpoint();
    }

    // ------------------------------------------------------------------ observations

    private Observation.Builder fact(Route route, Classification c) {
        String text = route + " " + c + " " + boot + " " + elapsed + " " + (++observationCount);
        return new Observation.Builder().installation(Fixtures.INSTALLATION)
                .observationId(Fixtures.id(fallingIds ? 0x1fffffffL - (++sequence) : 0x10000000L + (++sequence)))
                .boot(boot).route(route).raw(DeploymentRecords.sha256Hex(text.getBytes(StandardCharsets.US_ASCII)))
                .classification(c).at(-1, elapsed, wall());
    }

    private List<Observation> deviceFacts(Route route, boolean withUsers) {
        List<Observation> list = new ArrayList<>();
        list.add(fact(route, completed ? Classification.BOOT_COMPLETED : Classification.BOOTING).text(fingerprint).build());
        list.add(fact(route, checkpointPending ? Classification.CHECKPOINT_PENDING : Classification.CHECKPOINT_COMMITTED)
                .build());
        list.add(fact(route, Classification.FACTORY_PRESENT).component(Fixtures.COMPONENT).digest(factory.digest)
                .version(factory.version).at(instance, elapsed, wall()).build());
        Apk active = active();
        list.add(fact(route, dataCopyActive() ? Classification.DATA_COPY : Classification.FACTORY_COPY)
                .component(Fixtures.COMPONENT).digest(active.digest).version(active.version)
                .number(uidChanged ? Fixtures.UID + 1 : Fixtures.UID).text(Fixtures.CONTEXT)
                .at(instance, elapsed, wall()).build());
        for (User u : withUsers ? users : List.<User>of()) {
            Classification c = u.removed ? Classification.USER_REMOVED
                    : !u.running ? Classification.NOT_RUNNING
                    : u.unlocked ? Classification.RUNNING_UNLOCKED : Classification.RUNNING_LOCKED;
            list.add(fact(route, c).user(u.id, u.serial).build());
            if (!u.removed && u.running && u.unlocked) {
                list.add(fact(route, u.probe).component(Fixtures.COMPONENT).user(u.id, u.serial).number(u.criteria)
                        .build());
            }
        }
        return list;
    }

    private static Classification classOf(Session s) {
        if (s.applied) return Classification.SESSION_APPLIED;
        if (s.failed) return s.refused ? Classification.SESSION_REFUSED : Classification.SESSION_FAILED;
        if (s.destroyed) return Classification.SESSION_ABANDONED;
        if (s.ready) return Classification.SESSION_READY;
        if (!s.sealed) return Classification.OPEN;
        return s.committed ? Classification.VERIFYING : Classification.SEALED;
    }

    private Reference shellReference(Session s) {
        return new Reference(Reference.SESSION | Reference.CREATED | Reference.STAGE_DIR | Reference.INSTALLER, s.id,
                s.created, s.stageDir, s.installer, NO_ID);
    }

    private Reference deviceReference(Session s) {
        int presence = Reference.SESSION | Reference.CREATED | Reference.INSTALLER;
        if (s.referrer != null) presence |= Reference.NONCE;
        return new Reference(presence, s.id, s.created, "", s.installer, s.referrer == null ? NO_ID : s.referrer);
    }

    /** The shell route: the listing joined with dumpsys by session ID, and dumpsys's history. */
    List<Observation> shellSessions() {
        List<Observation> list = new ArrayList<>();
        int listed = 0;
        for (Session s : live.values()) {
            list.add(fact(Route.SHELL, classOf(s)).component(Fixtures.COMPONENT).reference(shellReference(s))
                    .at(instance, elapsed, wall()).build());
            ++listed;
        }
        for (Session s : history) {
            list.add(fact(Route.SHELL, classOf(s)).component(Fixtures.COMPONENT).reference(shellReference(s))
                    .at(instance, elapsed, wall()).build());
        }
        list.add(fact(Route.SHELL, listed == 0 ? Classification.NONE_FOR_PACKAGE : Classification.SESSIONS_FOR_PACKAGE)
                .component(Fixtures.COMPONENT).number(listed).at(instance, elapsed, wall()).build());
        return list;
    }

    /** The device route: getStagedSessions as the installer, with referrers, without destroyed sessions. */
    List<Observation> deviceSessions() {
        List<Observation> list = new ArrayList<>();
        int listed = 0;
        for (Session s : live.values()) {
            list.add(fact(Route.DEVICE, classOf(s)).component(Fixtures.COMPONENT).reference(deviceReference(s))
                    .at(instance, elapsed, wall()).build());
            ++listed;
        }
        list.add(fact(Route.DEVICE, listed == 0 ? Classification.NONE_FOR_PACKAGE
                : Classification.SESSIONS_FOR_PACKAGE).component(Fixtures.COMPONENT).number(listed)
                .at(instance, elapsed, wall()).build());
        return list;
    }

    // ------------------------------------------------------------------ routes

    /** One readback route into this model. */
    final class Link implements Coordinator.Device {
        final Route route;

        Link(Route route) { this.route = route; }

        @Override
        public Route route() { return route; }

        @Override
        public Clock clock() { return new Clock(boot, instance, elapsed, wall()); }

        @Override
        public List<Observation> observe(Ticket ticket, Plan plan) {
            advance(1);
            // Users and health are read when the ticket needs them: for the notice before an
            // activating reboot, and from the activation boot on.
            DeploymentRecords.State state = ticket.state;
            boolean users = state.code >= DeploymentRecords.State.BOOT_OBSERVED.code
                    || state == DeploymentRecords.State.PUBLISHED || state == DeploymentRecords.State.READY
                    || state == DeploymentRecords.State.READY_AGAIN;
            List<Observation> list = deviceFacts(route, users);
            list.addAll(route == Route.SHELL ? shellSessions() : deviceSessions());
            return list;
        }

        @Override
        public Observation cross(Ticket ticket, Plan plan, Entry entry) {
            advance(1);
            Fault fault = begin(ticket, entry);
            if (fault == Fault.CRASH_BEFORE) throw new Crash();
            if (fault == Fault.NO_EFFECT) return null;
            int index = ticket.indexOf(entry);
            if (fault == Fault.REFUSED) {
                if (entry.crossing == Crossing.REBOOT || entry.crossing == Crossing.NOTICE) return null;
                return reply(route, ticket, index, entry.crossing, Classification.REPLY_REFUSED, Reference.NONE).build();
            }
            Classification answer;
            Reference reference = Reference.NONE;
            int session = ticket.reference.has(Reference.SESSION) ? ticket.reference.sessionId : 0;
            switch (entry.crossing) {
                case CREATE: {
                    int installer = route == Route.SHELL ? SHELL_UID : SYSTEM_UID;
                    session = create(installer, entry.reference);
                    calls.get(calls.size() - 1).sessionSet(session);
                    answer = Classification.REPLY_SUCCESS;
                    break;
                }
                case WRITE:
                    answer = write(session, apks.get(plan.bundleApk)) ? Classification.REPLY_SUCCESS
                            : Classification.REPLY_REFUSED;
                    break;
                case COMMIT:
                    answer = commit(session);
                    if (answer == Classification.REPLY_PENDING && route == Route.DEVICE) {
                        answer = Classification.REPLY_ACCEPTED;
                    }
                    break;
                case ABANDON:
                    answer = abandon(session);
                    break;
                case REBOOT:
                    if (fault == Fault.RESTART_AFTER) {
                        frameworkRestart();
                        return null;
                    }
                    kernelBoot(true);
                    if (fault == Fault.CRASH_AFTER) throw new Crash();
                    return null; // The connection drops with the device.
                case NOTICE:
                    notices.add(boot);
                    answer = Classification.REPLY_SUCCESS;
                    break;
                default:
                    throw new IllegalStateException("not a device crossing");
            }
            if (fault == Fault.CRASH_AFTER) throw new Crash();
            if (fault == Fault.STOP_AFTER) {
                kernelBoot(false);
                return null;
            }
            if (fault == Fault.RESTART_AFTER) frameworkRestart();
            if (fault == Fault.LOST) return null;
            if (fault == Fault.UNRECOGNIZED) answer = Classification.REPLY_UNRECOGNIZED;
            if (entry.crossing == Crossing.CREATE && answer == Classification.REPLY_SUCCESS) {
                // The route completes the reference in the same framework instance, or not at all.
                Session s = live.get(session);
                if (s != null && fault != Fault.RESTART_AFTER) {
                    reference = route == Route.SHELL ? shellReference(s) : deviceReference(s);
                } else {
                    reference = new Reference(Reference.SESSION, session, 0, "", 0, NO_ID);
                }
            }
            return reply(route, ticket, index, entry.crossing, answer, reference).build();
        }
    }

    private Observation.Builder reply(Route route, Ticket ticket, int index, Crossing crossing, Classification c,
            Reference reference) {
        long at = crossing.framework() ? instance : -1;
        return fact(route, c).component(Fixtures.COMPONENT).reply(ticket.ticketId, index, crossing)
                .reference(reference).at(at, elapsed, wall());
    }

    // Checks that the crossing's entry is already durable, then records the call and its fault.
    private Fault begin(Ticket ticket, Entry entry) {
        Fault fault = faults.getOrDefault(ordinal++, Fault.NONE);
        if (store != null) {
            Read<Ticket> stored = store.ticket(ticket.ticketId);
            if (stored.found != Found.RECORD || stored.value.ledger.isEmpty()
                    || !stored.value.ledger.get(stored.value.ledger.size() - 1).equals(entry)) {
                violations.add("crossing " + entry.crossing + " issued before its entry was synced");
            }
        }
        int session = ticket.reference.has(Reference.SESSION) ? ticket.reference.sessionId : 0;
        Session target = live.get(session);
        calls.add(new Call(entry.crossing, ticket.ticketId, ticket.indexOf(entry), session, fault, boot, elapsed,
                target != null && target.live()));
        return fault;
    }

    Link shell() { return new Link(Route.SHELL); }

    Link device() { return new Link(Route.DEVICE); }

    // ------------------------------------------------------------------ the host signer and store

    /** The host signer with the development key, and the artifact store. */
    final class Host implements Coordinator.Host {
        final Map<String, Classification> requests = new HashMap<>();
        final Set<String> published = new HashSet<>();
        boolean refuse;
        int signatures;

        @Override
        public Observation sign(Ticket ticket, Plan plan, Entry entry, Authorization grant) {
            Fault fault = begin(ticket, entry);
            if (fault == Fault.CRASH_BEFORE) throw new Crash();
            if (fault == Fault.NO_EFFECT) return null;
            if (refuse || fault == Fault.REFUSED) {
                requests.put(entry.reference, Classification.SIGN_REFUSED);
            } else {
                requests.put(entry.reference, Classification.SIGN_COMPLETED);
                ++signatures;
            }
            if (fault == Fault.CRASH_AFTER) throw new Crash();
            if (fault == Fault.LOST) return null;
            return hostFact(requests.get(entry.reference)).subject(entry.reference).build();
        }

        @Override
        public Observation publish(Ticket ticket, Plan plan, Entry entry) {
            Fault fault = begin(ticket, entry);
            if (fault == Fault.CRASH_BEFORE) throw new Crash();
            if (fault == Fault.NO_EFFECT) return null;
            published.add(plan.bundle);
            if (plan.hasRestoration()) published.add(plan.restoration);
            if (fault == Fault.CRASH_AFTER) throw new Crash();
            if (fault == Fault.LOST) return null;
            return hostFact(Classification.BUNDLE_PUBLISHED).digest(plan.bundle).build();
        }

        // The signer answers by request ID. A request it never received can no longer complete:
        // the query records it as dead, which is the signer's proof.
        @Override
        public List<Observation> query(Ticket ticket, Plan plan) {
            List<Observation> list = new ArrayList<>();
            DeploymentRecords.State state = ticket.state;
            if (state != DeploymentRecords.State.SIGNING && state != DeploymentRecords.State.SIGNED
                    && state != DeploymentRecords.State.AUTHORIZED) {
                return list; // Signing and publication are settled; nothing is read again.
            }
            for (Entry e : ticket.ledger) {
                if (e.crossing != Crossing.SIGN) continue;
                Classification c = requests.computeIfAbsent(e.reference, r -> Classification.SIGN_CANNOT_COMPLETE);
                list.add(hostFact(c).subject(e.reference).build());
            }
            if (plan.target == DeploymentRecords.Target.VARIANT) {
                list.add(hostFact(published.contains(plan.bundle) ? Classification.BUNDLE_PUBLISHED
                        : Classification.BUNDLE_ABSENT).digest(plan.bundle).build());
                if (plan.hasRestoration()) {
                    list.add(hostFact(published.contains(plan.restoration) ? Classification.BUNDLE_PUBLISHED
                            : Classification.BUNDLE_ABSENT).digest(plan.restoration).build());
                }
            }
            return list;
        }

        private Observation.Builder hostFact(Classification c) {
            return fact(Route.HOST, c).component(Fixtures.COMPONENT).boot(NO_ID).at(-1, 0, wall());
        }
    }

    Host host() { return new Host(); }
}
