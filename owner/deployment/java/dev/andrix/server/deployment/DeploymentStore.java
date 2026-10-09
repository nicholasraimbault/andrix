// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Kind;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Prefix;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Durable host storage of the deployment records, for stages coordinated from the host.
 *
 * <p>Layout: one directory per kind under the root, plans, authorizations, tickets,
 * observations and selections, each record in one file named by its ID, or a selection by its
 * component, with the suffix ".rec". The name repeats what the record holds and the reader
 * checks that it does: no state lives in a file name. A writer stages the bytes in a sibling
 * whose name starts with "." and ends with ".staging", which is never a record.
 *
 * <p>Every write follows the native store's discipline: refuse unless the target's presence and
 * bytes are the expected ones, write the staging file through its own descriptor and sync it,
 * read it back, rename it over the target, sync the parent directory, then read the target
 * back. A crash leaves the old record or the new one, and a reader never sees a torn record.
 * A lost acknowledgement is resolved by reading the exact bytes, never by writing again.
 *
 * <p>Presence comes from one stat that does not follow links. Only a genuine NoSuchFileException
 * is absence. A link, directory or special node is damage, and any other failure leaves the
 * record unavailable: neither absent nor damaged, never overwritten, removed or selected around.
 * A file whose frame is intact but whose version this codec does not read is a newer record. Its
 * stable prefix is negative evidence: a ticket names its component, which then accepts no new
 * ticket. Damage, unknown files and unavailable entries in the tickets directory block every new
 * ticket, because they may hide an open one.
 *
 * <p>Plans, authorizations and observations are written once. A ticket is created only when no
 * other ticket of its component is open, as the next attempt of its plan, and changes only by a
 * step that {@link TicketMachine#check} accepts. A selection's choice, plan, update
 * responsibility and rebuild window change only together with the next revision. Its realization,
 * checked boot, repair link and temporary factory plan change only at the same revision, so the
 * cohort check never touches the choice. A temporary factory plan must be stored, of the
 * selection's component, and stand in for the chosen plan.
 *
 * <p>The store holds no lock. Its one coordinator serializes every call.
 *
 * <p>The public constructor always syncs. Host sweeps of the reconciler, which cannot observe a
 * sync, may use {@link #unsynced}. The store's own suite runs with every sync.
 */
public final class DeploymentStore {
    /** Named points of the write protocol, for host fault injection. Production passes none. */
    public interface Steps {
        void at(String step) throws IOException;
    }

    /** The write protocol's points, in order. */
    public static final List<String> STEPS = List.of("staged", "synced", "renamed", "parent-synced");

    /** What one record path holds. */
    public enum Found { ABSENT, RECORD, DAMAGED, NEWER, UNAVAILABLE }

    /** One read: the value when RECORD, the prefix when NEWER. */
    public static final class Read<T> {
        public final Found found;
        public final T value;
        public final Prefix prefix;
        final byte[] bytes;

        Read(Found found, T value, Prefix prefix, byte[] bytes) {
            this.found = found;
            this.value = value;
            this.prefix = prefix;
            this.bytes = bytes;
        }
    }

    /** All records of one kind, and every footprint the directory holds besides them. */
    public static final class Listing<T> {
        public final List<T> values;
        /** Damaged, newer, unavailable or unknown entries, by file name. */
        public final List<String> footprints;
        /** The stable prefixes of newer records. */
        public final List<Prefix> newer;

        Listing(List<T> values, List<String> footprints, List<Prefix> newer) {
            this.values = Collections.unmodifiableList(values);
            this.footprints = Collections.unmodifiableList(footprints);
            this.newer = Collections.unmodifiableList(newer);
        }
    }

    private static final String SUFFIX = ".rec";
    private static final String STAGING = ".staging";

    private final Path root;
    private final String installation;
    private final Steps steps;
    private final boolean sync;

    public DeploymentStore(Path root, String installation) {
        this(root, installation, step -> { }, true);
    }

    DeploymentStore(Path root, String installation, Steps steps, boolean sync) {
        this.root = Objects.requireNonNull(root, "root");
        DeploymentRecords.checkId(installation, "installation", false);
        this.installation = installation;
        this.steps = Objects.requireNonNull(steps, "steps");
        this.sync = sync;
    }

    /** For host sweeps of the reconciler only: the same protocol without the syncs. */
    static DeploymentStore unsynced(Path root, String installation) {
        return new DeploymentStore(root, installation, step -> { }, false);
    }

    public String installation() { return installation; }

    /** Creates the root and the kind directories, owner only, and syncs each parent. */
    public void initialize() throws IOException {
        directory(root);
        for (Kind kind : Kind.values()) directory(dir(kind));
    }

    private void directory(Path path) throws IOException {
        Node node = node(path);
        if (node == Node.DIRECTORY) return;
        if (node != Node.ABSENT) throw new IOException("store path is not a directory");
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        if (sync) syncDirectory(path.getParent());
    }

    private Path dir(Kind kind) {
        switch (kind) {
            case PLAN: return root.resolve("plans");
            case AUTHORIZATION: return root.resolve("authorizations");
            case TICKET: return root.resolve("tickets");
            case OBSERVATION: return root.resolve("observations");
            default: return root.resolve("selections");
        }
    }

    private Path file(Kind kind, String name) { return dir(kind).resolve(name + SUFFIX); }

    // ------------------------------------------------------------------ writes

    /** Writes a plan once. True when it is now stored with exactly these bytes. */
    public boolean addPlan(Plan plan) {
        return addOnce(Kind.PLAN, plan.planId, mine(plan.installation) ? DeploymentRecords.encodePlan(plan) : null);
    }

    /** Writes an authorization once, for a stored plan of the same component. */
    public boolean addAuthorization(Authorization a) {
        Read<Plan> plan = plan(a.planId);
        if (plan.found != Found.RECORD || !plan.value.component.equals(a.component)) return false;
        return addOnce(Kind.AUTHORIZATION, a.authorizationId,
                mine(a.installation) ? DeploymentRecords.encodeAuthorization(a) : null);
    }

    /** Writes an observation once. */
    public boolean addObservation(Observation o) {
        return addOnce(Kind.OBSERVATION, o.observationId,
                mine(o.installation) ? DeploymentRecords.encodeObservation(o) : null);
    }

    private boolean mine(String value) { return installation.equals(value); }

    private boolean addOnce(Kind kind, String name, byte[] bytes) {
        if (bytes == null) return false;
        Read<byte[]> current = readRaw(file(kind, name));
        if (current.found == Found.RECORD) return Arrays.equals(current.value, bytes);
        if (current.found != Found.ABSENT) return false;
        return write(file(kind, name), bytes, null);
    }

    /**
     * Creates a ticket in PLANNED as the next attempt of its stored plan, when no ticket of its
     * component is open and nothing in the tickets directory could hide an open one.
     */
    public boolean createTicket(Ticket ticket) {
        if (!mine(ticket.installation) || ticket.state != DeploymentRecords.State.PLANNED
                || !ticket.ledger.isEmpty()) {
            return false;
        }
        Read<Plan> plan = plan(ticket.planId);
        if (plan.found != Found.RECORD || !plan.value.component.equals(ticket.component)) return false;
        Listing<Ticket> tickets = tickets();
        if (!tickets.footprints.isEmpty()) return false;
        int attempt = 0;
        for (Ticket t : tickets.values) {
            if (t.component.equals(ticket.component) && !t.state.terminal()) return false;
            if (t.planId.equals(ticket.planId)) attempt = Math.max(attempt, t.attempt);
        }
        if (ticket.attempt != attempt + 1) return false;
        Path path = file(Kind.TICKET, ticket.ticketId);
        if (node(path) != Node.ABSENT) return false;
        return write(path, DeploymentRecords.encodeTicket(ticket), null);
    }

    /** Replaces a ticket with a legal successor, when the stored bytes are exactly the expected value's. */
    public boolean updateTicket(Ticket expected, Ticket next) {
        if (!expected.ticketId.equals(next.ticketId) || TicketMachine.check(expected, next) != null) return false;
        byte[] old = DeploymentRecords.encodeTicket(expected);
        return write(file(Kind.TICKET, expected.ticketId), DeploymentRecords.encodeTicket(next), old);
    }

    /**
     * Writes a component's selection. With no expected value, the first selection: revision 0,
     * unchecked. Otherwise the stored bytes must be exactly the expected value's.
     */
    public boolean putSelection(Selection expected, Selection next) {
        if (!mine(next.installation)) return false;
        if (expected == null) {
            if (next.revision != 0 || next.realization != Realization.UNCHECKED) return false;
            Path path = file(Kind.SELECTION, next.component);
            if (node(path) != Node.ABSENT) return false;
            return write(path, DeploymentRecords.encodeSelection(next), null);
        }
        if (!expected.component.equals(next.component) || !expected.installation.equals(next.installation)) {
            return false;
        }
        boolean sameChoice = expected.choice == next.choice && expected.planId.equals(next.planId)
                && expected.responsibility == next.responsibility
                && expected.rebuildWindowMillis == next.rebuildWindowMillis;
        if (!next.temporary.equals(DeploymentRecords.NO_ID)) {
            Read<Plan> temporary = plan(next.temporary);
            if (temporary.found != Found.RECORD || !temporary.value.component.equals(next.component)
                    || temporary.value.target != DeploymentRecords.Target.TEMPORARY_FACTORY
                    || !temporary.value.repairs.equals(next.planId)) {
                return false;
            }
        }
        if (next.revision == expected.revision) {
            if (!sameChoice || expected.changedAt != next.changedAt) return false;
        } else if (next.revision == expected.revision + 1) {
            if (sameChoice) return false;
            if (next.choice == ChoiceKind.PLAN) {
                Read<Plan> plan = plan(next.planId);
                if (plan.found != Found.RECORD || !plan.value.component.equals(next.component)) return false;
            }
        } else {
            return false;
        }
        return write(file(Kind.SELECTION, next.component), DeploymentRecords.encodeSelection(next),
                DeploymentRecords.encodeSelection(expected));
    }

    // The write protocol. prior is the exact current content, or null when the target must be
    // absent. Returns true only after the parent is synced and the target reads back exactly.
    private boolean write(Path target, byte[] bytes, byte[] prior) {
        Path parent = target.getParent();
        Path staging = parent.resolve("." + target.getFileName() + STAGING);
        try {
            if (node(parent) != Node.DIRECTORY) return false;
            Read<byte[]> current = readRaw(target);
            if (prior == null ? current.found != Found.ABSENT
                    : current.found != Found.RECORD || !Arrays.equals(current.value, prior)) {
                return false;
            }
            Node leftover = node(staging);
            if (leftover == Node.FILE) {
                Files.delete(staging); // An earlier writer's staging file is never a record.
            } else if (leftover != Node.ABSENT) {
                return false;
            }
            try (FileChannel out = FileChannel.open(staging, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) out.write(buffer);
                steps.at("staged");
                if (sync) out.force(true);
            }
            steps.at("synced");
            Read<byte[]> staged = readRaw(staging);
            if (staged.found != Found.RECORD || !Arrays.equals(staged.value, bytes)) return false;
            Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
            steps.at("renamed");
            if (sync) syncDirectory(parent);
            steps.at("parent-synced");
            Read<byte[]> written = readRaw(target);
            return written.found == Found.RECORD && Arrays.equals(written.value, bytes);
        } catch (IOException | RuntimeException error) {
            // Retain every copy: the outcome is resolved by reading the exact bytes.
            return false;
        }
    }

    private static void syncDirectory(Path directory) throws IOException {
        if (node(directory) != Node.DIRECTORY) throw new IOException("parent is not a directory");
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    // ------------------------------------------------------------------ reads

    private enum Node { ABSENT, FILE, DIRECTORY, OTHER, UNKNOWN }

    private static Node node(Path path) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (attributes.isRegularFile()) return Node.FILE;
            return attributes.isDirectory() ? Node.DIRECTORY : Node.OTHER;
        } catch (NoSuchFileException absent) {
            return Node.ABSENT;
        } catch (IOException | RuntimeException unknown) {
            return Node.UNKNOWN;
        }
    }

    // The bytes of one regular file within the size bound.
    private static Read<byte[]> readRaw(Path path) {
        Node node = node(path);
        if (node == Node.ABSENT) return new Read<>(Found.ABSENT, null, null, null);
        if (node == Node.UNKNOWN) return new Read<>(Found.UNAVAILABLE, null, null, null);
        if (node != Node.FILE) return new Read<>(Found.DAMAGED, null, null, null);
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = in.readNBytes(DeploymentRecords.MAX_BYTES + 1);
            if (bytes.length > DeploymentRecords.MAX_BYTES) return new Read<>(Found.DAMAGED, null, null, null);
            return new Read<>(Found.RECORD, bytes, null, bytes);
        } catch (IOException | RuntimeException unavailable) {
            return new Read<>(Found.UNAVAILABLE, null, null, null);
        }
    }

    private <T> Read<T> read(Kind kind, String name, Function<byte[], T> decode, Function<T, String> nameOf) {
        Read<byte[]> raw = readRaw(file(kind, name));
        if (raw.found != Found.RECORD) return new Read<>(raw.found, null, null, null);
        try {
            T value = decode.apply(raw.value);
            if (!nameOf.apply(value).equals(name)) return new Read<>(Found.DAMAGED, null, null, raw.value);
            return new Read<>(Found.RECORD, value, null, raw.value);
        } catch (IllegalArgumentException undecodable) {
            int[] frame = DeploymentRecords.intactFrame(raw.value);
            if (frame != null && frame[0] == kind.code && frame[1] > DeploymentRecords.VERSION) {
                Prefix prefix = null;
                try {
                    prefix = DeploymentRecords.decodePrefix(raw.value);
                } catch (IllegalArgumentException brokenPrefix) {
                    // A newer record whose prefix breaks a rule gives no evidence.
                }
                return new Read<>(Found.NEWER, null, prefix, raw.value);
            }
            return new Read<>(Found.DAMAGED, null, null, raw.value);
        }
    }

    public Read<Plan> plan(String id) {
        return read(Kind.PLAN, id, DeploymentRecords::decodePlan, p -> p.planId);
    }

    public Read<Ticket> ticket(String id) {
        return read(Kind.TICKET, id, DeploymentRecords::decodeTicket, t -> t.ticketId);
    }

    public Read<Selection> selection(String component) {
        return read(Kind.SELECTION, component, DeploymentRecords::decodeSelection, s -> s.component);
    }

    private <T> Listing<T> list(Kind kind, Function<byte[], T> decode, Function<T, String> nameOf) {
        List<String> names = new ArrayList<>();
        List<String> footprints = new ArrayList<>();
        if (node(dir(kind)) != Node.DIRECTORY) {
            footprints.add(dir(kind).getFileName().toString());
            return new Listing<>(new ArrayList<>(), footprints, new ArrayList<>());
        }
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir(kind))) {
            for (Path entry : entries) names.add(entry.getFileName().toString());
        } catch (IOException | RuntimeException unavailable) {
            footprints.add(dir(kind).getFileName().toString());
            return new Listing<>(new ArrayList<>(), footprints, new ArrayList<>());
        }
        Collections.sort(names);
        List<T> values = new ArrayList<>();
        List<Prefix> newer = new ArrayList<>();
        for (String name : names) {
            if (name.startsWith(".") && name.endsWith(STAGING)) continue; // Never a record.
            if (!name.endsWith(SUFFIX)) {
                footprints.add(name);
                continue;
            }
            Read<T> read = read(kind, name.substring(0, name.length() - SUFFIX.length()), decode, nameOf);
            if (read.found == Found.RECORD) {
                values.add(read.value);
            } else {
                footprints.add(name);
                if (read.prefix != null) newer.add(read.prefix);
            }
        }
        return new Listing<>(values, footprints, newer);
    }

    public Listing<Plan> plans() { return list(Kind.PLAN, DeploymentRecords::decodePlan, p -> p.planId); }

    public Listing<Authorization> authorizations() {
        return list(Kind.AUTHORIZATION, DeploymentRecords::decodeAuthorization, a -> a.authorizationId);
    }

    public Listing<Ticket> tickets() { return list(Kind.TICKET, DeploymentRecords::decodeTicket, t -> t.ticketId); }

    public Listing<Observation> observations() {
        return list(Kind.OBSERVATION, DeploymentRecords::decodeObservation, o -> o.observationId);
    }

    public Listing<Selection> selections() {
        return list(Kind.SELECTION, DeploymentRecords::decodeSelection, s -> s.component);
    }

    /** The authorizations of one plan. */
    public List<Authorization> authorizationsOf(String planId) {
        List<Authorization> result = new ArrayList<>();
        for (Authorization a : authorizations().values) if (a.planId.equals(planId)) result.add(a);
        return result;
    }

    /** The tickets of one plan. */
    public List<Ticket> ticketsOf(String planId) {
        List<Ticket> result = new ArrayList<>();
        for (Ticket t : tickets().values) if (t.planId.equals(planId)) result.add(t);
        return result;
    }
}
