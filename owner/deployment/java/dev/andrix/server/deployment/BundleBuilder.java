// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.DeploymentRecords.NO_DIGEST;
import static dev.andrix.server.deployment.DeploymentRecords.NO_ID;

import dev.andrix.server.deployment.ArtifactRecords.Manifest;
import dev.andrix.server.deployment.ArtifactRecords.Member;
import dev.andrix.server.deployment.ArtifactRecords.Operation;
import dev.andrix.server.deployment.ArtifactRecords.Output;
import dev.andrix.server.deployment.ArtifactRecords.Publication;
import dev.andrix.server.deployment.ArtifactRecords.Role;
import dev.andrix.server.deployment.ArtifactRecords.Scheme;
import dev.andrix.server.deployment.ArtifactRecords.Transaction;
import dev.andrix.server.deployment.ArtifactRecords.TransactionState;
import dev.andrix.server.deployment.ArtifactStore.Presence;
import dev.andrix.server.deployment.ArtifactStore.Staged;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.HostSigner.Signed;
import dev.andrix.server.deployment.HostSigner.Verification;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * The bundle builder and the coordinator's host: it signs a variant and its restoration in one
 * transaction of the host signer, verifies every output, stages both bundles privately and
 * publishes them together through the artifact store, or neither.
 *
 * <p>Each output must meet the facts its transaction record names: its entries are its input's,
 * v2 verifies with a pass below SDK 28, v3 and v4 verify over the declared range, and every signer
 * of every scheme has the platform role's certificate and key digests from the trusted role
 * manifest. Only then is a bundle staged, and only then does the ticket see SIGN_COMPLETED: SIGNED
 * means verified and private. A publication names exactly the bundles of the ticket's own SIGN
 * requests, each with its transaction, which is that request's ID. A plan that signs nothing is
 * decision 3's restoration plan, and names the restoration that the repaired plan's publication
 * bound. Host only.
 *
 * <p>An input is signed only when it is the plan's: its entry digest is the plan's input for its
 * role, it carries no v1 signature files, and the facts its own binary manifest declares are the
 * plan's and the component's. For SystemUI those are the package {@code com.android.systemui},
 * the shared user {@code android.uid.systemui}, the persistent flag, the plan's versionCode for
 * the role, and the declared SDK range of the transaction.
 */
public final class BundleBuilder implements Coordinator.Host {
    /** The first component, and the facts its APK must declare besides the plan's own. */
    static final String SYSTEMUI = "com.android.systemui";
    static final String SYSTEMUI_SHARED_USER = "android.uid.systemui";

    /** The operator's signing inputs, by their entry digest. Null when an input is not at hand. */
    public interface Inputs {
        byte[] input(String inputEntries);
    }

    /** The platform role as the trusted role manifest binds it: certificate and public key digests. */
    public static final class RoleIdentity {
        public final String certificate;
        public final String key;

        public RoleIdentity(String certificate, String key) {
            DeploymentRecords.checkDigest(certificate, "certificate", false);
            DeploymentRecords.checkDigest(key, "key", false);
            this.certificate = certificate;
            this.key = key;
        }
    }

    private final String installation;
    private final HostSigner signer;
    private final ArtifactStore store;
    private final HostSigner.Engine engine;
    private final RoleIdentity role;
    private final int sdkMin;
    private final int sdkMax;
    private final Inputs inputs;
    private final Reconciler.Ids ids;
    private final LongSupplier wall;

    public BundleBuilder(String installation, HostSigner signer, ArtifactStore store, HostSigner.Engine engine,
            RoleIdentity role, int sdkMin, int sdkMax, Inputs inputs, Reconciler.Ids ids, LongSupplier wall) {
        DeploymentRecords.checkId(installation, "installation", false);
        this.installation = installation;
        this.signer = Objects.requireNonNull(signer, "signer");
        this.store = Objects.requireNonNull(store, "store");
        this.engine = Objects.requireNonNull(engine, "engine");
        this.role = Objects.requireNonNull(role, "role");
        if (sdkMin < 1 || sdkMax < sdkMin || sdkMax > 0xffff) throw new IllegalArgumentException("SDK range");
        this.sdkMin = sdkMin;
        this.sdkMax = sdkMax;
        this.inputs = Objects.requireNonNull(inputs, "inputs");
        this.ids = Objects.requireNonNull(ids, "ids");
        this.wall = Objects.requireNonNull(wall, "wall");
    }

    // ------------------------------------------------------------------ signing

    @Override
    public Observation sign(Ticket ticket, Plan plan, Entry entry, Authorization grant) {
        List<Role> roles = roles(grant);
        Map<Role, byte[]> bytes = new EnumMap<>(Role.class);
        Transaction open = template(plan, grant == null ? NO_ID : grant.authorizationId, roles, entry.reference, bytes);
        if (open == null) return null; // No input at hand: nothing signed and nothing recorded.
        boolean inputsMatch = true;
        for (Role r : roles) {
            try {
                inputsMatch &= ApkEntries.digest(bytes.get(r)).equals(input(plan, r));
                inputsMatch &= !ApkEntries.hasSignatureFiles(bytes.get(r));
                inputsMatch &= facts(plan, r, engine.facts(bytes.get(r))) == null;
            } catch (IllegalArgumentException notZip) {
                inputsMatch = false;
            }
        }
        // Inputs that are not the plan's are never signed: the request can no longer complete.
        HostSigner.Reply reply = inputsMatch ? signer.sign(open, bytes) : signer.query(entry.reference, open);
        return reply == null ? null : signerFact(plan, reply.record);
    }

    /** The OPEN record that signing this plan's inputs under the grant would write, or null. */
    Transaction open(Plan plan, Authorization grant, String transaction) {
        return template(plan, grant.authorizationId, roles(grant), transaction, new EnumMap<>(Role.class));
    }

    // The roles a SIGN grant covers, the variant first. None without a grant.
    private static List<Role> roles(Authorization grant) {
        List<Role> roles = new ArrayList<>();
        if (grant != null && (grant.inputs & DeploymentRecords.INPUT_VARIANT) != 0) roles.add(Role.VARIANT);
        if (grant != null && (grant.inputs & DeploymentRecords.INPUT_RESTORATION) != 0) roles.add(Role.RESTORATION);
        return roles;
    }

    // The OPEN record for a transaction: fresh operation IDs, and the expected outputs with the
    // facts each must meet. Null when an input is not at hand.
    private Transaction template(Plan plan, String authorization, List<Role> roles, String transaction,
            Map<Role, byte[]> bytes) {
        if (roles.isEmpty() || authorization.equals(NO_ID)) return null;
        List<Operation> operations = new ArrayList<>();
        List<Output> outputs = new ArrayList<>();
        for (Role r : roles) {
            byte[] input = inputs.input(input(plan, r));
            if (input == null) return null;
            bytes.put(r, input);
            for (Scheme s : Scheme.values()) operations.add(new Operation(ids.get(), r, s));
            String sha = DeploymentRecords.sha256Hex(input);
            long version = r == Role.VARIANT ? plan.bundleVersion : plan.restorationVersion;
            outputs.add(new Output(r, Member.APK, ArtifactRecords.APK_FACTS, sha, input(plan, r), version, NO_DIGEST, 0));
            outputs.add(new Output(r, Member.IDSIG, ArtifactRecords.IDSIG_FACTS, sha, input(plan, r), version,
                    NO_DIGEST, 0));
        }
        return new Transaction(installation, transaction, plan.component, plan.planId, authorization,
                role.certificate, role.key, sdkMin, sdkMax, TransactionState.OPEN, 0, operations, outputs);
    }

    private static String input(Plan plan, Role r) { return r == Role.VARIANT ? plan.bundleInput : plan.restorationInput; }

    /**
     * Checks the facts an input's own binary manifest declares against the plan and the
     * component. Returns null when every fact holds, else the first that fails.
     */
    String facts(Plan plan, Role r, HostSigner.Facts f) {
        if (f == null) return "no binary manifest";
        if (!plan.component.equals(SYSTEMUI)) return "no known facts for the component";
        if (!f.packageName.equals(plan.component)) return "another package";
        if (!f.sharedUserId.equals(SYSTEMUI_SHARED_USER)) return "another shared user";
        if (!f.persistent) return "not persistent";
        if (f.versionCode != (r == Role.VARIANT ? plan.bundleVersion : plan.restorationVersion)) {
            return "another versionCode";
        }
        if (f.minSdk != sdkMin || f.targetSdk < f.minSdk || (f.maxSdk == 0 ? sdkMax != 0xffff : f.maxSdk != sdkMax)) {
            return "another SDK range";
        }
        return null;
    }

    // The signer's answer as the ticket reads it. A COMPLETED transaction counts only once every
    // output verified and both bundles are staged privately. Outputs that fail their facts never
    // heal, so the request can no longer complete. A read, verifier or staging I/O failure proves
    // nothing: it gives no fact, and a later read verifies and stages the same outputs again.
    private Observation signerFact(Plan plan, Transaction t) {
        Classification c;
        switch (t.state) {
            case COMPLETED:
                Finish finished = staged(t) ? Finish.STAGED : finish(t);
                if (finished == Finish.UNAVAILABLE) return null;
                c = finished == Finish.STAGED ? Classification.SIGN_COMPLETED : Classification.SIGN_CANNOT_COMPLETE;
                break;
            case REFUSED:
                c = Classification.SIGN_REFUSED;
                break;
            case CANNOT_COMPLETE:
                c = Classification.SIGN_CANNOT_COMPLETE;
                break;
            default:
                return null; // Still OPEN: only a later read proves the outcome.
        }
        return hostFact(plan, c, DeploymentRecords.sha256Hex(ArtifactRecords.encodeTransaction(t)))
                .subject(t.transaction).build();
    }

    private boolean staged(Transaction t) {
        for (Role r : t.roles()) if (store.held(ArtifactRecords.bundleId(manifest(t, r))) == null) return false;
        return true;
    }

    // What finishing a COMPLETED transaction found: both bundles staged, an output that is gone,
    // damaged or fails its facts, or a read, verifier or staging I/O failure.
    private enum Finish { STAGED, FAILED, UNAVAILABLE }

    // Verifies every retained output of a COMPLETED transaction and stages its bundles. Nothing is
    // staged unless every output of the transaction passes.
    private Finish finish(Transaction t) {
        Map<Role, Signed> signed = new EnumMap<>(Role.class);
        for (Role r : t.roles()) {
            Signed s;
            try {
                s = signer.retained(t.transaction, r);
            } catch (UncheckedIOException unreadable) {
                return Finish.UNAVAILABLE; // A read error proves nothing: a later read tries again.
            }
            Manifest m = manifest(t, r);
            try {
                if (s == null || verify(s.apk, s.idsig, m) != null) return Finish.FAILED;
            } catch (UncheckedIOException unverified) {
                return Finish.UNAVAILABLE; // Only a check that fails is final, never the verifier's I/O error.
            }
            signed.put(r, s);
        }
        for (Role r : t.roles()) {
            // The outputs passed. Only the private copy failed, which a later read writes again.
            if (store.stage(manifest(t, r), signed.get(r).apk, signed.get(r).idsig) == null) return Finish.UNAVAILABLE;
        }
        return Finish.STAGED;
    }

    /** The manifest of one role's bundle, from a COMPLETED transaction record. */
    Manifest manifest(Transaction t, Role r) {
        Output apk = null, idsig = null;
        for (Output o : t.outputs) {
            if (o.role == r && o.member == Member.APK) apk = o;
            if (o.role == r && o.member == Member.IDSIG) idsig = o;
        }
        Objects.requireNonNull(apk, "apk output");
        Objects.requireNonNull(idsig, "idsig output");
        return new Manifest(installation, t.component, r, t.transaction, apk.input, apk.inputEntries, apk.versionCode,
                apk.digest, apk.bytes, idsig.digest, idsig.bytes, t.certificate, t.key, ArtifactRecords.SCHEMES,
                t.sdkMin, t.sdkMax, ArtifactRecords.V4Check.VERIFIED);
    }

    /**
     * Checks one signed APK and its sidecar against the facts its manifest names. Returns null when
     * every fact holds, else the first that fails. Throws UncheckedIOException when the engine's
     * own I/O fails, which proves nothing about the APK.
     */
    String verify(byte[] apk, byte[] idsig, Manifest m) {
        if (!m.certificate.equals(role.certificate) || !m.key.equals(role.key)) return "not the platform role";
        Verification v = engine.verify(apk, idsig, m.sdkMin, m.sdkMax);
        if (!v.v2BelowSdk28) return "v2 does not verify below SDK 28";
        if (!v.v3) return "v3 does not verify over the declared range";
        if (!v.v4) return "v4 does not verify over the declared range";
        if (v.signers.isEmpty()) return "no signer";
        for (String[] s : v.signers) {
            if (!s[0].equals(role.certificate) || !s[1].equals(role.key)) return "a signer without the platform role";
        }
        try {
            if (!ApkEntries.digest(apk).equals(m.inputEntries)) return "entries other than the input's";
        } catch (IllegalArgumentException notZip) {
            return "not a ZIP archive";
        }
        return null;
    }

    // ------------------------------------------------------------------ publication

    @Override
    public Observation publish(Ticket ticket, Plan plan, Entry entry) {
        List<Role> roles = new ArrayList<>(List.of(Role.VARIANT));
        if (plan.hasRestoration()) roles.add(Role.RESTORATION);
        Map<Role, Staged> chosen = new EnumMap<>(Role.class);
        if (plan.signing > 0) {
            // Exactly the bundles of this ticket's own SIGN requests, whose IDs are their transactions.
            for (Entry e : ticket.ledger) {
                if (e.crossing != Crossing.SIGN) continue;
                Transaction t = signer.read(e.reference);
                if (t == null || t.state != TransactionState.COMPLETED) continue;
                for (Role r : t.roles()) {
                    Staged s = store.held(ArtifactRecords.bundleId(manifest(t, r)));
                    if (s != null) chosen.put(r, s);
                }
            }
        } else {
            // Decision 3's restoration plan: the restoration that the repaired plan's publication bound.
            Publication repaired = store.publication(plan.repairs);
            Staged s = repaired == null || repaired.bundles.size() != 2 ? null : store.held(repaired.bundles.get(1));
            if (s != null) chosen.put(Role.VARIANT, s);
        }
        List<Staged> staged = new ArrayList<>();
        List<String> bundles = new ArrayList<>();
        List<String> transactions = new ArrayList<>();
        for (Role r : roles) {
            Staged s = chosen.get(r);
            if (s == null) return bundleFact(plan, entry.reference); // Never one bundle alone.
            staged.add(s);
            bundles.add(s.id);
            transactions.add(s.manifest.transaction);
        }
        Publication publication = new Publication(installation, plan.planId, plan.component, bundles, transactions,
                wall.getAsLong());
        store.publish(plan, publication, staged, b -> verify(b.apk(), b.idsig(), b.manifest));
        return bundleFact(plan, entry.reference);
    }

    // The store's read of the plan's publication, naming the attempt it follows and, when it reads
    // PUBLISHED, the APKs the publication binds. An unreadable record gives no fact.
    private Observation bundleFact(Plan plan, String attempt) {
        Presence presence = store.planPublication(plan.planId);
        if (presence == Presence.UNAVAILABLE) return null;
        if (presence == Presence.PUBLISHED) {
            Publication p = store.publication(plan.planId);
            List<String> apks = store.apks(plan.planId);
            if (p == null || apks == null) return null;
            String digest = DeploymentRecords.sha256Hex(ArtifactRecords.encodePublication(p));
            return hostFact(plan, Classification.BUNDLE_PUBLISHED, digest).subject(attempt).plan(plan.planId)
                    .digest(digest).apks(apks.get(0), apks.size() > 1 ? apks.get(1) : NO_DIGEST).build();
        }
        Classification c = presence == Presence.ABSENT ? Classification.BUNDLE_ABSENT : Classification.BUNDLE_MISMATCH;
        String raw = DeploymentRecords.sha256Hex((c + " " + plan.planId).getBytes(StandardCharsets.US_ASCII));
        return hostFact(plan, c, raw).subject(attempt).plan(plan.planId).build();
    }

    // ------------------------------------------------------------------ reads

    /**
     * Reads each SIGN request of the ticket by its ID while signing is open, never signing again,
     * and the plan's publication after the ticket's last PUBLISH attempt, in every later state. A
     * request without a record, or one left OPEN, can no longer complete, and the read records that
     * proof. A request without a record is recorded with the roles and inputs of the grant its entry
     * names.
     */
    @Override
    public List<Observation> query(Ticket ticket, Plan plan, List<Authorization> grants) {
        List<Observation> list = new ArrayList<>();
        boolean signing = ticket.state == State.SIGNING || ticket.state == State.SIGNED
                || ticket.state == State.AUTHORIZED;
        for (Entry e : ticket.ledger) {
            if (!signing || e.crossing != Crossing.SIGN) continue;
            Authorization grant = null;
            for (Authorization a : grants) if (a.authorizationId.equals(e.grant)) grant = a;
            Transaction template = grant == null ? null
                    : template(plan, grant.authorizationId, roles(grant), e.reference, new EnumMap<>(Role.class));
            HostSigner.Reply reply = signer.query(e.reference, template);
            if (reply == null) continue;
            Observation fact = signerFact(plan, reply.record);
            if (fact != null) list.add(fact);
        }
        Entry attempt = ticket.last(Crossing.PUBLISH);
        if (attempt != null) {
            Observation fact = bundleFact(plan, attempt.reference);
            if (fact != null) list.add(fact);
        }
        return list;
    }

    private Observation.Builder hostFact(Plan plan, Classification c, String raw) {
        return new Observation.Builder().installation(installation).observationId(ids.get()).component(plan.component)
                .boot(NO_ID).route(Route.HOST).at(-1, 0, wall.getAsLong()).raw(raw).classification(c);
    }
}
