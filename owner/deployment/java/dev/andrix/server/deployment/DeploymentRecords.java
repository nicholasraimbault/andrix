// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The five deployment record kinds of the first durable component transaction and their binary
 * encoding, version 1 of each: {@link Plan}, {@link Authorization}, {@link Ticket},
 * {@link Observation} and {@link Selection}. The layout is documented in
 * owner/deployment/README.md, which the independent encoder of the runner follows.
 *
 * <p>This class only defines values and bytes. It performs no I/O, issues no native call and
 * grants nothing. A decoded record is well formed, not current or trusted. Reconciliation
 * compares it with the other records and with observations before anything relies on it.
 *
 * <p>Every record has one frame: u32 magic 0x52445841 ("AXDR" in file order), u16 type (1 plan,
 * 2 authorization, 3 ticket, 4 observation, 5 selection), u16 version, u32 total length, the
 * body, then the SHA-256 of all preceding bytes. Integers are fixed width and little endian. An
 * ID is 16 raw bytes and a digest 32. Text is a u16 length and that many printable ASCII bytes.
 * Each body begins with its kind's stable prefix, which every later version keeps:
 * <pre>
 * plan           installation, plan ID, component
 * authorization  installation, authorization ID, component, plan ID
 * ticket         installation, ticket ID, component, plan ID, i32 attempt
 * observation    installation, observation ID, component or empty, boot ID, i32 user, i64 serial
 * selection      installation, component, i64 revision
 * </pre>
 * {@link #decodePrefix} reads the prefix of an intact frame of a later version as negative
 * evidence only: it tells what the record concerns, so a reader can fail closed, and yields no
 * value.
 *
 * <p>Each valid value has exactly one encoding, and decoding accepts nothing else. Decoding
 * checks the size, frame, checksum, version, strict text, every field rule and bound, every
 * relation between fields, and the absence of trailing bytes. It never repairs input. Malformed
 * input throws {@link IllegalArgumentException} and null throws {@link NullPointerException}.
 * Messages do not repeat input values. Strict fields refuse unknown codes. Informational fields
 * accept any value and decide nothing: a plan's creation time, a ledger entry's issue time, an
 * observation's wall time and a selection's change time never carry authority, expiry or
 * discharge. An authorization's grant time is strict, because it decides an ACTIVATE's expiry.
 * The checksum detects accidental damage only. It is not authenticity.
 */
public final class DeploymentRecords {
    /** Largest accepted encoding of any record, in bytes. */
    public static final int MAX_BYTES = 65536;
    /** The one version of every kind that this codec reads and writes. */
    public static final int VERSION = 1;
    /** The user value of an observation of the boot or the device: Android's USER_NULL. */
    public static final int NO_USER = -10000;
    /** The serial that goes with {@link #NO_USER}. */
    public static final long NO_SERIAL = -1;
    /** The all zero ID: no reference. Never a record ID. */
    public static final String NO_ID = "0".repeat(32);
    /** The all zero digest: no bundle. Never a record digest. */
    public static final String NO_DIGEST = "0".repeat(64);
    /** Most users with a health outcome in one ticket. */
    public static final int MAX_USERS = 64;
    /** Largest boot limit a plan may state. */
    public static final int MAX_BOOT_LIMIT = 32;
    /** Largest request limit a plan may state. */
    public static final int MAX_REQUEST_LIMIT = 16;
    /** Most ledger entries of one ticket: the sum of the per crossing bounds. */
    public static final int MAX_LEDGER;
    /** Longest text field, in bytes. */
    public static final int MAX_TEXT = 255;

    static final int MAGIC = 0x52445841; // "AXDR" in file order.
    static final int FRAME_BYTES = 12;
    static final int CHECKSUM_BYTES = 32;
    private static final int LENGTH_OFFSET = 8;
    private static final int ID_BYTES = 16;
    private static final int DIGEST_BYTES = 32;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** The record kinds and their frame type codes. */
    public enum Kind {
        PLAN(1), AUTHORIZATION(2), TICKET(3), OBSERVATION(4), SELECTION(5);

        final int code;

        Kind(int code) { this.code = code; }

        static Kind of(int code) {
            for (Kind kind : values()) if (kind.code == code) return kind;
            return null;
        }
    }

    // ------------------------------------------------------------------ strict codes

    /** How a component is installed. Version 1 coordinates STAGED_SYSTEM_APK only. */
    public enum ComponentClass {
        STAGED_SYSTEM_APK(1), STAGED_APEX(2), NONSTAGED_APK(3);
        final int code;
        ComponentClass(int code) { this.code = code; }
    }

    /**
     * What a plan does: choose its bundle, choose the factory copy, or stand in for the chosen
     * variant with the new image's factory source while the variant is rebuilt (decision 6).
     */
    public enum Target {
        VARIANT(1), FACTORY(2), TEMPORARY_FACTORY(3);
        final int code;
        Target(int code) { this.code = code; }
    }

    /** Who runs the component's code. Shared code affects all users. */
    public enum AffectedUsers {
        ALL_USERS(1);
        final int code;
        AffectedUsers(int code) { this.code = code; }
    }

    /** The plan's data transition. The first plan declares it forward only. */
    public enum DataTransition {
        FORWARD_ONLY(1);
        final int code;
        DataTransition(int code) { this.code = code; }
    }

    /** Decision 2: when commit happens relative to the owner's activation. */
    public enum CommitMode {
        LATE(1), EARLY(2);
        final int code;
        CommitMode(int code) { this.code = code; }
    }

    /** Decision 3, health response: report and wait, or restore from the restoration bundle. */
    public enum HealthResponse {
        REPORT_AND_WAIT(1), RESTORE_AUTOMATICALLY(2);
        final int code;
        HealthResponse(int code) { this.code = code; }
    }

    /** The plan's recovery route. */
    public enum RecoveryRoute {
        HOST_SHELL(1), DEVICE_COORDINATOR(2);
        final int code;
        RecoveryRoute(int code) { this.code = code; }
    }

    /** The health criteria of the plan's Definitions, as bits of the criteria mask. */
    public enum Criterion {
        UID_AND_CONTEXT(0), NO_CRASH_OR_ANR(1), UI_MARKER(2), UNLOCK_AND_CE(3), BYTES_UNCHANGED(4),
        NATIVE_WORK(5), RECOVERY_ROUTE(6);
        final int bit;
        Criterion(int bit) { this.bit = bit; }
        /** Every defined criterion. */
        public static final int ALL = 0x7f;
    }

    /**
     * What one authorization grants. Each grant is its own record. EMERGENCY_NOTICE is decision
     * 7's explicit emergency policy, which the installation grant does not imply.
     */
    public enum Effect {
        SIGN(1), STAGE(2), ACTIVATE(3), SELECT(4), EMERGENCY_NOTICE(5);
        final int code;
        Effect(int code) { this.code = code; }
    }

    /** The SIGN inputs bits: the variant and its restoration. */
    public static final int INPUT_VARIANT = 1;
    /** See {@link #INPUT_VARIANT}. */
    public static final int INPUT_RESTORATION = 2;

    /** Who granted an authorization. */
    public enum ActorClass {
        GRANT_HOLDER(1), LAB_OPERATOR(2);
        final int code;
        ActorClass(int code) { this.code = code; }
    }

    /** Decision 1: the component scope of the installation grant an actor held. */
    public enum GrantScope {
        /** No installation grant: the lab operator stands in for it. */
        NONE(0),
        /** The grant over every component, normally the owner's. */
        ALL_COMPONENTS(1),
        /** The grant delegated for this record's component only. */
        ONE_COMPONENT(2);
        final int code;
        GrantScope(int code) { this.code = code; }
    }

    /** Where the owning coordinator runs. */
    public enum CoordinatorClass {
        HOST(1), DEVICE(2);
        final int code;
        CoordinatorClass(int code) { this.code = code; }
    }

    /** The ticket states of the plan's table, terminal ones last. */
    public enum State {
        PLANNED(1), AUTHORIZED(2), SIGNING(3), SIGNED(4), PUBLISHED(5), SESSION_INTENT(6),
        SESSION_BOUND(7), WRITTEN(8), COMMIT_INTENT(9), READY(10), READY_AGAIN(11), REBOOT_INTENT(12),
        ABANDON_INTENT(13), BOOT_OBSERVED(14), APPLIED_PROVISIONAL(15), APPLIED(16), HEALTH_WINDOW(17),
        SIGN_FAILED(18), NO_SESSION(19), ABANDONED(20), FAILED_NATIVE(21), NATIVE_RECORD_LOST(22),
        CLOSED_APPLIED(23), CLOSED_FAILED(24), CANCELLED(25), VOID(26), DIVERGED(27), SUPERSEDED(28);

        final int code;

        State(int code) { this.code = code; }

        /** The terminal states: CLOSED_APPLIED, CLOSED_FAILED, CANCELLED, VOID, DIVERGED, SUPERSEDED. */
        public boolean terminal() { return code >= CLOSED_APPLIED.code; }

        /** The intent states, which carry the UNRESOLVED flag when their reply is lost. */
        public boolean intent() {
            return this == SIGNING || this == SESSION_INTENT || this == COMMIT_INTENT
                    || this == ABANDON_INTENT || this == REBOOT_INTENT;
        }
    }

    /** Ticket flag: the current intent's reply was lost or ambiguous. */
    public static final int FLAG_UNRESOLVED = 1;
    /** Ticket flag: the boot limit was reached. The owner is alerted. */
    public static final int FLAG_BOOT_LIMIT = 2;
    /** Ticket flag: a request limit was reached while the ticket holds. The owner is alerted. */
    public static final int FLAG_REQUEST_LIMIT = 4;

    /**
     * Why a ticket stops, recorded at once and effective once any intent resolves. A later cause
     * replaces a recorded one only when its code is higher.
     */
    public enum Cause {
        NONE(0), CANCELLED(1), VOID_SELECTION(2), VOID_TRUST(3), VOID_TARGET(4), VOID_BASE(5),
        OTHER_BYTES(6);
        final int code;
        Cause(int code) { this.code = code; }
        /** A cause that voids the plan. */
        public boolean voids() { return code >= VOID_SELECTION.code && code <= VOID_BASE.code; }
    }

    /** One user's health outcome, bound by serial. OBSERVING only while the window runs. */
    public enum Outcome {
        OBSERVING(0), HEALTHY(1), DEGRADED(2), UNHEALTHY(3), INCONCLUSIVE(4), REMOVED(5);
        final int code;
        Outcome(int code) { this.code = code; }
    }

    /** The crossings a ticket's ledger records, each written and synced before it is issued. */
    public enum Crossing {
        SIGN(1, 2), PUBLISH(2, 2), CREATE(3, 1), WRITE(4, 1), COMMIT(5, 1), ABANDON(6, 16),
        REBOOT(7, 16), NOTICE(8, 17), HANDOVER(9, 4);

        final int code;
        /** Most entries of this crossing in one ledger. */
        final int bound;

        Crossing(int code, int bound) {
            this.code = code;
            this.bound = bound;
        }

        /** A call into Android's package machinery through a framework instance. */
        public boolean framework() {
            return this == CREATE || this == WRITE || this == COMMIT || this == ABANDON;
        }

        /** A crossing into the device: the framework calls, the reboot and the notice. */
        public boolean device() { return framework() || this == REBOOT || this == NOTICE; }
    }

    static {
        int total = 0;
        for (Crossing crossing : Crossing.values()) total += crossing.bound;
        MAX_LEDGER = total;
    }

    /** What an observation records. */
    public enum ObservationKind {
        BOOT(1), CHECKPOINT(2), FACTORY(3), ACTIVE(4), LISTING(5), SESSION(6), REPLY(7), USER(8),
        HEALTH(9), SIGNER(10), BUNDLE(11);
        final int code;
        ObservationKind(int code) { this.code = code; }
    }

    /** How an observation was read. */
    public enum Route {
        SHELL(1), DEVICE(2), HOST(3);
        final int code;
        Route(int code) { this.code = code; }
    }

    /** Every classification, by kind. A code is strict within its kind. */
    public enum Classification {
        BOOTING(ObservationKind.BOOT, 1), BOOT_COMPLETED(ObservationKind.BOOT, 2),
        CHECKPOINT_PENDING(ObservationKind.CHECKPOINT, 1),
        CHECKPOINT_COMMITTED(ObservationKind.CHECKPOINT, 2),
        FACTORY_PRESENT(ObservationKind.FACTORY, 1),
        FACTORY_COPY(ObservationKind.ACTIVE, 1), DATA_COPY(ObservationKind.ACTIVE, 2),
        NONE_FOR_PACKAGE(ObservationKind.LISTING, 1), SESSIONS_FOR_PACKAGE(ObservationKind.LISTING, 2),
        LISTING_INCOMPLETE(ObservationKind.LISTING, 3),
        OPEN(ObservationKind.SESSION, 1), SEALED(ObservationKind.SESSION, 2),
        VERIFYING(ObservationKind.SESSION, 3), LIVE_NOT_READY(ObservationKind.SESSION, 4),
        SESSION_READY(ObservationKind.SESSION, 5), SESSION_APPLIED(ObservationKind.SESSION, 6),
        SESSION_FAILED(ObservationKind.SESSION, 7), SESSION_ABANDONED(ObservationKind.SESSION, 8),
        SESSION_REFUSED(ObservationKind.SESSION, 9),
        REPLY_SUCCESS(ObservationKind.REPLY, 1), REPLY_REFUSED(ObservationKind.REPLY, 2),
        REPLY_READY(ObservationKind.REPLY, 3), REPLY_ACCEPTED(ObservationKind.REPLY, 4),
        REPLY_PENDING(ObservationKind.REPLY, 5), REPLY_UNRECOGNIZED(ObservationKind.REPLY, 6),
        RUNNING_UNLOCKED(ObservationKind.USER, 1), RUNNING_LOCKED(ObservationKind.USER, 2),
        NOT_RUNNING(ObservationKind.USER, 3), USER_REMOVED(ObservationKind.USER, 4),
        HEALTH_HELD(ObservationKind.HEALTH, 1), HEALTH_DEGRADED(ObservationKind.HEALTH, 2),
        HEALTH_CRASH(ObservationKind.HEALTH, 3), HEALTH_INCONCLUSIVE(ObservationKind.HEALTH, 4),
        SIGN_PENDING(ObservationKind.SIGNER, 1), SIGN_COMPLETED(ObservationKind.SIGNER, 2),
        SIGN_REFUSED(ObservationKind.SIGNER, 3), SIGN_CANNOT_COMPLETE(ObservationKind.SIGNER, 4),
        BUNDLE_PUBLISHED(ObservationKind.BUNDLE, 1), BUNDLE_ABSENT(ObservationKind.BUNDLE, 2),
        BUNDLE_MISMATCH(ObservationKind.BUNDLE, 3);

        final ObservationKind kind;
        final int code;

        Classification(ObservationKind kind, int code) {
            this.kind = kind;
            this.code = code;
        }

        /** A session observation of a session that is not terminal. */
        public boolean live() {
            return this == OPEN || this == SEALED || this == VERIFYING || this == LIVE_NOT_READY
                    || this == SESSION_READY;
        }
    }

    /** What the owner chose for a component. */
    public enum ChoiceKind {
        FACTORY(1), PLAN(2);
        final int code;
        ChoiceKind(int code) { this.code = code; }
    }

    /**
     * Decision 6: how the choice stays current across image updates. REBUILD_WINDOW holds an
     * image update for the selection's declared window while the variant is rebuilt. KEEP_STALE
     * keeps the old variant knowingly as a stale base.
     */
    public enum UpdateResponsibility {
        REBUILD_WINDOW(1), KEEP_STALE(2);
        final int code;
        UpdateResponsibility(int code) { this.code = code; }
    }

    /**
     * How the active bytes relate to the choice, set by the cohort check at each kernel boot.
     * TEMPORARY_FACTORY is decision 6's owner approved stand in from the new image's factory
     * source, while the choice stays the variant. DISPLACED is Android's removal of the chosen
     * bytes. Neither changes the choice.
     */
    public enum Realization {
        UNCHECKED(1), CURRENT(2), STALE_BASE(3), DISPLACED(4), DIVERGED(5), TEMPORARY_FACTORY(6);
        final int code;
        Realization(int code) { this.code = code; }
    }

    // ------------------------------------------------------------------ values

    /**
     * A native session reference: the session ID, createdMillis, the stage directory, the
     * installer UID and the ticket nonce carried in the referrer. Each field is present or
     * absent, because each readback route reads only some of them. Absent fields are zero or
     * empty.
     */
    public static final class Reference {
        static final int SESSION = 1, CREATED = 2, STAGE_DIR = 4, INSTALLER = 8, NONCE = 16;
        private static final int ALL = 31;
        /** Nothing known. */
        public static final Reference NONE = new Reference(0, 0, 0, "", 0, NO_ID);

        /** Bits of the fields that are present. */
        public final int presence;
        /** Positive when present. */
        public final int sessionId;
        /** Not negative when present. */
        public final long createdMillis;
        /** One to MAX_TEXT printable bytes when present. */
        public final String stageDir;
        /** Not negative when present. */
        public final int installerUid;
        /** Nonzero when present. */
        public final String nonce;

        public Reference(int presence, int sessionId, long createdMillis, String stageDir, int installerUid,
                String nonce) {
            if ((presence & ~ALL) != 0) throw invalid("unknown reference presence bits");
            this.presence = presence;
            this.sessionId = sessionId;
            this.createdMillis = createdMillis;
            this.stageDir = Objects.requireNonNull(stageDir, "stageDir");
            this.installerUid = installerUid;
            this.nonce = Objects.requireNonNull(nonce, "nonce");
            checkId(nonce, "nonce", true);
            if (has(SESSION) ? sessionId <= 0 : sessionId != 0) throw invalid("session ID and its presence differ");
            if (has(CREATED) ? createdMillis < 0 : createdMillis != 0) {
                throw invalid("createdMillis and its presence differ");
            }
            if (has(STAGE_DIR)) {
                checkText(stageDir, 1, "stage directory");
            } else if (!stageDir.isEmpty()) {
                throw invalid("stage directory and its presence differ");
            }
            if (has(INSTALLER) ? installerUid < 0 : installerUid != 0) {
                throw invalid("installer UID and its presence differ");
            }
            if (has(NONCE) == nonce.equals(NO_ID)) throw invalid("nonce and its presence differ");
        }

        public boolean has(int field) { return (presence & field) != 0; }

        /** The same reference with the nonce of a ticket set. */
        public Reference withNonce(String value) {
            return new Reference(presence | NONCE, sessionId, createdMillis, stageDir, installerUid, value);
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Reference)) return false;
            Reference that = (Reference) other;
            return presence == that.presence && sessionId == that.sessionId && createdMillis == that.createdMillis
                    && stageDir.equals(that.stageDir) && installerUid == that.installerUid && nonce.equals(that.nonce);
        }

        @Override
        public int hashCode() {
            return Objects.hash(presence, sessionId, createdMillis, stageDir, installerUid, nonce);
        }

        @Override
        public String toString() {
            return "Reference{presence=" + presence + "}";
        }
    }

    /**
     * An immutable deployment plan. Build one with {@link Plan.Builder}, which validates every
     * field and relation. The plan names the signing inputs of its bundle and restoration, never
     * their bundle IDs: a bundle ID covers the signed bytes that the plan's own signing produces,
     * so the plan's publication record binds the produced bundles to it instead. It copies the
     * facts the cohort check needs: each APK's digest and versionCode, the signer, and the native
     * base, which is the cohort (fingerprint and factory APK) with the bytes, UID and context
     * active when the plan was made.
     */
    public static final class Plan {
        public final String installation;
        public final String planId;
        public final String component;
        public final ComponentClass componentClass;
        public final Target target;
        /** The plan this one repairs or replaces, or NO_ID. */
        public final String repairs;
        /** The variant's signing input: the SHA-256 over its ZIP entries outside the signing block. */
        public final String bundleInput;
        /** The APK digest the cohort check compares with the active bytes. */
        public final String bundleApk;
        public final long bundleVersion;
        public final String signer;
        /** The restoration's signing input, as for the variant, or NO_DIGEST. */
        public final String restorationInput;
        public final String restorationApk;
        public final long restorationVersion;
        /** Signing transactions: 0 when the bundles are already signed, 1 or 2 (decision 8). */
        public final int signing;
        public final String fingerprint;
        public final String factoryApk;
        public final long factoryVersion;
        public final String baseApk;
        public final long baseVersion;
        public final int baseUid;
        public final String baseContext;
        public final AffectedUsers users;
        public final DataTransition data;
        public final long selectionRevision;
        public final String trustPolicy;
        public final CommitMode commitMode;
        public final int criteria;
        public final long healthWindowMillis;
        public final HealthResponse healthResponse;
        /** Decision 3: the restoration plan approved up front, exactly for RESTORE_AUTOMATICALLY. */
        public final String restorationPlan;
        public final RecoveryRoute recoveryRoute;
        /** Decision 7: the declared delay other running users get after notice. */
        public final long noticeDelayMillis;
        /** A shorter delay for a restoration, only under an emergency policy and an undelivered notice. */
        public final long emergencyNoticeMillis;
        public final int bootLimit;
        public final long rebootTimeLimitMillis;
        public final int requestLimit;
        public final long activateWindowMillis;
        public final long verificationWaitMillis;
        /** Informational wall clock milliseconds. Decides nothing. */
        public final long createdAt;

        private Plan(Builder b) {
            installation = b.installation;
            planId = b.planId;
            component = b.component;
            componentClass = Objects.requireNonNull(b.componentClass, "componentClass");
            target = Objects.requireNonNull(b.target, "target");
            repairs = b.repairs;
            bundleInput = b.bundleInput;
            bundleApk = b.bundleApk;
            bundleVersion = b.bundleVersion;
            signer = b.signer;
            restorationInput = b.restorationInput;
            restorationApk = b.restorationApk;
            restorationVersion = b.restorationVersion;
            signing = b.signing;
            fingerprint = b.fingerprint;
            factoryApk = b.factoryApk;
            factoryVersion = b.factoryVersion;
            baseApk = b.baseApk;
            baseVersion = b.baseVersion;
            baseUid = b.baseUid;
            baseContext = b.baseContext;
            users = Objects.requireNonNull(b.users, "users");
            data = Objects.requireNonNull(b.data, "data");
            selectionRevision = b.selectionRevision;
            trustPolicy = b.trustPolicy;
            commitMode = Objects.requireNonNull(b.commitMode, "commitMode");
            criteria = b.criteria;
            healthWindowMillis = b.healthWindowMillis;
            healthResponse = Objects.requireNonNull(b.healthResponse, "healthResponse");
            restorationPlan = b.restorationPlan;
            recoveryRoute = Objects.requireNonNull(b.recoveryRoute, "recoveryRoute");
            noticeDelayMillis = b.noticeDelayMillis;
            emergencyNoticeMillis = b.emergencyNoticeMillis;
            bootLimit = b.bootLimit;
            rebootTimeLimitMillis = b.rebootTimeLimitMillis;
            requestLimit = b.requestLimit;
            activateWindowMillis = b.activateWindowMillis;
            verificationWaitMillis = b.verificationWaitMillis;
            createdAt = b.createdAt;
            validate();
        }

        private void validate() {
            checkId(installation, "installation", false);
            checkId(planId, "plan ID", false);
            checkPackage(component);
            checkId(repairs, "repairs", true);
            if (repairs.equals(planId)) throw invalid("a plan cannot repair itself");
            checkDigest(bundleInput, "bundle input", true);
            checkDigest(bundleApk, "bundle APK", true);
            checkDigest(signer, "signer", true);
            checkDigest(restorationInput, "restoration input", true);
            checkDigest(restorationApk, "restoration APK", true);
            checkText(fingerprint, 1, "fingerprint");
            checkDigest(factoryApk, "factory APK", false);
            checkDigest(baseApk, "base APK", false);
            checkText(baseContext, 1, "base context");
            checkDigest(trustPolicy, "trust policy", false);
            if (factoryVersion < 0) throw invalid("negative factory versionCode");
            if (baseVersion < factoryVersion) throw invalid("base versionCode below the factory copy");
            if (baseApk.equals(factoryApk) && baseVersion != factoryVersion) {
                throw invalid("the factory bytes with another versionCode");
            }
            if (baseUid < 0) throw invalid("negative base UID");
            if (selectionRevision < 0) throw invalid("negative selection revision");
            boolean hasRestoration = !restorationInput.equals(NO_DIGEST);
            if (hasRestoration == restorationApk.equals(NO_DIGEST)) {
                throw invalid("restoration and its APK differ in presence");
            }
            if (target == Target.FACTORY) {
                if (!bundleInput.equals(NO_DIGEST) || !bundleApk.equals(NO_DIGEST) || bundleVersion != 0
                        || !signer.equals(NO_DIGEST) || hasRestoration || restorationVersion != 0 || signing != 0) {
                    throw invalid("a factory plan names no bundle");
                }
                if (!baseApk.equals(factoryApk)) throw invalid("a factory plan needs the factory copy active");
            } else {
                if (bundleInput.equals(NO_DIGEST) || bundleApk.equals(NO_DIGEST) || signer.equals(NO_DIGEST)) {
                    throw invalid("a variant plan names its bundle input, APK and signer");
                }
                if (bundleVersion <= factoryVersion || bundleVersion <= baseVersion) {
                    throw invalid("bundle versionCode not above the factory and base copies");
                }
                if (hasRestoration ? restorationVersion <= bundleVersion : restorationVersion != 0) {
                    throw invalid("restoration versionCode not above the bundle");
                }
                if (signing < 0 || signing > 2 || (signing == 2 && !hasRestoration)) {
                    throw invalid("signing transactions outside 0..2 or two without a restoration");
                }
                if (bundleInput.equals(restorationInput) || bundleApk.equals(restorationApk)) {
                    throw invalid("restoration equals the bundle");
                }
                if (target == Target.TEMPORARY_FACTORY && repairs.equals(NO_ID)) {
                    throw invalid("a temporary factory plan stands in for the plan it names");
                }
            }
            if (criteria == 0 || (criteria & ~Criterion.ALL) != 0) {
                throw invalid("health criteria outside the defined set");
            }
            if (healthWindowMillis <= 0) throw invalid("health window not positive");
            if (healthResponse == HealthResponse.RESTORE_AUTOMATICALLY && !hasRestoration) {
                throw invalid("automatic restoration without a restoration bundle");
            }
            if (noticeDelayMillis < 0 || emergencyNoticeMillis < 0 || emergencyNoticeMillis > noticeDelayMillis) {
                throw invalid("notice delays outside 0..noticeDelay");
            }
            if (emergencyNoticeMillis < noticeDelayMillis && repairs.equals(NO_ID)) {
                throw invalid("a shorter emergency notice only for a restoration");
            }
            if (emergencyNoticeMillis < noticeDelayMillis && target == Target.TEMPORARY_FACTORY) {
                throw invalid("a temporary factory plan is no restoration and has no shorter notice");
            }
            checkId(restorationPlan, "restoration plan", true);
            if ((healthResponse == HealthResponse.RESTORE_AUTOMATICALLY) == restorationPlan.equals(NO_ID)) {
                throw invalid("a restoration plan exactly for automatic restoration");
            }
            if (restorationPlan.equals(planId) || (!restorationPlan.equals(NO_ID) && restorationPlan.equals(repairs))) {
                throw invalid("the restoration plan is another plan");
            }
            if (bootLimit < 1 || bootLimit > MAX_BOOT_LIMIT) throw invalid("boot limit outside 1..MAX_BOOT_LIMIT");
            if (requestLimit < 1 || requestLimit > MAX_REQUEST_LIMIT) {
                throw invalid("request limit outside 1..MAX_REQUEST_LIMIT");
            }
            if (rebootTimeLimitMillis <= 0 || activateWindowMillis <= 0 || verificationWaitMillis <= 0) {
                throw invalid("time limits must be positive");
            }
        }

        /** Whether the plan names a restoration. */
        public boolean hasRestoration() { return !restorationInput.equals(NO_DIGEST); }

        public Builder toBuilder() { return new Builder(this); }

        @Override
        public boolean equals(Object other) {
            return other instanceof Plan && Arrays.equals(encodePlan(this), encodePlan((Plan) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodePlan(this)); }

        @Override
        public String toString() {
            return "Plan{" + component + ", " + componentClass + ", " + target + ", " + commitMode + ", signing="
                    + signing + "}";
        }

        /** A mutable builder. {@link #build} validates. */
        public static final class Builder {
            String installation = NO_ID, planId = NO_ID, component = "";
            ComponentClass componentClass = ComponentClass.STAGED_SYSTEM_APK;
            Target target = Target.VARIANT;
            String repairs = NO_ID, bundleInput = NO_DIGEST, bundleApk = NO_DIGEST, signer = NO_DIGEST;
            long bundleVersion;
            String restorationInput = NO_DIGEST, restorationApk = NO_DIGEST;
            long restorationVersion;
            int signing;
            String fingerprint = "", factoryApk = NO_DIGEST, baseApk = NO_DIGEST, baseContext = "";
            long factoryVersion, baseVersion;
            int baseUid;
            AffectedUsers users = AffectedUsers.ALL_USERS;
            DataTransition data = DataTransition.FORWARD_ONLY;
            long selectionRevision;
            String trustPolicy = NO_DIGEST;
            CommitMode commitMode = CommitMode.LATE;
            int criteria = Criterion.ALL;
            long healthWindowMillis;
            HealthResponse healthResponse = HealthResponse.REPORT_AND_WAIT;
            RecoveryRoute recoveryRoute = RecoveryRoute.HOST_SHELL;
            long noticeDelayMillis, emergencyNoticeMillis;
            String restorationPlan = NO_ID;
            int bootLimit, requestLimit;
            long rebootTimeLimitMillis, activateWindowMillis, verificationWaitMillis, createdAt;

            public Builder() {}

            Builder(Plan p) {
                installation = p.installation; planId = p.planId; component = p.component;
                componentClass = p.componentClass; target = p.target; repairs = p.repairs; bundleInput = p.bundleInput;
                bundleApk = p.bundleApk; bundleVersion = p.bundleVersion; signer = p.signer;
                restorationInput = p.restorationInput; restorationApk = p.restorationApk;
                restorationVersion = p.restorationVersion; signing = p.signing; fingerprint = p.fingerprint;
                factoryApk = p.factoryApk; factoryVersion = p.factoryVersion; baseApk = p.baseApk;
                baseVersion = p.baseVersion; baseUid = p.baseUid; baseContext = p.baseContext; users = p.users;
                data = p.data; selectionRevision = p.selectionRevision; trustPolicy = p.trustPolicy;
                commitMode = p.commitMode; criteria = p.criteria; healthWindowMillis = p.healthWindowMillis;
                healthResponse = p.healthResponse; recoveryRoute = p.recoveryRoute;
                restorationPlan = p.restorationPlan; noticeDelayMillis = p.noticeDelayMillis;
                emergencyNoticeMillis = p.emergencyNoticeMillis; bootLimit = p.bootLimit;
                rebootTimeLimitMillis = p.rebootTimeLimitMillis; requestLimit = p.requestLimit;
                activateWindowMillis = p.activateWindowMillis; verificationWaitMillis = p.verificationWaitMillis;
                createdAt = p.createdAt;
            }

            public Builder installation(String v) { installation = v; return this; }
            public Builder planId(String v) { planId = v; return this; }
            public Builder component(String v) { component = v; return this; }
            public Builder componentClass(ComponentClass v) { componentClass = v; return this; }
            public Builder target(Target v) { target = v; return this; }
            public Builder repairs(String v) { repairs = v; return this; }
            public Builder bundle(String input, String apk, long version) {
                bundleInput = input; bundleApk = apk; bundleVersion = version; return this;
            }
            public Builder signer(String v) { signer = v; return this; }
            public Builder restoration(String input, String apk, long version) {
                restorationInput = input; restorationApk = apk; restorationVersion = version; return this;
            }
            public Builder signing(int v) { signing = v; return this; }
            public Builder cohort(String fingerprintValue, String factoryApkValue, long factoryVersionValue) {
                fingerprint = fingerprintValue; factoryApk = factoryApkValue; factoryVersion = factoryVersionValue;
                return this;
            }
            public Builder base(String apk, long version, int uid, String context) {
                baseApk = apk; baseVersion = version; baseUid = uid; baseContext = context; return this;
            }
            public Builder users(AffectedUsers v) { users = v; return this; }
            public Builder data(DataTransition v) { data = v; return this; }
            public Builder selectionRevision(long v) { selectionRevision = v; return this; }
            public Builder trustPolicy(String v) { trustPolicy = v; return this; }
            public Builder commitMode(CommitMode v) { commitMode = v; return this; }
            public Builder criteria(int v) { criteria = v; return this; }
            public Builder healthWindow(long v) { healthWindowMillis = v; return this; }
            public Builder healthResponse(HealthResponse v) { healthResponse = v; return this; }
            public Builder recoveryRoute(RecoveryRoute v) { recoveryRoute = v; return this; }
            public Builder notice(long delay, long emergency) {
                noticeDelayMillis = delay;
                emergencyNoticeMillis = emergency;
                return this;
            }
            public Builder restorationPlan(String v) { restorationPlan = v; return this; }
            public Builder limits(int boots, long rebootTime, int requests, long activateWindow,
                    long verificationWait) {
                bootLimit = boots; rebootTimeLimitMillis = rebootTime; requestLimit = requests;
                activateWindowMillis = activateWindow; verificationWaitMillis = verificationWait; return this;
            }
            public Builder createdAt(long v) { createdAt = v; return this; }

            public Plan build() {
                Objects.requireNonNull(installation, "installation");
                Objects.requireNonNull(planId, "planId");
                Objects.requireNonNull(component, "component");
                Objects.requireNonNull(repairs, "repairs");
                Objects.requireNonNull(bundleInput, "bundle");
                Objects.requireNonNull(bundleApk, "bundleApk");
                Objects.requireNonNull(signer, "signer");
                Objects.requireNonNull(restorationInput, "restoration");
                Objects.requireNonNull(restorationApk, "restorationApk");
                Objects.requireNonNull(fingerprint, "fingerprint");
                Objects.requireNonNull(factoryApk, "factoryApk");
                Objects.requireNonNull(baseApk, "baseApk");
                Objects.requireNonNull(baseContext, "baseContext");
                Objects.requireNonNull(trustPolicy, "trustPolicy");
                Objects.requireNonNull(restorationPlan, "restorationPlan");
                return new Plan(this);
            }
        }
    }

    /** One append only grant for one plan. Each grant is its own record. */
    public static final class Authorization {
        public final String installation;
        public final String authorizationId;
        public final String component;
        public final String planId;
        public final Effect effect;
        /** SIGN only: INPUT_VARIANT, INPUT_RESTORATION or both. Zero for every other effect. */
        public final int inputs;
        public final ActorClass actorClass;
        public final int actorUser;
        public final long actorSerial;
        /** The installation grant held, nonzero exactly for GRANT_HOLDER. */
        public final String grant;
        /** The grant's component scope: NONE exactly without a grant. */
        public final GrantScope grantScope;
        /** The owner interaction that granted it. Grants of one interaction share it. */
        public final String interaction;
        /** Wall clock milliseconds. Strict: it decides an ACTIVATE's expiry. */
        public final long grantedAt;

        public Authorization(String installation, String authorizationId, String component, String planId,
                Effect effect, int inputs, ActorClass actorClass, int actorUser, long actorSerial, String grant,
                GrantScope grantScope, String interaction, long grantedAt) {
            this.installation = installation;
            this.authorizationId = authorizationId;
            this.component = component;
            this.planId = planId;
            this.effect = Objects.requireNonNull(effect, "effect");
            this.inputs = inputs;
            this.actorClass = Objects.requireNonNull(actorClass, "actorClass");
            this.actorUser = actorUser;
            this.actorSerial = actorSerial;
            this.grant = grant;
            this.grantScope = Objects.requireNonNull(grantScope, "grantScope");
            this.interaction = interaction;
            this.grantedAt = grantedAt;
            checkId(installation, "installation", false);
            checkId(authorizationId, "authorization ID", false);
            checkPackage(component);
            checkId(planId, "plan ID", false);
            checkId(grant, "grant", true);
            checkId(interaction, "interaction", false);
            if (effect == Effect.SIGN ? inputs < 1 || inputs > 3 : inputs != 0) {
                throw invalid("inputs exactly for SIGN");
            }
            checkActor(actorUser, actorSerial, actorClass == ActorClass.LAB_OPERATOR);
            if ((actorClass == ActorClass.GRANT_HOLDER) == grant.equals(NO_ID)) {
                throw invalid("a grant reference exactly for GRANT_HOLDER");
            }
            if ((grantScope == GrantScope.NONE) != grant.equals(NO_ID)) {
                throw invalid("a grant scope exactly with a grant");
            }
            if (grantedAt <= 0) throw invalid("grant time not positive");
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Authorization
                    && Arrays.equals(encodeAuthorization(this), encodeAuthorization((Authorization) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodeAuthorization(this)); }

        @Override
        public String toString() {
            return "Authorization{" + component + ", " + effect + ", inputs=" + inputs + ", " + actorClass + ", "
                    + grantScope + "}";
        }
    }

    /** One user's health outcome in a ticket. */
    public static final class Health {
        public final int user;
        public final long serial;
        public final Outcome outcome;

        public Health(int user, long serial, Outcome outcome) {
            this.user = user;
            this.serial = serial;
            this.outcome = Objects.requireNonNull(outcome, "outcome");
            if (user < 0 || serial < 0) throw invalid("health of a negative user or serial");
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Health)) return false;
            Health that = (Health) other;
            return user == that.user && serial == that.serial && outcome == that.outcome;
        }

        @Override
        public int hashCode() { return Objects.hash(user, serial, outcome); }

        @Override
        public String toString() { return "Health{" + user + ", " + outcome + "}"; }
    }

    /** One issued crossing. Entries never change once written. */
    public static final class Entry {
        public final Crossing crossing;
        /** The kernel boot at issue, or NO_ID for a host crossing before any boot was known. */
        public final String boot;
        /** The framework instance at issue, or -1. */
        public final long instance;
        /** Milliseconds since that boot at issue. Strict: it decides the reboot time limit. */
        public final long elapsed;
        /** The authorization relied on, nonzero exactly for SIGN, CREATE, COMMIT, REBOOT and NOTICE. */
        public final String grant;
        /**
         * SIGN: the request ID. PUBLISH: the attempt ID, which the store's reply names. CREATE: the
         * ticket nonce. HANDOVER: the new coordinator. Else NO_ID.
         */
        public final String reference;
        /** Informational wall clock milliseconds. */
        public final long issuedAt;

        public Entry(Crossing crossing, String boot, long instance, long elapsed, String grant, String reference,
                long issuedAt) {
            this.crossing = Objects.requireNonNull(crossing, "crossing");
            this.boot = boot;
            this.instance = instance;
            this.elapsed = elapsed;
            this.grant = grant;
            this.reference = reference;
            this.issuedAt = issuedAt;
            checkId(boot, "entry boot", true);
            checkId(grant, "entry grant", true);
            checkId(reference, "entry reference", true);
            if (instance < -1) throw invalid("instance below -1");
            if (elapsed < 0) throw invalid("negative elapsed time");
            if (boot.equals(NO_ID)) {
                if (crossing.device() || instance != -1 || elapsed != 0) {
                    throw invalid("a device crossing needs its boot");
                }
            }
            if (crossing.framework() && instance < 0) throw invalid("a framework crossing needs its instance");
            boolean granted = crossing == Crossing.SIGN || crossing == Crossing.CREATE || crossing == Crossing.COMMIT
                    || crossing == Crossing.REBOOT || crossing == Crossing.NOTICE;
            if (granted == grant.equals(NO_ID)) throw invalid("a grant exactly for granted crossings");
            boolean referenced = crossing == Crossing.SIGN || crossing == Crossing.PUBLISH
                    || crossing == Crossing.CREATE || crossing == Crossing.HANDOVER;
            if (referenced == reference.equals(NO_ID)) throw invalid("a reference exactly where one is named");
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Entry)) return false;
            Entry that = (Entry) other;
            return crossing == that.crossing && boot.equals(that.boot) && instance == that.instance
                    && elapsed == that.elapsed && grant.equals(that.grant) && reference.equals(that.reference)
                    && issuedAt == that.issuedAt;
        }

        @Override
        public int hashCode() { return Objects.hash(crossing, boot, instance, elapsed, grant, reference, issuedAt); }

        @Override
        public String toString() { return "Entry{" + crossing + "}"; }
    }

    /**
     * One attempt under one plan with exactly one owning coordinator. Build one with
     * {@link Ticket.Builder}. The constructor checks every field rule and the relations between
     * state, flags, cause, reference, window, successor, health outcomes and ledger that any writer
     * must keep. Legal transitions between two tickets are {@link TicketMachine}'s concern.
     */
    public static final class Ticket {
        public final String installation;
        public final String ticketId;
        public final String component;
        public final String planId;
        public final int attempt;
        public final CoordinatorClass coordinatorClass;
        public final String coordinator;
        public final State state;
        public final int flags;
        public final Cause cause;
        public final int bootCount;
        /** The last kernel boot the ticket observed, or NO_ID. */
        public final String boot;
        public final Reference reference;
        public final String windowBoot;
        public final long windowStart;
        public final String successor;
        /** Unmodifiable, ascending by user then serial. */
        public final List<Health> health;
        /** Unmodifiable, in issue order. Only grows. */
        public final List<Entry> ledger;

        private Ticket(Builder b) {
            installation = b.installation;
            ticketId = b.ticketId;
            component = b.component;
            planId = b.planId;
            attempt = b.attempt;
            coordinatorClass = Objects.requireNonNull(b.coordinatorClass, "coordinatorClass");
            coordinator = b.coordinator;
            state = Objects.requireNonNull(b.state, "state");
            flags = b.flags;
            cause = Objects.requireNonNull(b.cause, "cause");
            bootCount = b.bootCount;
            boot = b.boot;
            reference = Objects.requireNonNull(b.reference, "reference");
            windowBoot = b.windowBoot;
            windowStart = b.windowStart;
            successor = b.successor;
            health = Collections.unmodifiableList(new ArrayList<>(b.health));
            ledger = Collections.unmodifiableList(new ArrayList<>(b.ledger));
            validate();
        }

        private void validate() {
            checkId(installation, "installation", false);
            checkId(ticketId, "ticket ID", false);
            checkPackage(component);
            checkId(planId, "plan ID", false);
            if (attempt < 1) throw invalid("attempt not positive");
            checkId(coordinator, "coordinator", false);
            if ((flags & ~(FLAG_UNRESOLVED | FLAG_BOOT_LIMIT | FLAG_REQUEST_LIMIT)) != 0) {
                throw invalid("unknown ticket flags");
            }
            if ((flags & FLAG_UNRESOLVED) != 0 && !state.intent()) {
                throw invalid("UNRESOLVED outside an intent state");
            }
            if (bootCount < 0 || bootCount > 0xffff) throw invalid("boot count outside u16");
            checkId(boot, "boot", true);
            if (bootCount > 0 && boot.equals(NO_ID)) throw invalid("boots counted without a boot");
            checkId(windowBoot, "window boot", true);
            checkId(successor, "successor", true);
            boolean window = state == State.HEALTH_WINDOW;
            if (window == windowBoot.equals(NO_ID)) throw invalid("a window boot exactly in HEALTH_WINDOW");
            if (window ? windowStart < 0 : windowStart != 0) throw invalid("a window start exactly in HEALTH_WINDOW");
            if ((state == State.SUPERSEDED) == successor.equals(NO_ID)) {
                throw invalid("a successor exactly in SUPERSEDED");
            }
            if (successor.equals(planId)) throw invalid("a plan cannot supersede its own ticket");
            switch (state) {
                case CANCELLED:
                    if (cause != Cause.CANCELLED) throw invalid("CANCELLED needs its cause");
                    break;
                case VOID:
                    if (!cause.voids() && cause != Cause.OTHER_BYTES) throw invalid("VOID needs a voiding cause");
                    break;
                case DIVERGED:
                    if (cause != Cause.OTHER_BYTES) throw invalid("DIVERGED needs other bytes as its cause");
                    break;
                case CLOSED_FAILED:
                    if (cause != Cause.NONE) throw invalid("CLOSED_FAILED has no recorded cause");
                    break;
                default:
                    break;
            }
            // Health outcomes: only from APPLIED on, OBSERVING only while the window runs.
            boolean healthState = state == State.APPLIED || window || state == State.CLOSED_APPLIED
                    || state == State.SUPERSEDED || state == State.DIVERGED;
            if (!health.isEmpty() && !healthState) throw invalid("health outcomes before APPLIED");
            if (health.size() > MAX_USERS) throw invalid("more than MAX_USERS health outcomes");
            for (int i = 0; i < health.size(); i++) {
                Health h = Objects.requireNonNull(health.get(i), "health");
                if (h.outcome == Outcome.OBSERVING && state != State.APPLIED && !window) {
                    throw invalid("OBSERVING outside the window");
                }
                if (i > 0) {
                    Health before = health.get(i - 1);
                    if (h.user < before.user || (h.user == before.user && h.serial <= before.serial)) {
                        throw invalid("health outcomes out of order");
                    }
                }
            }
            validateLedger();
        }

        private void validateLedger() {
            if (ledger.size() > MAX_LEDGER) throw invalid("ledger above MAX_LEDGER");
            Map<Crossing, Integer> counts = new EnumMap<>(Crossing.class);
            int phase = 0;
            String handedTo = null;
            for (Entry entry : ledger) {
                Objects.requireNonNull(entry, "entry");
                int count = counts.merge(entry.crossing, 1, Integer::sum);
                if (count > entry.crossing.bound) throw invalid("a crossing above its bound");
                switch (entry.crossing) {
                    case SIGN: case PUBLISH: case CREATE: case WRITE: case COMMIT:
                        // The native sequence never goes back: one create, one write, one commit.
                        if (entry.crossing.code < phase) throw invalid("ledger sequence out of order");
                        phase = entry.crossing.code;
                        if (entry.crossing == Crossing.WRITE && !counts.containsKey(Crossing.CREATE)) {
                            throw invalid("write before create");
                        }
                        if (entry.crossing == Crossing.COMMIT && !counts.containsKey(Crossing.WRITE)) {
                            throw invalid("commit before write");
                        }
                        break;
                    case ABANDON:
                        if (phase < Crossing.CREATE.code) throw invalid("abandon before create");
                        break;
                    case REBOOT:
                        if (phase < Crossing.COMMIT.code) throw invalid("reboot before commit");
                        break;
                    case HANDOVER:
                        handedTo = entry.reference;
                        break;
                    default:
                        break;
                }
                if (entry.crossing == Crossing.CREATE && !entry.reference.equals(reference.nonce)) {
                    throw invalid("create entry without the ticket nonce");
                }
            }
            boolean created = counts.containsKey(Crossing.CREATE);
            if (created != reference.has(Reference.NONCE)) throw invalid("a nonce exactly once created");
            if (!created && reference.presence != 0) throw invalid("a native reference without a create");
            if (handedTo != null && !handedTo.equals(coordinator)) {
                throw invalid("coordinator differs from its handover");
            }
            int order = state.code;
            boolean sessionPhase = order >= State.SESSION_INTENT.code && state != State.SIGN_FAILED;
            if (created && order < State.SESSION_INTENT.code) throw invalid("a create before SESSION_INTENT");
            if (sessionPhase && !created && state != State.CANCELLED && state != State.VOID
                    && state != State.CLOSED_FAILED) {
                throw invalid("a session state without its create");
            }
        }

        public boolean flag(int bit) { return (flags & bit) != 0; }

        /** The number of ledger entries of one crossing. */
        public int count(Crossing crossing) {
            int count = 0;
            for (Entry entry : ledger) if (entry.crossing == crossing) ++count;
            return count;
        }

        /** The last ledger entry of one crossing, or null. */
        public Entry last(Crossing crossing) {
            for (int i = ledger.size() - 1; i >= 0; i--) if (ledger.get(i).crossing == crossing) return ledger.get(i);
            return null;
        }

        /** The index of an entry in the ledger. */
        public int indexOf(Entry entry) {
            for (int i = 0; i < ledger.size(); i++) if (ledger.get(i) == entry) return i;
            return -1;
        }

        public Builder toBuilder() { return new Builder(this); }

        @Override
        public boolean equals(Object other) {
            return other instanceof Ticket && Arrays.equals(encodeTicket(this), encodeTicket((Ticket) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodeTicket(this)); }

        @Override
        public String toString() {
            return "Ticket{" + component + ", attempt " + attempt + ", " + state + ", flags=" + flags + ", " + cause
                    + ", boots=" + bootCount + ", ledger=" + ledger.size() + "}";
        }

        /** A mutable builder. {@link #build} validates. */
        public static final class Builder {
            String installation = NO_ID, ticketId = NO_ID, component = "", planId = NO_ID;
            int attempt = 1;
            CoordinatorClass coordinatorClass = CoordinatorClass.HOST;
            String coordinator = NO_ID;
            State state = State.PLANNED;
            int flags;
            Cause cause = Cause.NONE;
            int bootCount;
            String boot = NO_ID;
            Reference reference = Reference.NONE;
            String windowBoot = NO_ID;
            long windowStart;
            String successor = NO_ID;
            List<Health> health = new ArrayList<>();
            List<Entry> ledger = new ArrayList<>();

            public Builder() {}

            Builder(Ticket t) {
                installation = t.installation; ticketId = t.ticketId; component = t.component; planId = t.planId;
                attempt = t.attempt; coordinatorClass = t.coordinatorClass; coordinator = t.coordinator;
                state = t.state; flags = t.flags; cause = t.cause; bootCount = t.bootCount; boot = t.boot;
                reference = t.reference; windowBoot = t.windowBoot; windowStart = t.windowStart;
                successor = t.successor; health = new ArrayList<>(t.health); ledger = new ArrayList<>(t.ledger);
            }

            public Builder installation(String v) { installation = v; return this; }
            public Builder ticketId(String v) { ticketId = v; return this; }
            public Builder component(String v) { component = v; return this; }
            public Builder planId(String v) { planId = v; return this; }
            public Builder attempt(int v) { attempt = v; return this; }
            public Builder coordinator(CoordinatorClass c, String id) {
                coordinatorClass = c;
                coordinator = id;
                return this;
            }
            public Builder state(State v) { state = v; return this; }
            public Builder flags(int v) { flags = v; return this; }
            public Builder set(int bit) { flags |= bit; return this; }
            public Builder clear(int bit) { flags &= ~bit; return this; }
            public Builder cause(Cause v) { cause = v; return this; }
            public Builder bootCount(int v) { bootCount = v; return this; }
            public Builder boot(String v) { boot = v; return this; }
            public Builder reference(Reference v) { reference = v; return this; }
            public Builder window(String bootValue, long start) {
                windowBoot = bootValue;
                windowStart = start;
                return this;
            }
            public Builder successor(String v) { successor = v; return this; }
            public Builder health(List<Health> v) { health = new ArrayList<>(v); return this; }
            public Builder append(Entry v) { ledger.add(v); return this; }
            public Builder ledger(List<Entry> v) { ledger = new ArrayList<>(v); return this; }

            public State state() { return state; }
            public Cause cause() { return cause; }
            public int flags() { return flags; }
            public List<Health> health() { return health; }

            public Ticket build() {
                Objects.requireNonNull(installation, "installation");
                Objects.requireNonNull(ticketId, "ticketId");
                Objects.requireNonNull(component, "component");
                Objects.requireNonNull(planId, "planId");
                Objects.requireNonNull(coordinator, "coordinator");
                Objects.requireNonNull(boot, "boot");
                Objects.requireNonNull(windowBoot, "windowBoot");
                Objects.requireNonNull(successor, "successor");
                return new Ticket(this);
            }
        }
    }

    /**
     * One append only fact scoped to one kernel boot. The kind decides which facts follow the
     * common fields, and which scope the observation has: the boot or device, the component, or a
     * user. Host facts of the signer and the artifact store may carry NO_ID as their boot.
     */
    public static final class Observation {
        public final String installation;
        public final String observationId;
        /** The package, or empty for an observation of the boot or the device. */
        public final String component;
        public final String boot;
        public final int user;
        public final long serial;
        public final ObservationKind kind;
        public final Route route;
        /** The framework instance the fact was read through, or -1. */
        public final long instance;
        /** Milliseconds since the boot at capture. Strict: it decides the time limits. */
        public final long elapsed;
        /** Informational wall clock milliseconds. */
        public final long wall;
        /** SHA-256 of the raw capture. */
        public final String raw;
        public final Classification classification;
        /** BOOT: the build fingerprint. ACTIVE: the SELinux context. Else empty. */
        public final String text;
        /**
         * FACTORY and ACTIVE: the APK digest. BUNDLE_PUBLISHED: the SHA-256 of the plan's
         * publication record. Else NO_DIGEST.
         */
        public final String digest;
        /** FACTORY and ACTIVE: the versionCode. Else 0. */
        public final long version;
        /** ACTIVE: the UID. LISTING: the count of the package's sessions. HEALTH: the criteria covered. */
        public final int number;
        /** REPLY: the ticket. SIGNER: the request ID. BUNDLE: the PUBLISH attempt read after. Else NO_ID. */
        public final String subject;
        /** REPLY: the ledger index answered. Else 0. */
        public final int sequence;
        /** REPLY: the crossing answered. Else null. */
        public final Crossing crossing;
        /** SESSION and REPLY: the native reference read. Else NONE. */
        public final Reference reference;

        private Observation(Builder b) {
            installation = b.installation; observationId = b.observationId; component = b.component; boot = b.boot;
            user = b.user; serial = b.serial; kind = Objects.requireNonNull(b.kind, "kind");
            route = Objects.requireNonNull(b.route, "route"); instance = b.instance; elapsed = b.elapsed;
            wall = b.wall; raw = b.raw; classification = Objects.requireNonNull(b.classification, "classification");
            text = Objects.requireNonNull(b.text, "text"); digest = Objects.requireNonNull(b.digest, "digest");
            version = b.version; number = b.number; subject = Objects.requireNonNull(b.subject, "subject");
            sequence = b.sequence; crossing = b.crossing; reference = Objects.requireNonNull(b.reference, "reference");
            validate();
        }

        private void validate() {
            checkId(installation, "installation", false);
            checkId(observationId, "observation ID", false);
            Objects.requireNonNull(component, "component");
            if (!component.isEmpty()) checkPackage(component);
            checkId(boot, "boot", true);
            checkActor(user, serial, user == NO_USER);
            checkDigest(raw, "raw capture digest", false);
            if (classification.kind != kind) throw invalid("classification of another kind");
            if (instance < -1) throw invalid("instance below -1");
            if (elapsed < 0) throw invalid("negative elapsed time");
            boolean host = route == Route.HOST;
            boolean hostKind = kind == ObservationKind.SIGNER || kind == ObservationKind.BUNDLE;
            if (host && !hostKind) throw invalid("a device fact read on the host");
            if (boot.equals(NO_ID) && (!host || instance != -1 || elapsed != 0)) {
                throw invalid("only host facts may lack a boot");
            }
            boolean device = kind == ObservationKind.BOOT || kind == ObservationKind.CHECKPOINT
                    || kind == ObservationKind.USER;
            if (device != component.isEmpty()) throw invalid("a component exactly for component facts");
            boolean perUser = kind == ObservationKind.USER || kind == ObservationKind.HEALTH;
            if (perUser == (user == NO_USER)) throw invalid("a user exactly for user facts");
            boolean framework = kind == ObservationKind.LISTING || kind == ObservationKind.SESSION;
            if (framework && instance < 0) throw invalid("a framework fact needs its instance");
            // Every fact field is zero unless the kind names it.
            boolean textKind = kind == ObservationKind.BOOT || kind == ObservationKind.ACTIVE;
            if (textKind) {
                checkText(text, 1, "text fact");
            } else if (!text.isEmpty()) {
                throw invalid("text fact of another kind");
            }
            // A bundle fact names the publication record it read, exactly when it read one complete.
            boolean digestKind = kind == ObservationKind.FACTORY || kind == ObservationKind.ACTIVE
                    || classification == Classification.BUNDLE_PUBLISHED;
            checkDigest(digest, "digest fact", !digestKind);
            if (!digestKind && !digest.equals(NO_DIGEST)) throw invalid("digest fact of another kind");
            boolean versionKind = kind == ObservationKind.FACTORY || kind == ObservationKind.ACTIVE;
            if (versionKind ? version < 0 : version != 0) throw invalid("versionCode fact of another kind");
            switch (kind) {
                case ACTIVE:
                    if (number < 0) throw invalid("negative UID");
                    break;
                case LISTING:
                    if (number < 0 || number > 0xffff) throw invalid("listing count outside u16");
                    if ((classification == Classification.SESSIONS_FOR_PACKAGE) != (number > 0)) {
                        throw invalid("listing count differs from its classification");
                    }
                    break;
                case HEALTH:
                    if (number == 0 || (number & ~Criterion.ALL) != 0) {
                        throw invalid("criteria outside the defined set");
                    }
                    break;
                default:
                    if (number != 0) throw invalid("number fact of another kind");
            }
            boolean subjectKind = kind == ObservationKind.REPLY || kind == ObservationKind.SIGNER
                    || kind == ObservationKind.BUNDLE;
            checkId(subject, "subject", !subjectKind);
            if (!subjectKind && !subject.equals(NO_ID)) throw invalid("subject of another kind");
            if (kind == ObservationKind.REPLY) {
                Objects.requireNonNull(crossing, "crossing");
                if (sequence < 0 || sequence >= MAX_LEDGER) throw invalid("reply sequence outside the ledger bound");
                if (crossing == Crossing.SIGN || crossing == Crossing.PUBLISH || crossing == Crossing.HANDOVER) {
                    throw invalid("a reply of a crossing that has its own kind");
                }
                if (crossing.framework() && instance < 0) throw invalid("a framework reply needs its instance");
                boolean commitReply = classification == Classification.REPLY_READY
                        || classification == Classification.REPLY_ACCEPTED
                        || classification == Classification.REPLY_PENDING;
                if (commitReply && crossing != Crossing.COMMIT) throw invalid("a commit reply for another crossing");
                if (classification == Classification.REPLY_SUCCESS && crossing == Crossing.COMMIT) {
                    throw invalid("a commit replies ready, accepted or pending");
                }
                boolean session = crossing == Crossing.CREATE && classification == Classification.REPLY_SUCCESS;
                if (session != reference.has(Reference.SESSION)) throw invalid("a session exactly in a create reply");
                if (!session && reference.presence != 0) throw invalid("a reference outside a create reply");
            } else {
                if (sequence != 0 || crossing != null) throw invalid("reply fields of another kind");
                if (kind == ObservationKind.SESSION) {
                    if (!reference.has(Reference.SESSION)) throw invalid("a session observation without its ID");
                } else if (reference.presence != 0) {
                    throw invalid("a reference of another kind");
                }
            }
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Observation
                    && Arrays.equals(encodeObservation(this), encodeObservation((Observation) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodeObservation(this)); }

        @Override
        public String toString() {
            return "Observation{" + kind + ", " + classification + ", " + route + "}";
        }

        /** A mutable builder. {@link #build} validates. */
        public static final class Builder {
            String installation = NO_ID, observationId = NO_ID, component = "", boot = NO_ID;
            int user = NO_USER;
            long serial = NO_SERIAL;
            ObservationKind kind;
            Route route = Route.SHELL;
            long instance = -1, elapsed, wall;
            String raw = NO_DIGEST;
            Classification classification;
            String text = "", digest = NO_DIGEST, subject = NO_ID;
            long version;
            int number, sequence;
            Crossing crossing;
            Reference reference = Reference.NONE;

            public Builder() {}

            public Builder installation(String v) { installation = v; return this; }
            public Builder observationId(String v) { observationId = v; return this; }
            public Builder component(String v) { component = v; return this; }
            public Builder boot(String v) { boot = v; return this; }
            public Builder user(int u, long s) { user = u; serial = s; return this; }
            public Builder route(Route v) { route = v; return this; }
            public Builder at(long instanceValue, long elapsedValue, long wallValue) {
                instance = instanceValue; elapsed = elapsedValue; wall = wallValue; return this;
            }
            public Builder raw(String v) { raw = v; return this; }
            public Builder classification(Classification v) { classification = v; kind = v.kind; return this; }
            public Builder text(String v) { text = v; return this; }
            public Builder digest(String v) { digest = v; return this; }
            public Builder version(long v) { version = v; return this; }
            public Builder number(int v) { number = v; return this; }
            public Builder subject(String v) { subject = v; return this; }
            public Builder reply(String ticket, int index, Crossing c) {
                subject = ticket; sequence = index; crossing = c; return this;
            }
            public Builder reference(Reference v) { reference = v; return this; }

            public Observation build() {
                Objects.requireNonNull(installation, "installation");
                Objects.requireNonNull(observationId, "observationId");
                Objects.requireNonNull(boot, "boot");
                Objects.requireNonNull(raw, "raw");
                Objects.requireNonNull(classification, "classification");
                return new Observation(this);
            }
        }
    }

    /** The owner's choice for one component, its revision, responsibility and realization. */
    public static final class Selection {
        public final String installation;
        public final String component;
        public final long revision;
        public final ChoiceKind choice;
        /** The chosen plan, NO_ID exactly for FACTORY. */
        public final String planId;
        public final UpdateResponsibility responsibility;
        /** Decision 6: the declared rebuild window in milliseconds, positive exactly for REBUILD_WINDOW. */
        public final long rebuildWindowMillis;
        public final Realization realization;
        /** The boot of the last cohort check, NO_ID exactly for UNCHECKED. */
        public final String checkedBoot;
        /** A linked repair plan, or NO_ID. */
        public final String repair;
        /** The owner approved temporary factory plan, NO_ID exactly outside TEMPORARY_FACTORY. */
        public final String temporary;
        /** Informational wall clock milliseconds of the last choice change. */
        public final long changedAt;

        public Selection(String installation, String component, long revision, ChoiceKind choice, String planId,
                UpdateResponsibility responsibility, long rebuildWindowMillis, Realization realization,
                String checkedBoot, String repair, String temporary, long changedAt) {
            this.installation = installation;
            this.component = component;
            this.revision = revision;
            this.choice = Objects.requireNonNull(choice, "choice");
            this.planId = planId;
            this.responsibility = Objects.requireNonNull(responsibility, "responsibility");
            this.rebuildWindowMillis = rebuildWindowMillis;
            this.realization = Objects.requireNonNull(realization, "realization");
            this.checkedBoot = checkedBoot;
            this.repair = repair;
            this.temporary = temporary;
            this.changedAt = changedAt;
            checkId(installation, "installation", false);
            checkPackage(component);
            if (revision < 0) throw invalid("negative revision");
            checkId(planId, "plan ID", true);
            checkId(checkedBoot, "checked boot", true);
            checkId(repair, "repair", true);
            checkId(temporary, "temporary plan", true);
            if ((responsibility == UpdateResponsibility.REBUILD_WINDOW) ? rebuildWindowMillis <= 0
                    : rebuildWindowMillis != 0) {
                throw invalid("a rebuild window exactly for REBUILD_WINDOW");
            }
            if ((choice == ChoiceKind.FACTORY) != planId.equals(NO_ID)) {
                throw invalid("a plan exactly for a PLAN choice");
            }
            if ((realization == Realization.UNCHECKED) != checkedBoot.equals(NO_ID)) {
                throw invalid("a checked boot exactly once checked");
            }
            if (choice == ChoiceKind.FACTORY && (realization == Realization.STALE_BASE
                    || realization == Realization.DISPLACED || realization == Realization.TEMPORARY_FACTORY)) {
                throw invalid("the factory copy is never stale, displaced or temporarily replaced");
            }
            if ((realization == Realization.TEMPORARY_FACTORY) == temporary.equals(NO_ID)) {
                throw invalid("a temporary plan exactly in TEMPORARY_FACTORY");
            }
            if (!temporary.equals(NO_ID) && (temporary.equals(planId) || temporary.equals(repair))) {
                throw invalid("the temporary plan is another plan");
            }
            boolean repairable = realization == Realization.STALE_BASE || realization == Realization.DISPLACED
                    || realization == Realization.DIVERGED || realization == Realization.TEMPORARY_FACTORY;
            if (!repairable && !repair.equals(NO_ID)) throw invalid("a repair link without a realization to repair");
            if (repair.equals(planId) && !repair.equals(NO_ID)) throw invalid("the chosen plan cannot repair itself");
        }

        /** The same choice with a new realization: the choice and revision never change here. */
        public Selection realized(Realization status, String bootId, String repairPlan, String temporaryPlan) {
            return new Selection(installation, component, revision, choice, planId, responsibility,
                    rebuildWindowMillis, status, bootId, repairPlan, temporaryPlan, changedAt);
        }

        /** The choice moved to a plan, or to the factory copy, at the next revision. */
        public Selection chosen(ChoiceKind kind, String plan, Realization status, String bootId, long at) {
            return new Selection(installation, component, revision + 1, kind, plan, responsibility,
                    rebuildWindowMillis, status, bootId, NO_ID, NO_ID, at);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Selection
                    && Arrays.equals(encodeSelection(this), encodeSelection((Selection) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodeSelection(this)); }

        @Override
        public String toString() {
            return "Selection{" + component + ", revision " + revision + ", " + choice + ", " + responsibility + ", "
                    + realization + "}";
        }
    }

    /**
     * The stable prefix of an intact frame of a version this codec does not decode: what the
     * record concerns, as negative evidence only. It is never a value and grants nothing.
     */
    public static final class Prefix {
        public final Kind kind;
        public final int version;
        public final String installation;
        /** The record's ID: plan, authorization, ticket or observation. NO_ID for a selection. */
        public final String recordId;
        public final String component;
        /** Authorization and ticket: the plan. Else NO_ID. */
        public final String planId;

        Prefix(Kind kind, int version, String installation, String recordId, String component, String planId) {
            this.kind = kind;
            this.version = version;
            this.installation = installation;
            this.recordId = recordId;
            this.component = component;
            this.planId = planId;
        }

        @Override
        public String toString() { return "Prefix{" + kind + ", version " + version + ", " + component + "}"; }
    }

    private DeploymentRecords() {}

    // ------------------------------------------------------------------ encoding

    /** Returns the one encoding of a plan. */
    public static byte[] encodePlan(Plan p) {
        Objects.requireNonNull(p, "plan");
        Output out = new Output(Kind.PLAN);
        out.id(p.installation);
        out.id(p.planId);
        out.text(p.component);
        out.u8(p.componentClass.code);
        out.u8(p.target.code);
        out.id(p.repairs);
        out.digest(p.bundleInput);
        out.digest(p.bundleApk);
        out.i64(p.bundleVersion);
        out.digest(p.signer);
        out.digest(p.restorationInput);
        out.digest(p.restorationApk);
        out.i64(p.restorationVersion);
        out.u8(p.signing);
        out.text(p.fingerprint);
        out.digest(p.factoryApk);
        out.i64(p.factoryVersion);
        out.digest(p.baseApk);
        out.i64(p.baseVersion);
        out.i32(p.baseUid);
        out.text(p.baseContext);
        out.u8(p.users.code);
        out.u8(p.data.code);
        out.i64(p.selectionRevision);
        out.digest(p.trustPolicy);
        out.u8(p.commitMode.code);
        out.u16(p.criteria);
        out.i64(p.healthWindowMillis);
        out.u8(p.healthResponse.code);
        out.id(p.restorationPlan);
        out.u8(p.recoveryRoute.code);
        out.i64(p.noticeDelayMillis);
        out.i64(p.emergencyNoticeMillis);
        out.u16(p.bootLimit);
        out.i64(p.rebootTimeLimitMillis);
        out.u16(p.requestLimit);
        out.i64(p.activateWindowMillis);
        out.i64(p.verificationWaitMillis);
        out.i64(p.createdAt);
        return out.seal();
    }

    /** Returns the one encoding of an authorization. */
    public static byte[] encodeAuthorization(Authorization a) {
        Objects.requireNonNull(a, "authorization");
        Output out = new Output(Kind.AUTHORIZATION);
        out.id(a.installation);
        out.id(a.authorizationId);
        out.text(a.component);
        out.id(a.planId);
        out.u8(a.effect.code);
        out.u8(a.inputs);
        out.u8(a.actorClass.code);
        out.i32(a.actorUser);
        out.i64(a.actorSerial);
        out.id(a.grant);
        out.u8(a.grantScope.code);
        out.id(a.interaction);
        out.i64(a.grantedAt);
        return out.seal();
    }

    /** Returns the one encoding of a ticket. */
    public static byte[] encodeTicket(Ticket t) {
        Objects.requireNonNull(t, "ticket");
        Output out = new Output(Kind.TICKET);
        out.id(t.installation);
        out.id(t.ticketId);
        out.text(t.component);
        out.id(t.planId);
        out.i32(t.attempt);
        out.u8(t.coordinatorClass.code);
        out.id(t.coordinator);
        out.u8(t.state.code);
        out.u8(t.flags);
        out.u8(t.cause.code);
        out.u16(t.bootCount);
        out.id(t.boot);
        out.reference(t.reference);
        out.id(t.windowBoot);
        out.i64(t.windowStart);
        out.id(t.successor);
        out.u16(t.health.size());
        for (Health h : t.health) {
            out.i32(h.user);
            out.i64(h.serial);
            out.u8(h.outcome.code);
        }
        out.u16(t.ledger.size());
        for (Entry e : t.ledger) {
            out.u8(e.crossing.code);
            out.id(e.boot);
            out.i64(e.instance);
            out.i64(e.elapsed);
            out.id(e.grant);
            out.id(e.reference);
            out.i64(e.issuedAt);
        }
        return out.seal();
    }

    /** Returns the one encoding of an observation. */
    public static byte[] encodeObservation(Observation o) {
        Objects.requireNonNull(o, "observation");
        Output out = new Output(Kind.OBSERVATION);
        out.id(o.installation);
        out.id(o.observationId);
        out.text(o.component);
        out.id(o.boot);
        out.i32(o.user);
        out.i64(o.serial);
        out.u8(o.kind.code);
        out.u8(o.route.code);
        out.i64(o.instance);
        out.i64(o.elapsed);
        out.i64(o.wall);
        out.digest(o.raw);
        out.u8(o.classification.code);
        switch (o.kind) {
            case BOOT:
                out.text(o.text);
                break;
            case FACTORY:
                out.digest(o.digest);
                out.i64(o.version);
                break;
            case ACTIVE:
                out.digest(o.digest);
                out.i64(o.version);
                out.i32(o.number);
                out.text(o.text);
                break;
            case LISTING:
                out.u16(o.number);
                break;
            case SESSION:
                out.reference(o.reference);
                break;
            case REPLY:
                out.id(o.subject);
                out.u16(o.sequence);
                out.u8(o.crossing.code);
                out.reference(o.reference);
                break;
            case HEALTH:
                out.u16(o.number);
                break;
            case SIGNER:
                out.id(o.subject);
                break;
            case BUNDLE:
                out.id(o.subject);
                out.digest(o.digest);
                break;
            default:
                break; // CHECKPOINT and USER carry no further facts.
        }
        return out.seal();
    }

    /** Returns the one encoding of a selection. */
    public static byte[] encodeSelection(Selection s) {
        Objects.requireNonNull(s, "selection");
        Output out = new Output(Kind.SELECTION);
        out.id(s.installation);
        out.text(s.component);
        out.i64(s.revision);
        out.u8(s.choice.code);
        out.id(s.planId);
        out.u8(s.responsibility.code);
        out.i64(s.rebuildWindowMillis);
        out.u8(s.realization.code);
        out.id(s.checkedBoot);
        out.id(s.repair);
        out.id(s.temporary);
        out.i64(s.changedAt);
        return out.seal();
    }

    // ------------------------------------------------------------------ decoding

    /** Decodes one complete plan record of version 1. */
    public static Plan decodePlan(byte[] record) {
        Input in = Input.open(record, Kind.PLAN);
        Plan.Builder b = new Plan.Builder();
        b.installation = in.id();
        b.planId = in.id();
        b.component = in.text();
        b.componentClass = code(ComponentClass.values(), in.u8(), c -> c.code, "component class");
        b.target = code(Target.values(), in.u8(), c -> c.code, "target");
        b.repairs = in.id();
        b.bundleInput = in.digest();
        b.bundleApk = in.digest();
        b.bundleVersion = in.i64();
        b.signer = in.digest();
        b.restorationInput = in.digest();
        b.restorationApk = in.digest();
        b.restorationVersion = in.i64();
        b.signing = in.u8();
        b.fingerprint = in.text();
        b.factoryApk = in.digest();
        b.factoryVersion = in.i64();
        b.baseApk = in.digest();
        b.baseVersion = in.i64();
        b.baseUid = in.i32();
        b.baseContext = in.text();
        b.users = code(AffectedUsers.values(), in.u8(), c -> c.code, "affected users");
        b.data = code(DataTransition.values(), in.u8(), c -> c.code, "data transition");
        b.selectionRevision = in.i64();
        b.trustPolicy = in.digest();
        b.commitMode = code(CommitMode.values(), in.u8(), c -> c.code, "commit mode");
        b.criteria = in.u16();
        b.healthWindowMillis = in.i64();
        b.healthResponse = code(HealthResponse.values(), in.u8(), c -> c.code, "health response");
        b.restorationPlan = in.id();
        b.recoveryRoute = code(RecoveryRoute.values(), in.u8(), c -> c.code, "recovery route");
        b.noticeDelayMillis = in.i64();
        b.emergencyNoticeMillis = in.i64();
        b.bootLimit = in.u16();
        b.rebootTimeLimitMillis = in.i64();
        b.requestLimit = in.u16();
        b.activateWindowMillis = in.i64();
        b.verificationWaitMillis = in.i64();
        b.createdAt = in.i64();
        in.finish();
        return b.build();
    }

    /** Decodes one complete authorization record of version 1. */
    public static Authorization decodeAuthorization(byte[] record) {
        Input in = Input.open(record, Kind.AUTHORIZATION);
        String installation = in.id();
        String id = in.id();
        String component = in.text();
        String plan = in.id();
        Effect effect = code(Effect.values(), in.u8(), c -> c.code, "effect");
        int inputs = in.u8();
        ActorClass actor = code(ActorClass.values(), in.u8(), c -> c.code, "actor class");
        int user = in.i32();
        long serial = in.i64();
        String grant = in.id();
        GrantScope scope = code(GrantScope.values(), in.u8(), c -> c.code, "grant scope");
        String interaction = in.id();
        long grantedAt = in.i64();
        in.finish();
        return new Authorization(installation, id, component, plan, effect, inputs, actor, user, serial, grant,
                scope, interaction, grantedAt);
    }

    /** Decodes one complete ticket record of version 1. */
    public static Ticket decodeTicket(byte[] record) {
        Input in = Input.open(record, Kind.TICKET);
        Ticket.Builder b = new Ticket.Builder();
        b.installation = in.id();
        b.ticketId = in.id();
        b.component = in.text();
        b.planId = in.id();
        b.attempt = in.i32();
        b.coordinatorClass = code(CoordinatorClass.values(), in.u8(), c -> c.code, "coordinator class");
        b.coordinator = in.id();
        b.state = code(State.values(), in.u8(), c -> c.code, "state");
        b.flags = in.u8();
        b.cause = code(Cause.values(), in.u8(), c -> c.code, "cause");
        b.bootCount = in.u16();
        b.boot = in.id();
        b.reference = in.reference();
        b.windowBoot = in.id();
        b.windowStart = in.i64();
        b.successor = in.id();
        int users = in.count(MAX_USERS);
        for (int i = 0; i < users; i++) {
            int user = in.i32();
            long serial = in.i64();
            Outcome outcome = code(Outcome.values(), in.u8(), c -> c.code, "outcome");
            b.health.add(new Health(user, serial, outcome));
        }
        int entries = in.count(MAX_LEDGER);
        for (int i = 0; i < entries; i++) {
            Crossing crossing = code(Crossing.values(), in.u8(), c -> c.code, "crossing");
            String boot = in.id();
            long instance = in.i64();
            long elapsed = in.i64();
            String grant = in.id();
            String reference = in.id();
            long issuedAt = in.i64();
            b.ledger.add(new Entry(crossing, boot, instance, elapsed, grant, reference, issuedAt));
        }
        in.finish();
        return b.build();
    }

    /** Decodes one complete observation record of version 1. */
    public static Observation decodeObservation(byte[] record) {
        Input in = Input.open(record, Kind.OBSERVATION);
        Observation.Builder b = new Observation.Builder();
        b.installation = in.id();
        b.observationId = in.id();
        b.component = in.optionalText();
        b.boot = in.id();
        b.user = in.i32();
        b.serial = in.i64();
        ObservationKind kind = code(ObservationKind.values(), in.u8(), c -> c.code, "observation kind");
        b.route = code(Route.values(), in.u8(), c -> c.code, "route");
        b.instance = in.i64();
        b.elapsed = in.i64();
        b.wall = in.i64();
        b.raw = in.digest();
        int code = in.u8();
        Classification classification = null;
        for (Classification c : Classification.values()) {
            if (c.kind == kind && c.code == code) classification = c;
        }
        if (classification == null) throw invalid("unknown classification");
        b.classification(classification);
        switch (kind) {
            case BOOT:
                b.text = in.text();
                break;
            case FACTORY:
                b.digest = in.digest();
                b.version = in.i64();
                break;
            case ACTIVE:
                b.digest = in.digest();
                b.version = in.i64();
                b.number = in.i32();
                b.text = in.text();
                break;
            case LISTING:
                b.number = in.u16();
                break;
            case SESSION:
                b.reference = in.reference();
                break;
            case REPLY:
                b.subject = in.id();
                b.sequence = in.u16();
                b.crossing = code(Crossing.values(), in.u8(), c -> c.code, "crossing");
                b.reference = in.reference();
                break;
            case HEALTH:
                b.number = in.u16();
                break;
            case SIGNER:
                b.subject = in.id();
                break;
            case BUNDLE:
                b.subject = in.id();
                b.digest = in.digest();
                break;
            default:
                break;
        }
        in.finish();
        return b.build();
    }

    /** Decodes one complete selection record of version 1. */
    public static Selection decodeSelection(byte[] record) {
        Input in = Input.open(record, Kind.SELECTION);
        String installation = in.id();
        String component = in.text();
        long revision = in.i64();
        ChoiceKind choice = code(ChoiceKind.values(), in.u8(), c -> c.code, "choice");
        String plan = in.id();
        UpdateResponsibility responsibility = code(UpdateResponsibility.values(), in.u8(), c -> c.code,
                "update responsibility");
        long window = in.i64();
        Realization realization = code(Realization.values(), in.u8(), c -> c.code, "realization");
        String checked = in.id();
        String repair = in.id();
        String temporary = in.id();
        long changedAt = in.i64();
        in.finish();
        return new Selection(installation, component, revision, choice, plan, responsibility, window, realization,
                checked, repair, temporary, changedAt);
    }

    /**
     * The kind and declared version of an intact frame, or null for any other input. A frame is
     * intact when its size is within the bounds, it starts with the magic and a known type, and
     * its length field and SHA-256 match. Nothing after the frame is parsed, and the result grants
     * nothing.
     */
    public static int[] intactFrame(byte[] record) {
        Objects.requireNonNull(record, "record");
        try {
            byte[] bytes = bounded(record).clone();
            Kind kind = Kind.of(u16At(bytes, 4));
            if (kind == null) return null;
            return new int[] {kind.code, frame(bytes, kind)};
        } catch (IllegalArgumentException notIntact) {
            return null;
        }
    }

    /**
     * The stable prefix of one intact frame of a version above 1, as negative evidence. The frame
     * is verified first, then every prefix field against its frozen rule. Nothing after the prefix
     * is read, so a later version may change everything that follows it. Version 1 frames are
     * refused: this codec decodes them in full.
     */
    public static Prefix decodePrefix(byte[] record) {
        byte[] bytes = bounded(record).clone();
        Kind kind = Kind.of(u16At(bytes, 4));
        if (kind == null) throw invalid("unknown record type");
        int version = frame(bytes, kind);
        if (version <= VERSION) throw invalid("no prefix reading of this version");
        Input in = new Input(bytes, bytes.length - CHECKSUM_BYTES, version);
        String installation = in.id();
        checkId(installation, "installation", false);
        String recordId = NO_ID;
        String plan = NO_ID;
        String component;
        switch (kind) {
            case PLAN:
                recordId = in.id();
                component = in.text();
                break;
            case AUTHORIZATION:
            case TICKET:
                recordId = in.id();
                component = in.text();
                plan = in.id();
                checkId(plan, "plan ID", false);
                if (kind == Kind.TICKET && in.i32() < 1) throw invalid("attempt not positive");
                break;
            case OBSERVATION:
                recordId = in.id();
                component = in.optionalText();
                checkId(in.id(), "boot", true);
                int user = in.i32();
                long serial = in.i64();
                checkActor(user, serial, user == NO_USER);
                break;
            default:
                component = in.text();
                if (in.i64() < 0) throw invalid("negative revision");
                break;
        }
        if (kind != Kind.SELECTION) checkId(recordId, "record ID", false);
        if (!component.isEmpty()) checkPackage(component);
        return new Prefix(kind, version, installation, recordId, component, plan);
    }

    // ------------------------------------------------------------------ helpers

    private interface Code<T> { int of(T value); }

    private static <T> T code(T[] values, int code, Code<T> codeOf, String field) {
        for (T value : values) if (codeOf.of(value) == code) return value;
        throw invalid("unknown " + field);
    }

    // Builds one record: frame, body, then the checksum.
    private static final class Output {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream(512);

        Output(Kind kind) {
            i32(MAGIC);
            u16(kind.code);
            u16(VERSION);
            i32(0); // Total length, set by seal.
        }

        void u8(int value) { bytes.write(value); }

        void u16(int value) {
            u8(value);
            u8(value >>> 8);
        }

        void i32(int value) {
            u16(value);
            u16(value >>> 16);
        }

        void i64(long value) {
            i32((int) value);
            i32((int) (value >>> 32));
        }

        void raw(String hexDigits) {
            for (int i = 0; i < hexDigits.length(); i += 2) {
                u8((Character.digit(hexDigits.charAt(i), 16) << 4) | Character.digit(hexDigits.charAt(i + 1), 16));
            }
        }

        void id(String value) { raw(value); }

        void digest(String value) { raw(value); }

        void text(String value) {
            u16(value.length());
            byte[] text = value.getBytes(StandardCharsets.US_ASCII);
            bytes.write(text, 0, text.length);
        }

        void reference(Reference r) {
            u8(r.presence);
            i32(r.sessionId);
            i64(r.createdMillis);
            text(r.stageDir);
            i32(r.installerUid);
            id(r.nonce);
        }

        byte[] seal() {
            int length = bytes.size() + CHECKSUM_BYTES;
            if (length > MAX_BYTES) throw new IllegalStateException("record exceeds MAX_BYTES");
            byte[] record = Arrays.copyOf(bytes.toByteArray(), length);
            for (int i = 0; i < 4; i++) record[LENGTH_OFFSET + i] = (byte) (length >>> (8 * i));
            System.arraycopy(sha256(record, length - CHECKSUM_BYTES), 0, record, length - CHECKSUM_BYTES,
                    CHECKSUM_BYTES);
            return record;
        }
    }

    // Reads the body of one record whose frame and checksum were verified.
    private static final class Input {
        private final byte[] bytes;
        private final int end;
        final int version;
        private int position = FRAME_BYTES;

        Input(byte[] bytes, int end, int version) {
            this.bytes = bytes;
            this.end = end;
            this.version = version;
        }

        // Verifies a private copy, so later writes to the caller's array cannot race the checks.
        static Input open(byte[] record, Kind kind) {
            byte[] bytes = bounded(record).clone();
            if (u16At(bytes, 4) != kind.code) throw invalid("wrong record type");
            int version = frame(bytes, kind);
            if (version != VERSION) throw invalid("unsupported record version");
            return new Input(bytes, bytes.length - CHECKSUM_BYTES, version);
        }

        private int take(int count) {
            if (count > end - position) throw invalid("truncated record");
            int at = position;
            position += count;
            return at;
        }

        int u8() { return bytes[take(1)] & 0xff; }

        int u16() { return u16At(bytes, take(2)); }

        int i32() { return i32At(bytes, take(4)); }

        long i64() {
            int at = take(8);
            return (i32At(bytes, at) & 0xffffffffL) | ((long) i32At(bytes, at + 4) << 32);
        }

        int count(int max) {
            int count = u16();
            if (count > max) throw invalid("count above its bound");
            return count;
        }

        String hex(int count) {
            int at = take(count);
            char[] digits = new char[2 * count];
            for (int i = 0; i < count; i++) {
                digits[2 * i] = HEX[(bytes[at + i] & 0xff) >>> 4];
                digits[2 * i + 1] = HEX[bytes[at + i] & 0xf];
            }
            return new String(digits);
        }

        String id() { return hex(ID_BYTES); }

        String digest() { return hex(DIGEST_BYTES); }

        // Printable ASCII of at most MAX_TEXT bytes. The value's constructor checks its grammar.
        String optionalText() {
            int length = u16();
            if (length > MAX_TEXT) throw invalid("text too long");
            int at = take(length);
            for (int i = at; i < at + length; i++) {
                if (bytes[i] < 0x20 || bytes[i] > 0x7e) throw invalid("text not printable ASCII");
            }
            return new String(bytes, at, length, StandardCharsets.US_ASCII);
        }

        String text() {
            String value = optionalText();
            if (value.isEmpty()) throw invalid("empty text");
            return value;
        }

        Reference reference() {
            int presence = u8();
            int session = i32();
            long created = i64();
            String stageDir = optionalText();
            int installer = i32();
            String nonce = id();
            return new Reference(presence, session, created, stageDir, installer, nonce);
        }

        void finish() {
            if (position != end) throw invalid("trailing bytes");
        }
    }

    // Refuses null and a size outside the frame bounds, before anything is copied.
    private static byte[] bounded(byte[] record) {
        Objects.requireNonNull(record, "record");
        if (record.length > MAX_BYTES) throw invalid("record exceeds MAX_BYTES");
        if (record.length < FRAME_BYTES + CHECKSUM_BYTES) throw invalid("record too short");
        return record;
    }

    // Verifies the magic, type, length field and checksum. Returns the declared version.
    private static int frame(byte[] bytes, Kind kind) {
        if (i32At(bytes, 0) != MAGIC) throw invalid("not a deployment record");
        if (u16At(bytes, 4) != kind.code) throw invalid("wrong record type");
        if (i32At(bytes, LENGTH_OFFSET) != bytes.length) throw invalid("wrong record length");
        int end = bytes.length - CHECKSUM_BYTES;
        if (!MessageDigest.isEqual(sha256(bytes, end), Arrays.copyOfRange(bytes, end, bytes.length))) {
            throw invalid("record checksum mismatch");
        }
        return u16At(bytes, 6);
    }

    private static int u16At(byte[] bytes, int at) {
        return (bytes[at] & 0xff) | ((bytes[at + 1] & 0xff) << 8);
    }

    private static int i32At(byte[] bytes, int at) {
        return u16At(bytes, at) | (u16At(bytes, at + 2) << 16);
    }

    static byte[] sha256(byte[] bytes, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes, 0, length);
            return digest.digest();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    /** Lowercase hex of the SHA-256 of some bytes. */
    public static String sha256Hex(byte[] bytes) {
        byte[] digest = sha256(bytes, bytes.length);
        char[] digits = new char[2 * digest.length];
        for (int i = 0; i < digest.length; i++) {
            digits[2 * i] = HEX[(digest[i] & 0xff) >>> 4];
            digits[2 * i + 1] = HEX[digest[i] & 0xf];
        }
        return new String(digits);
    }

    // An actor or observed user: a user and serial that are not negative, or exactly NO_USER and
    // NO_SERIAL where none is allowed.
    private static void checkActor(int user, long serial, boolean none) {
        if (none) {
            if (user != NO_USER || serial != NO_SERIAL) throw invalid("NO_USER needs NO_SERIAL");
        } else if (user < 0 || serial < 0) {
            throw invalid("negative user or serial");
        }
    }

    private static void checkHex(String value, int digits, String field, boolean zeroAllowed) {
        Objects.requireNonNull(value, field);
        boolean valid = value.length() == digits;
        boolean zero = true;
        for (int i = 0; valid && i < digits; i++) {
            char c = value.charAt(i);
            valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            zero &= c == '0';
        }
        if (!valid) throw invalid(field + " is not " + digits + " lowercase hex digits");
        if (zero && !zeroAllowed) throw invalid(field + " is zero");
    }

    static void checkId(String value, String field, boolean zeroAllowed) {
        checkHex(value, 2 * ID_BYTES, field, zeroAllowed);
    }

    static void checkDigest(String value, String field, boolean zeroAllowed) {
        checkHex(value, 2 * DIGEST_BYTES, field, zeroAllowed);
    }

    private static void checkText(String value, int min, String field) {
        Objects.requireNonNull(value, field);
        if (value.length() < min || value.length() > MAX_TEXT) throw invalid(field + " length outside its bounds");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e) throw invalid(field + " not printable ASCII");
        }
    }

    // Dot separated ASCII segments. Each starts with a letter, then letters, digits or '_'.
    static void checkPackage(String name) {
        Objects.requireNonNull(name, "component");
        int length = name.length();
        boolean valid = length > 0 && length <= MAX_TEXT;
        int segments = 1;
        boolean segmentStart = true;
        for (int i = 0; valid && i < length; i++) {
            char c = name.charAt(i);
            boolean letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            boolean trailing = (c >= '0' && c <= '9') || c == '_';
            if (letter || (trailing && !segmentStart)) {
                segmentStart = false;
            } else if (c == '.' && !segmentStart) {
                ++segments;
                segmentStart = true;
            } else {
                valid = false;
            }
        }
        if (!valid || segmentStart || segments < 2) throw invalid("malformed package name");
    }

    static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException(reason);
    }
}
