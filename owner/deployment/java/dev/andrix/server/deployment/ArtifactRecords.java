// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The artifact store's records, version 1: the bundle manifest, type 6, and the publication,
 * type 7. They use the frame of the deployment records: magic "AXDR", a u16 type, a u16 version,
 * a u32 length, the body and the SHA-256 of every preceding byte. Integers are little endian.
 *
 * <p>A manifest names bytes, never approval. Its SHA-256 over the whole frame is the bundle ID, and
 * it holds no time, so the same bytes always give the same ID. A built APK may already carry
 * signatures, which prove nothing about the outputs, so the input's identity is the digest of its
 * ZIP entries outside the signing block. A publication names the bundles of one plan that become
 * visible together, the variant and its restoration when the plan has one (decision 8), and each
 * bundle's own signing transaction, so a pair from two transactions fits the layout. It binds the
 * produced bundles to the plan, which names only their signing inputs. Each kind has a fixed
 * version, strict fields that refuse unknown codes and a stable prefix that every later version
 * keeps. The publication's one informational time decides nothing.
 */
public final class ArtifactRecords {
    public static final int MANIFEST = 6;
    public static final int PUBLICATION = 7;
    public static final int TRANSACTION = 8;
    public static final int VERSION = 1;
    /** No artifact record is larger. */
    public static final int MAX_BYTES = 4096;
    public static final int SCHEME_V2 = 1;
    public static final int SCHEME_V3 = 2;
    public static final int SCHEME_V4 = 4;
    /** The schemes a staged system APK needs: v2 and v3, plus the signed v4 sidecar. */
    public static final int SCHEMES = SCHEME_V2 | SCHEME_V3 | SCHEME_V4;

    private static final int FRAME_BYTES = 12;
    private static final int CHECKSUM_BYTES = 32;

    private ArtifactRecords() {}

    /** Which APK of the pair a bundle holds. The prompt says which one is the recovery copy. */
    public enum Role {
        VARIANT(1), RESTORATION(2);

        final int code;

        Role(int code) { this.code = code; }

        static Role of(int code) {
            for (Role r : values()) if (r.code == code) return r;
            throw DeploymentRecords.invalid("unknown role");
        }
    }

    /** One key operation's signature scheme: three for each APK. */
    public enum Scheme {
        V2(1), V3(2), V4(3);

        final int code;

        Scheme(int code) { this.code = code; }

        static Scheme of(int code) {
            for (Scheme s : values()) if (s.code == code) return s;
            throw DeploymentRecords.invalid("unknown scheme");
        }
    }

    /** One output of a signing transaction: the signed APK or its v4 sidecar. */
    public enum Member {
        APK(1), IDSIG(2);

        final int code;

        Member(int code) { this.code = code; }

        static Member of(int code) {
            for (Member m : values()) if (m.code == code) return m;
            throw DeploymentRecords.invalid("unknown member");
        }
    }

    /** Where a signing transaction stands. Only OPEN changes, and only once. */
    public enum TransactionState {
        OPEN(1), COMPLETED(2), REFUSED(3), CANNOT_COMPLETE(4);

        final int code;

        TransactionState(int code) { this.code = code; }

        static TransactionState of(int code) {
            for (TransactionState t : values()) if (t.code == code) return t;
            throw DeploymentRecords.invalid("unknown transaction state");
        }
    }

    /** The facts an output must meet, as bits. */
    public static final int FACT_ENTRIES = 1;
    public static final int FACT_V2 = 2;
    public static final int FACT_V3 = 4;
    public static final int FACT_V4 = 8;
    public static final int FACT_ROLE = 16;
    /** A signed APK: its entries are the input's, v2 verifies below SDK 28, v3 over the range, every signer has the role. */
    public static final int APK_FACTS = FACT_ENTRIES | FACT_V2 | FACT_V3 | FACT_ROLE;
    /** A v4 sidecar: v4 verifies over its APK and the range, and its signer has the role. */
    public static final int IDSIG_FACTS = FACT_V4 | FACT_ROLE;

    /** One key operation of a signing transaction. */
    public static final class Operation {
        public final String id;
        public final Role role;
        public final Scheme scheme;

        public Operation(String id, Role role, Scheme scheme) {
            DeploymentRecords.checkId(id, "operation", false);
            this.id = id;
            this.role = Objects.requireNonNull(role, "role");
            this.scheme = Objects.requireNonNull(scheme, "scheme");
        }
    }

    /**
     * One expected output, named by role and member, with the facts it must meet: its input's
     * digest and entry digest and its versionCode. The digest and size are set exactly once the
     * transaction COMPLETED.
     */
    public static final class Output {
        public final Role role;
        public final Member member;
        public final int facts;
        public final String input;
        public final String inputEntries;
        public final long versionCode;
        public final String digest;
        public final long bytes;

        public Output(Role role, Member member, int facts, String input, String inputEntries, long versionCode,
                String digest, long bytes) {
            this.role = Objects.requireNonNull(role, "role");
            this.member = Objects.requireNonNull(member, "member");
            if (facts != (member == Member.APK ? APK_FACTS : IDSIG_FACTS)) {
                throw DeploymentRecords.invalid("facts other than the member's");
            }
            DeploymentRecords.checkDigest(input, "input", false);
            DeploymentRecords.checkDigest(inputEntries, "input entries", false);
            DeploymentRecords.checkDigest(digest, "output", true);
            if (versionCode <= 0) throw DeploymentRecords.invalid("versionCode not positive");
            if (digest.equals(DeploymentRecords.NO_DIGEST) != (bytes == 0) || bytes < 0) {
                throw DeploymentRecords.invalid("an output digest exactly with its size");
            }
            this.facts = facts;
            this.input = input;
            this.inputEntries = inputEntries;
            this.versionCode = versionCode;
            this.digest = digest;
            this.bytes = bytes;
        }

        /** The same output with its produced digest and size. */
        public Output produced(String outputDigest, long size) {
            return new Output(role, member, facts, input, inputEntries, versionCode, outputDigest, size);
        }
    }

    /**
     * The host signer's durable record of one signing transaction: the approved context, the
     * operations' own IDs, three for each APK, and the expected outputs, two for each APK. It is
     * written OPEN before the first key operation and replaced once by its outcome. Its ID is the
     * ticket's SIGN request ID, so a lost reply is resolved by that ID, never by signing again.
     */
    public static final class Transaction {
        public final String installation;
        public final String transaction;
        public final String component;
        public final String plan;
        public final String authorization;
        public final String certificate;
        public final String key;
        public final int sdkMin;
        public final int sdkMax;
        public final TransactionState state;
        /** The refused operation, 1 to the operation count, exactly for REFUSED. Else 0. */
        public final int refused;
        public final List<Operation> operations;
        public final List<Output> outputs;

        public Transaction(String installation, String transaction, String component, String plan,
                String authorization, String certificate, String key, int sdkMin, int sdkMax,
                TransactionState state, int refused, List<Operation> operations, List<Output> outputs) {
            DeploymentRecords.checkId(installation, "installation", false);
            DeploymentRecords.checkId(transaction, "transaction", false);
            DeploymentRecords.checkPackage(component);
            DeploymentRecords.checkId(plan, "plan", false);
            DeploymentRecords.checkId(authorization, "authorization", false);
            DeploymentRecords.checkDigest(certificate, "certificate", false);
            DeploymentRecords.checkDigest(key, "key", false);
            if (sdkMin < 1 || sdkMax < sdkMin || sdkMax > 0xffff) throw DeploymentRecords.invalid("SDK range");
            this.state = Objects.requireNonNull(state, "state");
            List<Operation> ops = List.copyOf(operations);
            List<Output> outs = List.copyOf(outputs);
            if (ops.size() != 3 && ops.size() != 6) throw DeploymentRecords.invalid("three operations for each APK");
            if (outs.size() != ops.size() / 3 * 2) throw DeploymentRecords.invalid("two outputs for each APK");
            List<Role> roles = new ArrayList<>();
            for (int i = 0; i < ops.size(); i += 3) {
                Role role = ops.get(i).role;
                if (!roles.isEmpty() && role.code <= roles.get(roles.size() - 1).code) {
                    throw DeploymentRecords.invalid("roles out of order");
                }
                roles.add(role);
                for (int j = 0; j < 3; j++) {
                    Operation op = ops.get(i + j);
                    if (op.role != role || op.scheme != Scheme.values()[j]) {
                        throw DeploymentRecords.invalid("operations out of order");
                    }
                }
            }
            java.util.Set<String> ids = new java.util.HashSet<>();
            for (Operation op : ops) {
                if (!ids.add(op.id) || op.id.equals(transaction)) throw DeploymentRecords.invalid("an operation ID twice");
            }
            boolean completed = state == TransactionState.COMPLETED;
            for (int i = 0; i < outs.size(); i++) {
                Output out = outs.get(i);
                if (out.role != roles.get(i / 2) || out.member != Member.values()[i % 2]) {
                    throw DeploymentRecords.invalid("outputs out of order");
                }
                if (completed == out.digest.equals(DeploymentRecords.NO_DIGEST)) {
                    throw DeploymentRecords.invalid("output digests exactly when COMPLETED");
                }
                if (i % 2 == 1 && (!out.input.equals(outs.get(i - 1).input)
                        || !out.inputEntries.equals(outs.get(i - 1).inputEntries)
                        || out.versionCode != outs.get(i - 1).versionCode)) {
                    throw DeploymentRecords.invalid("an APK's two outputs name different inputs");
                }
            }
            if ((state == TransactionState.REFUSED) == (refused == 0) || refused < 0 || refused > ops.size()) {
                throw DeploymentRecords.invalid("a refused operation exactly for REFUSED");
            }
            this.installation = installation;
            this.transaction = transaction;
            this.component = component;
            this.plan = plan;
            this.authorization = authorization;
            this.certificate = certificate;
            this.key = key;
            this.sdkMin = sdkMin;
            this.sdkMax = sdkMax;
            this.refused = refused;
            this.operations = ops;
            this.outputs = outs;
        }

        /** The same transaction in another state, with its refused operation and outputs. */
        public Transaction with(TransactionState next, int refusedOperation, List<Output> nextOutputs) {
            return new Transaction(installation, transaction, component, plan, authorization, certificate, key,
                    sdkMin, sdkMax, next, refusedOperation, operations, nextOutputs);
        }

        /** The roles it signs, in order. */
        public List<Role> roles() {
            List<Role> roles = new ArrayList<>();
            for (int i = 0; i < operations.size(); i += 3) roles.add(operations.get(i).role);
            return roles;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Transaction
                    && Arrays.equals(encodeTransaction(this), encodeTransaction((Transaction) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodeTransaction(this)); }
    }

    /** The v4 check of the sidecar against base.apk. Version 1 knows only a passed check. */
    public enum V4Check {
        VERIFIED(1);

        final int code;

        V4Check(int code) { this.code = code; }

        static V4Check of(int code) {
            for (V4Check v : values()) if (v.code == code) return v;
            throw DeploymentRecords.invalid("unknown v4 check");
        }
    }

    /** The canonical manifest of one bundle. */
    public static final class Manifest {
        public final String installation;
        public final String component;
        public final Role role;
        /** The signing transaction. The operations' own IDs stay in the signer's records. */
        public final String transaction;
        /** The SHA-256 of the exact input APK bytes. */
        public final String input;
        /** The input's identity: the SHA-256 over its ZIP entries outside its signatures (ApkEntries). */
        public final String inputEntries;
        public final long versionCode;
        public final String apk;
        public final long apkBytes;
        public final String idsig;
        public final long idsigBytes;
        public final String certificate;
        public final String key;
        public final int schemes;
        public final int sdkMin;
        public final int sdkMax;
        public final V4Check v4;

        /**
         * The schemes are each checked explicitly over the APK's declared SDK range. Signing may
         * reproduce its input exactly, so the output may equal the input.
         */
        public Manifest(String installation, String component, Role role, String transaction, String input,
                String inputEntries, long versionCode, String apk, long apkBytes, String idsig, long idsigBytes,
                String certificate, String key, int schemes, int sdkMin, int sdkMax, V4Check v4) {
            DeploymentRecords.checkId(installation, "installation", false);
            DeploymentRecords.checkPackage(component);
            this.role = Objects.requireNonNull(role, "role");
            DeploymentRecords.checkId(transaction, "transaction", false);
            for (String d : List.of(input, inputEntries, apk, idsig, certificate, key)) {
                DeploymentRecords.checkDigest(d, "digest", false);
            }
            if (versionCode <= 0) throw DeploymentRecords.invalid("versionCode not positive");
            if (apkBytes <= 0 || idsigBytes <= 0) throw DeploymentRecords.invalid("an empty member");
            if (schemes != SCHEMES) throw DeploymentRecords.invalid("schemes other than v2, v3 and v4");
            if (sdkMin < 1 || sdkMax < sdkMin || sdkMax > 0xffff) throw DeploymentRecords.invalid("SDK range");
            this.installation = installation;
            this.component = component;
            this.transaction = transaction;
            this.input = input;
            this.inputEntries = inputEntries;
            this.versionCode = versionCode;
            this.apk = apk;
            this.apkBytes = apkBytes;
            this.idsig = idsig;
            this.idsigBytes = idsigBytes;
            this.certificate = certificate;
            this.key = key;
            this.schemes = schemes;
            this.sdkMin = sdkMin;
            this.sdkMax = sdkMax;
            this.v4 = Objects.requireNonNull(v4, "v4");
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Manifest && Arrays.equals(encodeManifest(this), encodeManifest((Manifest) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodeManifest(this)); }
    }

    /** The bundles of one plan that become visible together, the variant first. */
    public static final class Publication {
        public final String installation;
        public final String plan;
        public final String component;
        /** The bundle IDs: the variant, then the restoration when there is one. */
        public final List<String> bundles;
        /** Each bundle's signing transaction, in the same order. */
        public final List<String> transactions;
        /** Informational. */
        public final long publishedAt;

        public Publication(String installation, String plan, String component, List<String> bundles,
                List<String> transactions, long publishedAt) {
            DeploymentRecords.checkId(installation, "installation", false);
            DeploymentRecords.checkId(plan, "plan", false);
            DeploymentRecords.checkPackage(component);
            List<String> copy = new ArrayList<>(bundles);
            List<String> signing = new ArrayList<>(transactions);
            if (copy.isEmpty() || copy.size() > 2) throw DeploymentRecords.invalid("one or two bundles");
            if (signing.size() != copy.size()) throw DeploymentRecords.invalid("a transaction for each bundle");
            for (String b : copy) DeploymentRecords.checkDigest(b, "bundle", false);
            for (String t : signing) DeploymentRecords.checkId(t, "transaction", false);
            if (copy.size() == 2 && copy.get(0).equals(copy.get(1))) throw DeploymentRecords.invalid("a bundle twice");
            this.installation = installation;
            this.plan = plan;
            this.component = component;
            this.bundles = Collections.unmodifiableList(copy);
            this.transactions = Collections.unmodifiableList(signing);
            this.publishedAt = publishedAt;
        }

        /** The role of the bundle at an index: the variant first, then its restoration. */
        public static Role roleAt(int index) { return index == 0 ? Role.VARIANT : Role.RESTORATION; }

        @Override
        public boolean equals(Object other) {
            return other instanceof Publication
                    && Arrays.equals(encodePublication(this), encodePublication((Publication) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encodePublication(this)); }
    }

    /** What a record of a later version concerns. It decides nothing else. */
    public static final class Prefix {
        public final int type;
        public final int version;
        public final String installation;
        /** The manifest's component, or the publication's. */
        public final String component;
        /** The manifest's signing transaction, the publication's plan, or the transaction's own ID. */
        public final String id;

        Prefix(int type, int version, String installation, String component, String id) {
            this.type = type;
            this.version = version;
            this.installation = installation;
            this.component = component;
            this.id = id;
        }
    }

    /** The bundle ID: the SHA-256 of the manifest's whole frame. */
    public static String bundleId(Manifest m) { return DeploymentRecords.sha256Hex(encodeManifest(m)); }

    // ------------------------------------------------------------------ encoding

    public static byte[] encodeManifest(Manifest m) {
        Out out = new Out(MANIFEST);
        out.id(m.installation);
        out.text(m.component);
        out.u8(m.role.code);
        out.id(m.transaction);
        out.raw(m.input);
        out.raw(m.inputEntries);
        out.i64(m.versionCode);
        out.raw(m.apk);
        out.i64(m.apkBytes);
        out.raw(m.idsig);
        out.i64(m.idsigBytes);
        out.raw(m.certificate);
        out.raw(m.key);
        out.u8(m.schemes);
        out.u16(m.sdkMin);
        out.u16(m.sdkMax);
        out.u8(m.v4.code);
        return out.seal();
    }

    public static byte[] encodePublication(Publication p) {
        Out out = new Out(PUBLICATION);
        out.id(p.installation);
        out.id(p.plan);
        out.text(p.component);
        out.u8(p.bundles.size());
        for (int i = 0; i < p.bundles.size(); i++) {
            out.raw(p.bundles.get(i));
            out.u8(Publication.roleAt(i).code);
            out.id(p.transactions.get(i));
        }
        out.i64(p.publishedAt);
        return out.seal();
    }

    public static byte[] encodeTransaction(Transaction t) {
        Out out = new Out(TRANSACTION);
        out.id(t.installation);
        out.id(t.transaction);
        out.text(t.component);
        out.id(t.plan);
        out.id(t.authorization);
        out.raw(t.certificate);
        out.raw(t.key);
        out.u16(t.sdkMin);
        out.u16(t.sdkMax);
        out.u8(t.state.code);
        out.u8(t.refused);
        out.u8(t.operations.size());
        for (Operation op : t.operations) {
            out.id(op.id);
            out.u8(op.role.code);
            out.u8(op.scheme.code);
        }
        out.u8(t.outputs.size());
        for (Output o : t.outputs) {
            out.u8(o.role.code);
            out.u8(o.member.code);
            out.u8(o.facts);
            out.raw(o.input);
            out.raw(o.inputEntries);
            out.i64(o.versionCode);
            out.raw(o.digest);
            out.i64(o.bytes);
        }
        return out.seal();
    }

    public static Transaction decodeTransaction(byte[] record) {
        In in = new In(record, TRANSACTION, false);
        String installation = in.hex(16);
        String transaction = in.hex(16);
        String component = in.text();
        String plan = in.hex(16);
        String authorization = in.hex(16);
        String certificate = in.hex(32);
        String key = in.hex(32);
        int sdkMin = in.u16();
        int sdkMax = in.u16();
        TransactionState state = TransactionState.of(in.u8());
        int refused = in.u8();
        int count = in.u8();
        if (count != 3 && count != 6) throw DeploymentRecords.invalid("three operations for each APK");
        List<Operation> ops = new ArrayList<>();
        for (int i = 0; i < count; i++) ops.add(new Operation(in.hex(16), Role.of(in.u8()), Scheme.of(in.u8())));
        int outputs = in.u8();
        if (outputs != count / 3 * 2) throw DeploymentRecords.invalid("two outputs for each APK");
        List<Output> outs = new ArrayList<>();
        for (int i = 0; i < outputs; i++) {
            Role role = Role.of(in.u8());
            Member member = Member.of(in.u8());
            int facts = in.u8();
            String input = in.hex(32);
            String entries = in.hex(32);
            long version = in.i64();
            String digest = in.hex(32);
            long bytes = in.i64();
            outs.add(new Output(role, member, facts, input, entries, version, digest, bytes));
        }
        in.finish();
        return new Transaction(installation, transaction, component, plan, authorization, certificate, key, sdkMin,
                sdkMax, state, refused, ops, outs);
    }

    public static Manifest decodeManifest(byte[] record) {
        In in = new In(record, MANIFEST, false);
        String installation = in.hex(16);
        String component = in.text();
        Role role = Role.of(in.u8());
        String transaction = in.hex(16);
        String input = in.hex(32);
        String entries = in.hex(32);
        long version = in.i64();
        String apk = in.hex(32);
        long apkBytes = in.i64();
        String idsig = in.hex(32);
        long idsigBytes = in.i64();
        String certificate = in.hex(32);
        String key = in.hex(32);
        int schemes = in.u8();
        int sdkMin = in.u16();
        int sdkMax = in.u16();
        V4Check v4 = V4Check.of(in.u8());
        in.finish();
        return new Manifest(installation, component, role, transaction, input, entries, version, apk, apkBytes, idsig,
                idsigBytes, certificate, key, schemes, sdkMin, sdkMax, v4);
    }

    public static Publication decodePublication(byte[] record) {
        In in = new In(record, PUBLICATION, false);
        String installation = in.hex(16);
        String plan = in.hex(16);
        String component = in.text();
        int count = in.u8();
        if (count < 1 || count > 2) throw DeploymentRecords.invalid("one or two bundles");
        List<String> bundles = new ArrayList<>();
        List<String> transactions = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            bundles.add(in.hex(32));
            if (Role.of(in.u8()) != Publication.roleAt(i)) throw DeploymentRecords.invalid("roles out of order");
            transactions.add(in.hex(16));
        }
        long publishedAt = in.i64();
        in.finish();
        return new Publication(installation, plan, component, bundles, transactions, publishedAt);
    }

    /**
     * The stable prefix of an intact frame of a later version: the installation, then the
     * component and signing transaction of a manifest, the plan and component of a publication,
     * or the transaction and component of a signing transaction. It reads nothing after the prefix.
     */
    public static Prefix decodePrefix(byte[] record) {
        In in = new In(record, 0, true);
        if (in.version <= VERSION) throw DeploymentRecords.invalid("no prefix reading of this version");
        String installation = in.hex(16);
        DeploymentRecords.checkId(installation, "installation", false);
        if (in.type == MANIFEST) {
            String component = in.text();
            in.u8(); // The role: a later version may add codes.
            String transaction = in.hex(16);
            DeploymentRecords.checkId(transaction, "transaction", false);
            return new Prefix(in.type, in.version, installation, component, transaction);
        }
        String plan = in.hex(16);
        DeploymentRecords.checkId(plan, "plan", false);
        String component = in.text();
        // A publication's plan, or a signing transaction's own ID.
        return new Prefix(in.type, in.version, installation, component, plan);
    }

    /** The type and version of an intact artifact frame, or null. */
    public static int[] intactFrame(byte[] record) {
        try {
            In in = new In(record, 0, true);
            return new int[] {in.type, in.version};
        } catch (IllegalArgumentException damaged) {
            return null;
        }
    }

    private static final class Out {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        Out(int type) {
            i32(DeploymentRecords.MAGIC);
            u16(type);
            u16(VERSION);
            i32(0);
        }

        void u8(int v) { bytes.write(v); }

        void u16(int v) {
            u8(v & 0xff);
            u8((v >>> 8) & 0xff);
        }

        void i32(int v) { for (int i = 0; i < 4; i++) u8((v >>> (8 * i)) & 0xff); }

        void i64(long v) { for (int i = 0; i < 8; i++) u8((int) ((v >>> (8 * i)) & 0xff)); }

        void raw(String hex) {
            for (int i = 0; i < hex.length(); i += 2) u8(Integer.parseInt(hex.substring(i, i + 2), 16));
        }

        void id(String hex) { raw(hex); }

        void text(String value) {
            byte[] t = value.getBytes(StandardCharsets.US_ASCII);
            u16(t.length);
            bytes.write(t, 0, t.length);
        }

        byte[] seal() {
            byte[] body = bytes.toByteArray();
            int length = body.length + CHECKSUM_BYTES;
            for (int i = 0; i < 4; i++) body[8 + i] = (byte) (length >>> (8 * i));
            byte[] sum = DeploymentRecords.sha256(body, body.length);
            byte[] record = Arrays.copyOf(body, length);
            System.arraycopy(sum, 0, record, body.length, CHECKSUM_BYTES);
            return record;
        }
    }

    private static final class In {
        private final byte[] bytes;
        private final int end;
        final int type;
        final int version;
        private int at = FRAME_BYTES;

        // Checks the size, the frame and the checksum first, then the type and the version.
        In(byte[] record, int expectedType, boolean anyVersion) {
            Objects.requireNonNull(record, "record");
            if (record.length < FRAME_BYTES + CHECKSUM_BYTES || record.length > MAX_BYTES) {
                throw DeploymentRecords.invalid("record size");
            }
            bytes = record.clone();
            if (le(0, 4) != (DeploymentRecords.MAGIC & 0xffffffffL)) throw DeploymentRecords.invalid("not an artifact record");
            if (le(8, 4) != bytes.length) throw DeploymentRecords.invalid("length differs");
            end = bytes.length - CHECKSUM_BYTES;
            byte[] sum = DeploymentRecords.sha256(bytes, end);
            if (!Arrays.equals(sum, Arrays.copyOfRange(bytes, end, bytes.length))) {
                throw DeploymentRecords.invalid("checksum differs");
            }
            type = (int) le(4, 2);
            version = (int) le(6, 2);
            if (type != MANIFEST && type != PUBLICATION && type != TRANSACTION) {
                throw DeploymentRecords.invalid("not an artifact record type");
            }
            if (expectedType != 0 && type != expectedType) throw DeploymentRecords.invalid("another record type");
            if (!anyVersion && version != VERSION) throw DeploymentRecords.invalid("unknown version");
        }

        private long le(int from, int count) {
            long v = 0;
            for (int i = count - 1; i >= 0; i--) v = (v << 8) | (bytes[from + i] & 0xff);
            return v;
        }

        private int take(int count) {
            if (at + count > end) throw DeploymentRecords.invalid("truncated");
            int from = at;
            at += count;
            return from;
        }

        int u8() { return (int) le(take(1), 1); }

        int u16() { return (int) le(take(2), 2); }

        long i64() { return le(take(8), 8); }

        String hex(int count) {
            int from = take(count);
            StringBuilder s = new StringBuilder();
            for (int i = from; i < from + count; i++) s.append(String.format("%02x", bytes[i] & 0xff));
            return s.toString();
        }

        String text() {
            int length = u16();
            int from = take(length);
            String value = new String(bytes, from, length, StandardCharsets.US_ASCII);
            DeploymentRecords.checkPackage(value);
            return value;
        }

        void finish() {
            if (at != end) throw DeploymentRecords.invalid("trailing bytes");
        }
    }
}
