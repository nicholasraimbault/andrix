// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import static dev.andrix.lab.notice.Cases.check;

import android.app.ActivityOptions;
import android.app.IActivityTaskManager;
import android.app.WaitResult;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserManager;
import android.system.Os;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * The actual helper, provider, writer holder and disk classes run on the host against explicit
 * stubs of the Android classes they use. The stubs model the pinned sources' rules that matter
 * here: the share identity key of ActivityOptions.toBundle, the launched UID that
 * ActivityClientController reveals only with identity sharing, and ContentProvider's entry points.
 * They are not Android, its IPC, its permission checks or its file system. The modeled activity
 * runs the actual Delivery.decide against a store and sends its decision to the helper's report
 * binder as NoticeActivity does.
 *
 * <p>Modes: no argument runs every case with the actual sources; "no-identity" runs the identity
 * case against a helper built without identity sharing and expects the activity to refuse;
 * "signature" runs the signature case against a stub interface of another shape and expects
 * the helper to refuse before any call. The first argument after the mode is a scratch directory.
 */
public final class ModelTests {
    static final int INVALID_UID = -1;
    static final int APP_UID = 10 * 100000 + 10123;

    /** One recorded call of the model's activity task manager. */
    static final class Call {
        final Method method;
        final Object[] args;

        Call(Method method, Object[] args) {
            this.method = method;
            this.args = args;
        }
    }

    static final List<Call> CALLS = new ArrayList<>();
    static final List<String> DECISIONS = new ArrayList<>();
    static int startResult;
    static RuntimeException startThrows;
    /** The modeled activity's store; with none, the activity sends no decision. */
    static ReceiptStore activityStore;
    static String reportDescriptor = NoticeRequest.REPORT_DESCRIPTOR;
    static int reportVersion = NoticeRequest.REPORT_VERSION;
    static int reporterUid = APP_UID;
    /** When set, the activity sends this text instead of its decision. */
    static String reportText;
    /** When set, the activity sends this second report after its decision. */
    static String laterReport;

    private ModelTests() {}

    /** The model's manager, a proxy, so it fits whatever shape the stub interface has. */
    static void installManager() {
        CALLS.clear();
        Class<?>[] shape = {IActivityTaskManager.class};
        IActivityTaskManager.Stub.manager = (IActivityTaskManager) Proxy.newProxyInstance(
                ModelTests.class.getClassLoader(), shape, (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) return method.invoke(new Object(), args);
                    CALLS.add(new Call(method, args));
                    if (startThrows != null) throw startThrows;
                    if (method.getReturnType() != WaitResult.class) return 0;
                    WaitResult result = new WaitResult();
                    result.result = startResult;
                    if (startResult == 0) {
                        result.who = ((Intent) args[3]).getComponent();
                        result.totalTime = 321;
                        result.launchState = 1;
                        if (activityStore != null) activity((Intent) args[3], (Bundle) args[10]);
                    }
                    return result;
                });
    }

    /**
     * The modeled activity: its decision before anything is shown, by the actual Delivery.decide
     * on the request it received, sent one way to the helper's report binder as the app's UID.
     */
    static void activity(Intent intent, Bundle options) throws RemoteException {
        Bundle extras = intent.getExtras();
        IBinder report = extras.getBinder(NoticeRequest.KEY_REPORT);
        String decision;
        try {
            NoticeRequest request = NoticeRequest.fromExtras(extras(extras));
            decision = Delivery.decide(launchedFromUid(2000, options), APP_UID, 5, request, activityStore);
        } catch (IllegalArgumentException refused) {
            decision = NoticeRequest.REFUSED + "request";
        }
        DECISIONS.add(decision);
        if (report == null) return;
        send(report, reportText == null ? decision : reportText);
        if (laterReport != null) send(report, laterReport);
    }

    /** One report in NoticeActivity's form, sent one way as the reporter's UID. */
    static void send(IBinder report, String text) throws RemoteException {
        Parcel data = Parcel.obtain();
        data.writeInterfaceToken(reportDescriptor);
        data.writeInt(reportVersion);
        data.writeString(text);
        int saved = Binder.callingUid;
        Binder.callingUid = reporterUid;
        try {
            report.transact(IBinder.FIRST_CALL_TRANSACTION, data, null, IBinder.FLAG_ONEWAY);
        } finally {
            Binder.callingUid = saved;
            data.recycle();
        }
    }

    /**
     * The launched UID the activity observes, as ActivityClientController.getUid and
     * canGetLaunchedFromLocked decide for an ordinary app that is not signed with the platform key
     * and not launched for a result: the launcher's UID only when it shared its identity, or when
     * it is the activity's own UID; otherwise INVALID_UID.
     */
    static int launchedFromUid(int launcherUid, Bundle options) {
        boolean shared = options != null && options.getBoolean(ActivityOptions.KEY_SHARE_IDENTITY, false);
        return shared || launcherUid == APP_UID ? launcherUid : INVALID_UID;
    }

    /** The activity's typed extras over the stub Bundle, by the same rule as NoticeActivity's. */
    static NoticeRequest.Extras extras(Bundle bundle) {
        return new NoticeRequest.Extras() {
            @Override
            public Set<String> keys() {
                return bundle.keySet();
            }

            @Override
            public String string(String key) {
                return bundle.getString(key);
            }

            @Override
            public Integer integer(String key) {
                int low = bundle.getInt(key, Integer.MIN_VALUE);
                return low == bundle.getInt(key, Integer.MAX_VALUE) ? Integer.valueOf(low) : null;
            }

            @Override
            public Long longValue(String key) {
                long low = bundle.getLong(key, Long.MIN_VALUE);
                return low == bundle.getLong(key, Long.MAX_VALUE) ? Long.valueOf(low) : null;
            }
        };
    }

    static String run(String[] args, int[] status) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(bytes, true, StandardCharsets.US_ASCII);
        status[0] = NoticePresent.run(args, out, 100);
        return bytes.toString(StandardCharsets.US_ASCII);
    }

    static void reset() {
        Process.uid = 2000;
        ServiceManager.absent = false;
        ServiceManager.LOOKUPS.clear();
        startResult = 0;
        startThrows = null;
        activityStore = new ReceiptStore(new MemoryDisk(), new NoticeHostTests.Counter());
        reportDescriptor = NoticeRequest.REPORT_DESCRIPTOR;
        reportVersion = NoticeRequest.REPORT_VERSION;
        reporterUid = APP_UID;
        reportText = null;
        laterReport = null;
        DECISIONS.clear();
        installManager();
    }

    /** A store whose request key already holds a row of this request's key: the honest repeat, or
     * one of another challenge, which conflicts. */
    static ReceiptStore storeWith(NoticeRequest first) {
        MemoryDisk disk = new MemoryDisk();
        ReceiptRow row = ReceiptRow.of(first, APP_UID, 5, 3000, 1000, 2000, 2100, 2500);
        disk.place(row.key(), row.encode(), true);
        return new ReceiptStore(disk, new NoticeHostTests.Counter());
    }

    public static void main(String[] args) throws IOException {
        Cases cases = new Cases();
        String mode = args.length > 0 ? args[0] : "all";
        Path scratch = Paths.get(args.length > 1 ? args[1] : System.getProperty("java.io.tmpdir"));
        UserManager.SERIALS.put(10, 5L);
        Path data = scratch.resolve("de");
        Files.createDirectories(data);
        Context.dataDir = data.toFile();
        if (mode.equals("no-identity")) {
            identity(cases, false);
        } else if (mode.equals("signature")) {
            signature(cases);
        } else {
            helper(cases);
            identity(cases, true);
            opening(cases, data);
            provider(cases, data);
            disk(cases, scratch.resolve("disk"));
        }
        System.exit(cases.finish());
    }

    // ------------------------------------------------------------------ the helper

    static void helper(Cases cases) {
        cases.run("helper / one startActivityAndWait as com.android.shell, explicit, typed and sharing identity",
                problems -> {
            reset();
            NoticeRequest request = NoticeHostTests.notice();
            int[] status = new int[1];
            String out = run(request.arguments(), status);
            check(problems, status[0] == 0, "status " + status[0]);
            check(problems, out.equals("andrix-notice-present-v2\nresult=0\ntimeout=false\n"
                    + "who=dev.andrix.lab.notice/.NoticeActivity\ntotal_time=321\nlaunch_state=1\n"
                    + "activity=presented\nreporter=" + APP_UID + "\n"), "output " + out);
            check(problems, ServiceManager.LOOKUPS.equals(Arrays.asList("activity_task")), "one service lookup");
            check(problems, CALLS.size() == 1, "one call " + CALLS.size());
            Call call = CALLS.get(0);
            Object[] a = call.args;
            check(problems, call.method.getName().equals("startActivityAndWait"), "the method");
            check(problems, a[0] == null && "com.android.shell".equals(a[1]) && a[2] == null && a[4] == null
                    && a[5] == null && a[6] == null && Integer.valueOf(0).equals(a[7])
                    && Integer.valueOf(0).equals(a[8]) && a[9] == null, "the fixed arguments");
            check(problems, Integer.valueOf(10).equals(a[11]), "the request's user " + a[11]);
            Intent intent = (Intent) a[3];
            check(problems, "dev.andrix.lab.notice.action.PRESENT".equals(intent.getAction())
                    && new ComponentName("dev.andrix.lab.notice", "dev.andrix.lab.notice.NoticeActivity")
                            .equals(intent.getComponent())
                    && intent.getFlags() == (Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK),
                    "the explicit intent");
            NoticeRequest received = NoticeRequest.fromExtras(extras(intent.getExtras()));
            check(problems, Arrays.equals(received.arguments(), request.arguments()), "the typed extras");
            check(problems, intent.getExtras().getBinder(NoticeRequest.KEY_REPORT) instanceof Binder,
                    "the report binder beside the request");
            Bundle options = (Bundle) a[10];
            check(problems, options.keySet().equals(Set.of(ActivityOptions.KEY_SHARE_IDENTITY))
                    && options.getBoolean(ActivityOptions.KEY_SHARE_IDENTITY, false), "identity sharing only");
        });
        cases.run("helper / refusals before any lookup or start", problems -> {
            int[] status = new int[1];
            for (int uid : new int[] {0, 1000, 10123, APP_UID}) {
                reset();
                Process.uid = uid;
                String out = run(NoticeHostTests.notice().arguments(), status);
                check(problems, status[0] == 3 && out.equals("andrix-notice-present-v2\nerror=identity\n")
                        && ServiceManager.LOOKUPS.isEmpty() && CALLS.isEmpty(), "uid " + uid);
            }
            reset();
            String[] bad = NoticeHostTests.notice().arguments();
            bad[12] = Forms.sha256("other");
            String out = run(bad, status);
            check(problems, status[0] == 2 && out.equals("andrix-notice-present-v2\nerror=arguments\n")
                    && ServiceManager.LOOKUPS.isEmpty(), "malformed arguments");
            reset();
            ServiceManager.absent = true;
            out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 4 && out.endsWith("error=service-absent\n") && CALLS.isEmpty(),
                    "no service");
        });
        cases.run("helper / a refused start and a fatal start code are reported, never as success", problems -> {
            int[] status = new int[1];
            reset();
            startThrows = new SecurityException("permission");
            String out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 6 && out.endsWith("error=start:java.lang.SecurityException\n"), out);
            reset();
            startResult = -94;
            out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 7 && out.contains("\nresult=-94\n") && out.contains("\nwho=null\n")
                    && out.endsWith("\nactivity=unreported\nreporter=-1\n") && DECISIONS.isEmpty(), out);
        });
        cases.run("helper / the activity's decision is the helper's result: a conflicting row is refused",
                problems -> {
            NoticeRequest request = NoticeHostTests.notice();
            NoticeRequest other = NoticeRequest.notice(NoticeHostTests.INSTALLATION, NoticeHostTests.COMPONENT,
                    NoticeHostTests.PLAN, NoticeHostTests.TICKET, NoticeHostTests.INDEX, NoticeHostTests.BOOT,
                    "9d".repeat(16), NoticeHostTests.TEXT, NoticeHostTests.USER, NoticeHostTests.SERIAL);
            int[] status = new int[1];
            reset();
            String out = run(request.arguments(), status);
            check(problems, status[0] == 0 && out.endsWith("\nactivity=presented\nreporter=" + APP_UID + "\n"),
                    "an absent key is presented " + out);
            reset();
            activityStore = storeWith(request);
            out = run(request.arguments(), status);
            check(problems, status[0] == 0 && out.endsWith("\nactivity=presented\nreporter=" + APP_UID + "\n"),
                    "the honest repeat is presented " + out);
            reset();
            MemoryDisk disk = new MemoryDisk();
            ReceiptRow first = ReceiptRow.of(other, APP_UID, 5, 3000, 1000, 2000, 2100, 2500);
            disk.place(first.key(), first.encode(), true);
            activityStore = new ReceiptStore(disk, new NoticeHostTests.Counter());
            out = run(request.arguments(), status);
            check(problems, status[0] == 9 && out.endsWith("\nactivity=refused:conflict\nreporter=" + APP_UID + "\n"),
                    "a conflicting row refuses " + out);
            check(problems, Arrays.equals(disk.bytes(first.key()), first.encode()) && disk.listing().size() == 1,
                    "nothing written");
            for (String operation : disk.operations) {
                check(problems, operation.startsWith("exists ") || operation.startsWith("read "),
                        "the decision only reads: " + operation);
            }
            reset();
            MemoryDisk damaged = new MemoryDisk();
            damaged.place(first.key(), "damaged".getBytes(StandardCharsets.US_ASCII), true);
            activityStore = new ReceiptStore(damaged, new NoticeHostTests.Counter());
            out = run(request.arguments(), status);
            check(problems, status[0] == 9 && out.contains("\nactivity=refused:corrupt\n"), "a corrupt key " + out);
            reset();
            activityStore = new ReceiptStore(disk, new NoticeHostTests.Counter());
            laterReport = NoticeRequest.PRESENTED;
            out = run(request.arguments(), status);
            check(problems, status[0] == 9 && out.endsWith("\nactivity=refused:conflict\nreporter=" + APP_UID + "\n"),
                    "a later report changes nothing " + out);
        });
        cases.run("helper / without a decision of known form from the recipient's app, nothing is reported",
                problems -> {
            int[] status = new int[1];
            String unreported = "\nactivity=unreported\nreporter=-1\n";
            reset();
            activityStore = null;
            String out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 10 && out.endsWith(unreported), "no decision " + out);
            reset();
            reporterUid = 11 * 100000 + 10123;
            out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 10 && out.endsWith(unreported) && DECISIONS.size() == 1,
                    "another user's app " + out);
            reset();
            reporterUid = 10 * 100000 + 1000;
            out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 10 && out.endsWith(unreported), "a system UID " + out);
            reset();
            reportDescriptor = "another.Interface";
            out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 10 && out.endsWith(unreported), "another interface " + out);
            reset();
            reportVersion = NoticeRequest.REPORT_VERSION + 1;
            out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 10 && out.endsWith(unreported), "another version " + out);
            for (String text : new String[] {NoticeRequest.REFUSED + "other", "shown", ""}) {
                reset();
                reportText = text;
                out = run(NoticeHostTests.notice().arguments(), status);
                check(problems, status[0] == 10 && out.endsWith(unreported), "an unknown decision " + out);
            }
        });
    }

    /** The activity's decision for the helper's one call: present with identity sharing, refuse
     * without it. */
    static void identity(Cases cases, boolean expectPresent) {
        cases.run("identity / the activity observes the shell launcher only with identity sharing" + (expectPresent
                ? "" : " (a helper without it is refused)"), problems -> {
            reset();
            int[] status = new int[1];
            String out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, CALLS.size() == 1 && DECISIONS.size() == 1, "one started call and decision");
            Object[] a = CALLS.get(0).args;
            int launched = launchedFromUid(2000, (Bundle) a[10]);
            if (expectPresent) {
                check(problems, launched == 2000 && status[0] == 0 && DECISIONS.get(0).equals("presented")
                        && out.contains("\nactivity=presented\n"), "presented " + out);
            } else {
                check(problems, launched == INVALID_UID && status[0] == 9
                        && DECISIONS.get(0).equals("refused:launcher") && out.contains("\nactivity=refused:launcher\n"),
                        "refused " + out);
            }
        });
    }

    static void signature(Cases cases) {
        cases.run("helper / a Binder interface of another shape is refused before any call", problems -> {
            reset();
            int[] status = new int[1];
            String out = run(NoticeHostTests.notice().arguments(), status);
            check(problems, status[0] == 5 && out.equals("andrix-notice-present-v2\nerror=signature\n"), out);
            check(problems, CALLS.isEmpty(), "no call");
        });
    }

    // ------------------------------------------------------------------ the provider

    interface Entry {
        Object call(ReceiptProvider provider) throws Exception;
    }

    static List<Object[]> entries() {
        Uri rows = Uri.parse(ProviderPolicy.ROWS);
        List<Object[]> all = new ArrayList<>();
        all.add(new Object[] {"query with a selection", (Entry) p -> p.query(rows, null, null, null, null)});
        all.add(new Object[] {"query with a selection and signal", (Entry) p -> p.query(rows, null, null, null, null,
                null)});
        all.add(new Object[] {"getType", (Entry) p -> p.getType(rows)});
        all.add(new Object[] {"getTypeAnonymous", (Entry) p -> p.getTypeAnonymous(rows)});
        all.add(new Object[] {"getStreamTypes", (Entry) p -> p.getStreamTypes(rows, "*/*")});
        all.add(new Object[] {"insert", (Entry) p -> p.insert(rows, null)});
        all.add(new Object[] {"insert with extras", (Entry) p -> p.insert(rows, null, null)});
        all.add(new Object[] {"bulkInsert", (Entry) p -> p.bulkInsert(rows, new android.content.ContentValues[1])});
        all.add(new Object[] {"update", (Entry) p -> p.update(rows, null, null, null)});
        all.add(new Object[] {"update with extras", (Entry) p -> p.update(rows, null, null)});
        all.add(new Object[] {"delete", (Entry) p -> p.delete(rows, null, null)});
        all.add(new Object[] {"delete with extras", (Entry) p -> p.delete(rows, (Bundle) null)});
        all.add(new Object[] {"applyBatch", (Entry) p -> p.applyBatch(new ArrayList<>())});
        all.add(new Object[] {"applyBatch with authority", (Entry) p -> p.applyBatch(ProviderPolicy.AUTHORITY,
                new ArrayList<>())});
        all.add(new Object[] {"call", (Entry) p -> p.call("write", null, null)});
        all.add(new Object[] {"call with authority", (Entry) p -> p.call(ProviderPolicy.AUTHORITY, "write", null,
                null)});
        all.add(new Object[] {"openFile read", (Entry) p -> p.openFile(rows, "r")});
        all.add(new Object[] {"openFile write", (Entry) p -> p.openFile(rows, "w")});
        all.add(new Object[] {"openFile with signal", (Entry) p -> p.openFile(rows, "rw", null)});
        all.add(new Object[] {"openAssetFile", (Entry) p -> p.openAssetFile(rows, "w")});
        all.add(new Object[] {"openAssetFile with signal", (Entry) p -> p.openAssetFile(rows, "w", null)});
        all.add(new Object[] {"openTypedAssetFile", (Entry) p -> p.openTypedAssetFile(rows, "*/*", null)});
        all.add(new Object[] {"openTypedAssetFile with signal", (Entry) p -> p.openTypedAssetFile(rows, "*/*", null,
                null)});
        all.add(new Object[] {"canonicalize", (Entry) p -> p.canonicalize(rows)});
        all.add(new Object[] {"uncanonicalize", (Entry) p -> p.uncanonicalize(rows)});
        all.add(new Object[] {"refresh", (Entry) p -> p.refresh(rows, null, null)});
        return all;
    }

    /** The exception class an entry throws, or "none". */
    static String outcome(ReceiptProvider provider, Entry entry) {
        try {
            entry.call(provider);
            return "none";
        } catch (Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    /** The writer holder opens the device encrypted data directory's store and creates nothing. It
     * keeps one store per process, so this runs before the provider writes into the same place. */
    static void opening(Cases cases, Path data) {
        cases.run("disk / the store is the device encrypted data directory's, and opening it creates nothing",
                problems -> {
            int before = Context.deviceProtectedContexts;
            Os.CALLS.clear();
            ReceiptStore s = Writer.store(new Context());
            check(problems, Context.deviceProtectedContexts == before + 1, "device protected context");
            check(problems, Os.CALLS.isEmpty() && !Files.exists(data.resolve("receipts")), "nothing created");
            check(problems, s.list(APP_UID, 5).status.equals("ABSENT"), "an absent store");
            check(problems, Writer.store(new Context()) == s, "one store per process");
        });
    }

    static void provider(Cases cases, Path directory) {
        Process.uid = APP_UID;
        cases.run("provider / a foreign caller is refused at every entry before an argument is read", problems -> {
            Process.uid = APP_UID;
            ReceiptProvider provider = new ReceiptProvider();
            List<Object[]> all = new ArrayList<>(entries());
            all.add(new Object[] {"whole read", (Entry) p -> p.query(Uri.parse(ProviderPolicy.ROWS), null, null,
                    (android.os.CancellationSignal) null)});
            all.add(new Object[] {"null arguments", (Entry) p -> p.query(null, null, (Bundle) null, null)});
            int contexts = Context.deviceProtectedContexts;
            Os.CALLS.clear();
            for (int uid : new int[] {0, 1000, APP_UID, 10123, -1, 2001}) {
                Binder.callingUid = uid;
                for (Object[] e : all) {
                    String got = outcome(provider, (Entry) e[1]);
                    check(problems, got.equals("SecurityException"), "uid " + uid + " " + e[0] + ": " + got);
                }
            }
            check(problems, Context.deviceProtectedContexts == contexts && Os.CALLS.isEmpty(), "no store touched");
            Binder.callingUid = 2000;
        });
        cases.run("provider / the shell user's writes, calls, opens and other operations are refused", problems -> {
            Process.uid = APP_UID;
            Binder.callingUid = 2000;
            ReceiptProvider provider = new ReceiptProvider();
            Os.CALLS.clear();
            for (Object[] e : entries()) {
                String got = outcome(provider, (Entry) e[1]);
                check(problems, got.equals("UnsupportedOperationException"), e[0] + ": " + got);
            }
            check(problems, Os.CALLS.isEmpty(), "no file operation " + Os.CALLS);
        });
        cases.run("provider / the shell user's one whole read is the store's listing, and nothing is written",
                problems -> {
            Process.uid = APP_UID;
            Binder.callingUid = 2000;
            ReceiptStore store = new ReceiptStore(new AndroidDisk(directory.resolve("receipts").toFile()),
                    new NoticeHostTests.Counter());
            ReceiptRow row = NoticeHostTests.row(NoticeHostTests.notice(), 2500);
            check(problems, store.record(row) == ReceiptStore.Outcome.WRITTEN, "a row written");
            Os.CALLS.clear();
            ReceiptProvider provider = new ReceiptProvider();
            Cursor cursor = provider.query(Uri.parse(ProviderPolicy.ROWS), null, new Bundle(), null);
            List<String> lines = new ArrayList<>();
            for (int i = 0; i < cursor.getCount(); i++) lines.add((String) cursor.get(i, 0));
            check(problems, Arrays.equals(cursor.getColumnNames(), new String[] {"line"}), "one column");
            check(problems, lines.equals(store.list(APP_UID, 5).lines), "the listing " + lines);
            check(problems, lines.size() == 3 && lines.get(1).startsWith("row " + row.key()), "one whole row");
            for (String call : Os.CALLS) {
                check(problems, call.startsWith("lstat ") || call.startsWith("open ") && call.contains(" RDONLY")
                        || call.startsWith("close "), "a read only call: " + call);
            }
            Cursor projected = provider.query(Uri.parse(ProviderPolicy.ROWS), new String[] {"line"}, null, null);
            check(problems, projected.getCount() == 3, "the one column asked by name");
            Bundle selection = new Bundle();
            selection.putString("android:query-arg-sql-selection", "x");
            check(problems, outcome(provider, p -> p.query(Uri.parse(ProviderPolicy.ROWS), null, selection, null))
                    .equals("IllegalArgumentException"), "a selection");
            check(problems, outcome(provider, p -> p.query(Uri.parse(ProviderPolicy.ROWS + "/1"), null, null, null))
                    .equals("IllegalArgumentException"), "another URI");
            check(problems, outcome(provider, p -> p.query(Uri.parse(ProviderPolicy.ROWS), new String[] {"x"}, null,
                    null)).equals("IllegalArgumentException"), "another column");
        });
        cases.run("provider / no entry clears the calling identity", problems ->
                check(problems, Binder.clears == 0, "clears " + Binder.clears));
    }

    // ------------------------------------------------------------------ the disk

    static void disk(Cases cases, Path directory) throws IOException {
        Files.createDirectories(directory);
        cases.run("disk / a new row's system calls: exclusive no follow create, fd sync, rename, directory syncs",
                problems -> {
            Path store = directory.resolve("receipts");
            Os.CALLS.clear();
            ReceiptStore s = new ReceiptStore(new AndroidDisk(store.toFile()), new NoticeHostTests.Counter());
            ReceiptRow row = NoticeHostTests.row(NoticeHostTests.notice(), 2500);
            check(problems, s.record(row) == ReceiptStore.Outcome.WRITTEN, "written");
            String dir = store.toString();
            String temporary = dir + "/." + row.key() + ".0000000000000001.tmp";
            List<String> expected = Arrays.asList("lstat " + dir, "mkdir " + dir + " 700",
                    "open " + directory + " RDONLY|CLOEXEC 0", "fsync " + directory, "close " + directory,
                    "lstat " + dir + "/" + row.key(), "open " + temporary + " WRONLY|CREAT|EXCL|NOFOLLOW|CLOEXEC 600",
                    "write " + temporary + " " + row.encode().length, "fsync " + temporary, "close " + temporary,
                    "rename " + temporary + " " + dir + "/" + row.key(), "open " + dir + " RDONLY|CLOEXEC 0",
                    "fsync " + dir, "close " + dir);
            check(problems, Os.CALLS.equals(expected), "calls " + Os.CALLS);
            check(problems, Arrays.equals(Files.readAllBytes(store.resolve(row.key())), row.encode()), "bytes");
            Os.CALLS.clear();
            check(problems, s.record(row) == ReceiptStore.Outcome.REPEAT, "repeat");
            for (String call : Os.CALLS) {
                check(problems, !call.startsWith("rename") && !call.contains("WRONLY") && !call.startsWith("mkdir"),
                        "a repeat writes nothing: " + call);
            }
        });
        cases.run("disk / a link or a directory under a key is never followed or read as a row", problems -> {
            Path store = directory.resolve("links");
            Files.createDirectories(store);
            ReceiptRow row = NoticeHostTests.row(NoticeHostTests.notice(), 2500);
            Path target = directory.resolve("elsewhere.row");
            Files.write(target, row.encode());
            Files.createSymbolicLink(store.resolve(row.key()), target);
            ReceiptRow q = NoticeHostTests.row(NoticeHostTests.qualification(), 2500);
            Files.createDirectory(store.resolve(q.key()));
            ReceiptStore s = new ReceiptStore(new AndroidDisk(store.toFile()), new NoticeHostTests.Counter());
            List<String> lines = s.list(APP_UID, 5).lines;
            check(problems, lines.contains("corrupt " + row.key() + " - - - not-regular")
                    && lines.contains("corrupt " + q.key() + " - - - not-regular") && lines.size() == 4,
                    "listing " + lines);
            check(problems, s.record(row) == ReceiptStore.Outcome.CORRUPT, "a link under the key is no row");
        });
        cases.run("disk / a restarted process syncs an existing directory's parent, and the directory for a repeat",
                problems -> {
            Path store = directory.resolve("restart");
            String dir = store.toString();
            ReceiptRow row = NoticeHostTests.row(NoticeHostTests.notice(), 2500);
            String key = dir + "/" + row.key();
            ReceiptStore first = new ReceiptStore(new AndroidDisk(store.toFile()), new NoticeHostTests.Counter());
            check(problems, first.record(row) == ReceiptStore.Outcome.WRITTEN, "written");
            // A new process on the same directory: the parent sync comes although the directory
            // exists, and the directory sync before the repeat is accepted. Nothing is written.
            Os.CALLS.clear();
            ReceiptStore second = new ReceiptStore(new AndroidDisk(store.toFile()), NoticeHostTests.later());
            check(problems, second.record(row) == ReceiptStore.Outcome.REPEAT, "a repeat");
            List<String> parent = Arrays.asList("lstat " + dir, "open " + directory + " RDONLY|CLOEXEC 0",
                    "fsync " + directory, "close " + directory);
            List<String> read = Arrays.asList("lstat " + key, "open " + key + " RDONLY|NONBLOCK|NOFOLLOW|CLOEXEC 0",
                    "close " + key);
            List<String> expected = new ArrayList<>(parent);
            expected.addAll(read);
            expected.addAll(Arrays.asList("open " + dir + " RDONLY|CLOEXEC 0", "fsync " + dir, "close " + dir));
            check(problems, Os.CALLS.equals(expected), "calls " + Os.CALLS);
            check(problems, Arrays.equals(Files.readAllBytes(store.resolve(row.key())), row.encode()), "bytes kept");
            // That process's next repeat only reads.
            Os.CALLS.clear();
            check(problems, second.record(row) == ReceiptStore.Outcome.REPEAT && Os.CALLS.equals(read),
                    "calls " + Os.CALLS);
            // A third process writes a new row there: the parent sync first, then the write order.
            Os.CALLS.clear();
            ReceiptRow other = NoticeHostTests.row(NoticeHostTests.qualification(), 2600);
            ReceiptStore third = new ReceiptStore(new AndroidDisk(store.toFile()), NoticeHostTests.later());
            check(problems, third.record(other) == ReceiptStore.Outcome.WRITTEN
                    && Os.CALLS.subList(0, 4).equals(parent) && Os.CALLS.size() == 13
                    && Os.CALLS.get(11).equals("fsync " + dir), "calls " + Os.CALLS);
        });
    }
}
