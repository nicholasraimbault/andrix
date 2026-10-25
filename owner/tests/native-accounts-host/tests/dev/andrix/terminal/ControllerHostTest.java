// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package dev.andrix.terminal;

import android.os.Handler;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.widget.TextView;
import dev.andrix.lifecycle.INativeAccountQuery;
import dev.andrix.lifecycle.NativeAccountRow;
import dev.andrix.lifecycle.NativeAccountSnapshot;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Controlled events exercise actual production controller worker, queue, callback and renderer. */
public final class ControllerHostTest {
    private static final List<CountDownLatch> releases=new ArrayList<>();
    private static int cases;
    private ControllerHostTest() { }
    private static void check(boolean yes,String why) { if (!yes) throw new AssertionError(why); }
    private static void run(String name, Test action) throws Exception {
        action.run();cases++;System.out.println("PASS controller "+name);
    }
    @FunctionalInterface private interface Test { void run() throws Exception; }
    private static final class Service extends INativeAccountQuery.Stub {
        final CountDownLatch entered=new CountDownLatch(1);
        final CountDownLatch release;
        volatile Thread worker;
        volatile boolean live=true, failure;
        volatile int calls;
        final NativeAccountSnapshot response;
        Service(NativeAccountSnapshot result, boolean blocked) {
            response=result; release=new CountDownLatch(blocked?1:0);
            releases.add(release);
        }
        @Override public NativeAccountSnapshot inspectCurrentUser() {
            worker=Thread.currentThread();calls++;entered.countDown();
            try { release.await(); }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();throw new IllegalStateException("test interrupted");
            }
            if (failure) throw new IllegalStateException("host service failure");
            return response;
        }
        @Override public boolean isBinderAlive() { return live; }
        void awaitEntered() throws InterruptedException {
            check(entered.await(4,TimeUnit.SECONDS),"read did not start");
        }
    }
    private static NativeAccountRow row(int source) {
        NativeAccountRow r=new NativeAccountRow();
        r.principalId=81;r.appId=10123;r.packageName="dev.andrix.native";
        r.lineage="0123456789abcdef0123456789abcdef";
        r.source=source;r.phase=NativeAccountRow.RETIRING_PIN;
        r.lifecycle=source==NativeAccountRow.BODY?NativeAccountRow.RETIRED:
                NativeAccountRow.LIFECYCLE_NOT_OBSERVED;
        r.suspension=source==NativeAccountRow.BODY?NativeAccountRow.SUSPENSION_PRESENT:
                NativeAccountRow.SUSPENSION_NOT_OBSERVED;
        return r;
    }
    private static NativeAccountSnapshot snapshot(NativeAccountRow... rows) {
        NativeAccountSnapshot s=new NativeAccountSnapshot();s.userId=0;s.userSerial=7;
        s.status=NativeAccountSnapshot.AVAILABLE;s.store=NativeAccountSnapshot.STORE_READY;
        s.complete=true;s.rows=rows;return s;
    }
    private static NativeAccountController open(TextView view) {
        NativeAccountController c=new NativeAccountController(view);c.open();return c;
    }
    private static void reset() {
        check(Handler.pendingPostsForHostTest()==0,"unconsumed main callbacks");
        check(Handler.pendingTimersForHostTest()==0,"timeout leak");
        ServiceManager.resetForHostTest();UserHandle.setMyUserIdForHostTest(0);
    }
    private static ThreadPoolExecutor lane() throws Exception {
        Field f=NativeAccountController.class.getDeclaredField("QUERY_LANE");
        f.setAccessible(true);return (ThreadPoolExecutor)f.get(null);
    }
    private static void rendering() throws Exception {
        run("BODY recorded lifecycle suspension and retirement causal caption",()->{
            String text=NativeAccountController.render(snapshot(row(NativeAccountRow.BODY)),0);
            check(text.contains("body, retiring pin, recorded retired; retirement alone deletes no data and releases no UID")
                    && text.contains("recorded suspension") && text.contains("lineage 0123456789abcdef")
                    && text.contains("principal 81") && text.contains("Inspection is not login"),text);
        });
        run("RESERVATION observations not invented",()->{
            String text=NativeAccountController.render(snapshot(row(NativeAccountRow.RESERVATION)),0);
            check(text.contains("reservation, retiring pin, lifecycle not observed, suspension not observed")
                    && !text.contains("recorded retired"),text);
        });
        run("reservation lifecycle contradiction refused",()->{
            NativeAccountRow r=row(NativeAccountRow.RESERVATION);r.lifecycle=NativeAccountRow.ELIGIBLE;
            check(NativeAccountController.render(snapshot(r),0).contains("Unknown account response"),"contradictory reservation accepted");
        });
        run("reservation suspension contradiction refused",()->{
            NativeAccountRow r=row(NativeAccountRow.RESERVATION);r.suspension=NativeAccountRow.SUSPENSION_NONE;
            check(NativeAccountController.render(snapshot(r),0).contains("Unknown account response"),"synthetic reservation suspension accepted");
        });
        run("BODY unobserved lifecycle refused",()->{
            NativeAccountRow r=row(NativeAccountRow.BODY);r.lifecycle=NativeAccountRow.LIFECYCLE_NOT_OBSERVED;
            check(NativeAccountController.render(snapshot(r),0).contains("Unknown account response"),"unobserved BODY accepted");
        });
        run("BODY unobserved suspension refused",()->{
            NativeAccountRow r=row(NativeAccountRow.BODY);r.suspension=NativeAccountRow.SUSPENSION_NOT_OBSERVED;
            check(NativeAccountController.render(snapshot(r),0).contains("Unknown account response"),"unobserved BODY suspension accepted");
        });
        run("complete empty distinct from unavailable",()->{
            String empty=NativeAccountController.render(snapshot(),0);
            check(empty.contains("No recorded native accounts in a complete cached store"),empty);
            NativeAccountSnapshot s=snapshot();s.complete=false;
            String withheld=NativeAccountController.render(s,0);
            check(withheld.contains("identity state unavailable, not an empty account list")
                    && !withheld.contains("No recorded"),withheld);
            check(NativeAccountController.render(null,0).contains("state unavailable"),"null result treated as empty");
        });
        run("missing, damaged, conflict, newer stores withhold empty claim",()->{
            int[] stores={NativeAccountSnapshot.STORE_MISSING,NativeAccountSnapshot.STORE_DAMAGED,
                    NativeAccountSnapshot.STORE_CONFLICT,NativeAccountSnapshot.STORE_NEWER};
            String[] labels={"provisioning unavailable","damaged","conflicting","newer than this reader"};
            for(int i=0;i<stores.length;i++) {
                NativeAccountSnapshot s=snapshot();s.store=stores[i];
                String text=NativeAccountController.render(s,0);
                check(text.contains(labels[i]) && text.contains("not an empty account list"),text);
            }
        });
        run("unsupported user shows no primary accounts",()->{
            NativeAccountSnapshot s=snapshot(row(NativeAccountRow.BODY));s.userId=2;
            s.status=NativeAccountSnapshot.UNSUPPORTED_USER;
            check(NativeAccountController.render(s,2).contains("No primary user accounts shown"),"secondary disclosure");
            check(NativeAccountController.render(s,0).contains("state unavailable"),"wrong user shown");
        });
        run("row cap and invalid lineage or app ID refuse response",()->{
            NativeAccountRow[] many=new NativeAccountRow[65];
            for(int i=0;i<many.length;i++) many[i]=row(NativeAccountRow.BODY);
            check(NativeAccountController.render(snapshot(many),0).contains("not an empty account list"),"row cap ignored");
            NativeAccountRow bad=row(NativeAccountRow.BODY);bad.lineage="ABCDEFGH012345670123456701234567";
            check(NativeAccountController.render(snapshot(bad),0).contains("Invalid account response"),"invalid lineage shown");
            bad=row(NativeAccountRow.BODY);bad.appId=9999;
            check(NativeAccountController.render(snapshot(bad),0).contains("Invalid account response"),"invalid app ID shown");
        });
    }
    private static void delivery() throws Exception {
        reset();
        run("open never queries until explicit Refresh",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            check(view.textForHostTest().contains("Press Refresh") && ServiceManager.checks==0,
                    "implicit query");c.close();reset();
        });
        run("old Binder alive but replaced before main acceptance",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            Service old=new Service(snapshot(row(NativeAccountRow.BODY)),false);
            Service replacement=new Service(snapshot(),false);
            ServiceManager.registerForHostTest(old);c.refresh();
            Runnable callback=Handler.awaitPostedForHostTest();check(old.live,"old Binder already dead");
            ServiceManager.registerForHostTest(replacement);callback.run();
            check(view.textForHostTest().contains("state unavailable")
                    && !view.textForHostTest().contains("recorded account(s)"),"replaced old response displayed");
            check(old.calls==1 && replacement.calls==0 && ServiceManager.checks>=3,"wrong Binder acceptance");
            c.close();reset();
        });
        run("same service identity positive",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            Service service=new Service(snapshot(row(NativeAccountRow.BODY)),false);
            ServiceManager.registerForHostTest(service);c.refresh();
            Handler.awaitPostedForHostTest().run();
            check(view.textForHostTest().contains("1 recorded account(s)") && service.calls==1,
                    "same identity result withheld");
            check(Handler.pendingTimersForHostTest()==0,"accepted callback left timer");
            c.close();reset();
        });
        run("older success cannot replace newer failure",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            Service old=new Service(snapshot(row(NativeAccountRow.BODY)),false);
            Service broken=new Service(snapshot(),false);broken.failure=true;
            ServiceManager.registerForHostTest(old);c.refresh();Runnable stale=Handler.awaitPostedForHostTest();
            ServiceManager.registerForHostTest(broken);c.refresh();Runnable latest=Handler.awaitPostedForHostTest();
            latest.run();String unavailable=view.textForHostTest();
            check(unavailable.contains("state unavailable"),"new failure not shown");
            stale.run();check(view.textForHostTest().equals(unavailable),"late old success replaced failure");
            c.close();reset();
        });
        run("older success cannot replace newer refresh success",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            Service old=new Service(snapshot(row(NativeAccountRow.BODY)),false);
            Service latestService=new Service(snapshot(),false);
            ServiceManager.registerForHostTest(old);c.refresh();Runnable stale=Handler.awaitPostedForHostTest();
            ServiceManager.registerForHostTest(latestService);c.refresh();Runnable latest=Handler.awaitPostedForHostTest();
            latest.run();String empty=view.textForHostTest();
            check(empty.contains("No recorded native accounts"),"new success not shown");
            stale.run();check(view.textForHostTest().equals(empty),"stale success replaced latest");
            c.close();reset();
        });
        run("hide discards callback",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            ServiceManager.registerForHostTest(new Service(snapshot(row(NativeAccountRow.BODY)),false));
            c.refresh();Runnable old=Handler.awaitPostedForHostTest();c.hide();String text=view.textForHostTest();
            old.run();check(view.textForHostTest().equals(text),"hidden view updated");
            c.close();reset();
        });
        run("close discards callback",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            ServiceManager.registerForHostTest(new Service(snapshot(row(NativeAccountRow.BODY)),false));
            c.refresh();Runnable old=Handler.awaitPostedForHostTest();c.close();String text=view.textForHostTest();
            old.run();check(view.textForHostTest().equals(text),"closed view updated");reset();
        });
        run("user change discards callback",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            ServiceManager.registerForHostTest(new Service(snapshot(row(NativeAccountRow.BODY)),false));
            c.refresh();Runnable old=Handler.awaitPostedForHostTest();UserHandle.setMyUserIdForHostTest(2);
            String text=view.textForHostTest();old.run();
            check(view.textForHostTest().equals(text),"old user displayed");
            UserHandle.setMyUserIdForHostTest(0);c.close();reset();
        });
        run("explicit timer expires display but not accepted late result",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            ServiceManager.registerForHostTest(new Service(snapshot(row(NativeAccountRow.BODY)),false));
            c.refresh();Runnable late=Handler.awaitPostedForHostTest();
            Handler.fireOneTimerForHostTest();String expired=view.textForHostTest();
            check(expired.contains("query timed out") && expired.contains("State unavailable"),expired);
            late.run();check(view.textForHostTest().equals(expired),"late success overwrote timeout");
            c.close();reset();
        });
        run("service absent is unavailable and never empty",()->{
            TextView view=new TextView();NativeAccountController c=open(view);
            ServiceManager.registerForHostTest(null);c.refresh();Handler.awaitPostedForHostTest().run();
            check(view.textForHostTest().contains("state unavailable")
                    && !view.textForHostTest().contains("No recorded"),"null Binder became empty");
            c.close();reset();
        });
    }
    private static void blockedLane() throws Exception {
        reset();
        run("blocked Binder bounded across recreation and explicit display timeout",()->{
            ThreadPoolExecutor executor=lane();
            TextView original=new TextView();NativeAccountController first=open(original);
            Service blocked=new Service(snapshot(row(NativeAccountRow.BODY)),true);
            ServiceManager.registerForHostTest(blocked);first.refresh();blocked.awaitEntered();
            check(blocked.worker.getName().equals("AndrixNativeAccountsRead"),"not designated worker");
            check(executor.getActiveCount()==1 && executor.getPoolSize()==1,"worker missing");
            first.close();
            Class<?> query=Class.forName("dev.andrix.terminal.NativeAccountController$Query");
            Field owner=query.getDeclaredField("owner");
            check(owner.getType()==WeakReference.class,"queued query holds strong UI owner");
            for(Field field:query.getDeclaredFields()) {
                check(field.getType()!=NativeAccountController.class && field.getType()!=TextView.class,
                        "query holds strong UI/controller field");
            }
            for(int i=0;i<8;i++) {
                NativeAccountController recreated=open(new TextView());recreated.refresh();
                check(executor.getQueue().size()==1 && executor.getActiveCount()==1
                        && executor.getLargestPoolSize()==1,"unbounded pending or worker");
                recreated.close();check(executor.getQueue().isEmpty(),"closed view left pending job");
            }
            TextView timedView=new TextView();NativeAccountController timed=open(timedView);
            timed.refresh();timed.refresh();timed.refresh();
            check(executor.getQueue().size()==1 && executor.getPoolSize()==1
                    && executor.getLargestPoolSize()==1,"refreshes spawned replacement worker");
            Handler.fireOneTimerForHostTest();
            check(timedView.textForHostTest().contains("query timed out")
                    && executor.getActiveCount()==1 && executor.getQueue().isEmpty(),
                    "display timeout falsely retired blocked Binder or left queue");
            NativeAccountController hidden=open(new TextView());hidden.refresh();
            check(executor.getQueue().size()==1,"new pending request not bounded");
            hidden.hide();check(executor.getQueue().isEmpty(),"hidden pending request not removed");
            hidden.close();timed.close();
            check(blocked.worker.isAlive() && executor.getPoolSize()==1,"old blocked worker replaced");
            blocked.release.countDown();
            Handler.awaitPostedForHostTest().run();
            check(!original.textForHostTest().contains("recorded account(s)"),
                    "blocked old view published after close");
            check(executor.getQueue().isEmpty(),"pending job left after release");
            reset();
        });
    }
    public static void main(String[] args) throws Exception {
        try {
            rendering();delivery();blockedLane();
            System.out.println("CONTROLLER HOST PASS "+cases+" CASES; no Android UI or Binder driver");
        } finally {
            for(CountDownLatch release:releases) release.countDown();
            ThreadPoolExecutor executor=lane();
            // Test only, after every owned blocking RPC has been released. Production has no shutdown.
            executor.shutdown();
            check(executor.awaitTermination(6,TimeUnit.SECONDS),"owned static worker did not retire");
            check(executor.getPoolSize()==0 && executor.getActiveCount()==0
                    && executor.getQueue().isEmpty(),"owned jobs or worker survive");
            Handler.resetForHostTest();
            System.out.println("OWNED_WORKER_RETIRED pool=0 active=0 pending=0");
        }
    }
}
