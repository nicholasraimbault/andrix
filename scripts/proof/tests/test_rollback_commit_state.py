# SPDX-License-Identifier: Apache-2.0
"""Changed-function Java trials with explicit Android mocks; not guest/I/O proof."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_rollback_retention import method, sources


class CommitStateTests(unittest.TestCase):
    def test_lifecycle_wiring_and_fail_closed_order(self):
        src = sources(); model = src['Rollback.java']; rms = src['RollbackManagerServiceImpl.java']
        finish = method(model, 'boolean completeCommit(')
        self.assertIn('if (!mRestoreUserDataInProgress)', finish)
        self.assertLess(finish.index('persistCommitState('), finish.rindex('deletePackageCodePaths('))
        self.assertIn('if (!isStaged() && !completeCommit())', model)
        self.assertIn('restoreAvailableAfterCommitFailure("Commit failed")', model)
        reconcile = method(rms, 'private void reconcileCommittedSession(')
        self.assertIn('rollback.info.getCommittedSessionId()', reconcile)
        self.assertNotIn('getOriginalSessionId()', reconcile)
        self.assertIn('(!session.isStaged() || !session.isStagedSessionFailed())', reconcile)
        self.assertIn('session.isStaged() && session.isStagedSessionApplied()', reconcile)
        self.assertIn('getInstalledPackageVersion(', reconcile)
        self.assertGreaterEqual(rms.count('|| rollback.isRestoreUserDataInProgress())'), 2)
        self.assertIn('Rollback restore is still in progress', rms)
        matcher = method(rms, 'private Rollback getRollbackForCommitSession(')
        self.assertIn('sessionId < 0', matcher)
        self.assertIn('rollback.isCommitted() && rollback.isRestoreUserDataInProgress()', matcher)
        if os.environ.get('ANDRIX_RETENTION_PREVIEW'):
            original = method(rms, 'private Rollback getRollbackForSession(')
            self.assertNotIn('getCommittedSessionId', original)
        self.assertIn('Rollback rollback = getRollbackForCommitSession(sessionId);', rms)
        self.assertIn('rollback = getRollbackForSession(sessionId);', rms)
        self.assertIn('rollback.discard();', rms)
        self.assertIn('if (mDiscarded || info.getCommittedSessionId() != parentSessionId)', model)

    def test_changed_java_state_and_reconciliation(self):
        javac = os.environ.get('JAVAC') or shutil.which('javac')
        java = os.environ.get('JAVA') or shutil.which('java')
        if not javac or not java:
            self.skipTest('JDK required')
        src = sources(); model = src['Rollback.java']; rms = src['RollbackManagerServiceImpl.java']
        bodies = '\n'.join(method(model, name) for name in (
            'private boolean persistCommitState(', 'boolean completeCommit(',
            'boolean restoreAvailableAfterCommitFailure(', 'void discard('))
        bodies = bodies.replace('@RollbackState ', '')
        source = HARNESS.replace('/*STATE*/', bodies).replace('/*RECONCILE*/',
            method(rms, 'private void reconcileCommittedSession('))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'CommitTrial.java').write_text(source)
            built = subprocess.run([javac, '-d', tmp, str(root/'CommitTrial.java')], capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout+built.stderr)
            run = subprocess.run([java, '-cp', tmp, 'CommitTrial'], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
            self.assertIn('PASS commit-state source trial', run.stdout)


HARNESS = r'''
import java.io.*;
import java.util.*;
public class CommitTrial {
 static void check(boolean v){if(!v)throw new AssertionError();}
 static final String TAG="trial";
 static final int ROLLBACK_STATE_AVAILABLE=1,ROLLBACK_STATE_COMMITTED=3;
 static class Slog {static void e(String t,String m){}}
 static class VersionedPackage {
  String name;long version;VersionedPackage(String n,long v){name=n;version=v;}
  long getLongVersionCode(){return version;}
 }
 static class PackageRollbackInfo {
  VersionedPackage from=new VersionedPackage("consumer",3),to=new VersionedPackage("consumer",2);
  boolean embedded;
  String getPackageName(){return "consumer";}boolean isApkInApex(){return embedded;}
  VersionedPackage getVersionRolledBackFrom(){return from;}VersionedPackage getVersionRolledBackTo(){return to;}
 }
 static class Info {
  int sessionId=-1;List<VersionedPackage> causes=new ArrayList<>();List<PackageRollbackInfo> packages=List.of(new PackageRollbackInfo());
  int getCommittedSessionId(){return sessionId;}void setCommittedSessionId(int id){sessionId=id;}
  List<VersionedPackage> getCausePackages(){return causes;}List<PackageRollbackInfo> getPackages(){return packages;}int getRollbackId(){return 7;}
 }
 static class RollbackStore {
  static boolean writeOk=true,backups=true;static int deletes,writes;
  static boolean saveRollback(Rollback r){writes++;return writeOk;}
  static File[] getPackageCodePaths(Rollback r,String p){return backups?new File[]{new File("mock.apk")}:null;}
  static void deletePackageCodePaths(Rollback r){deletes++;backups=false;}
 }
 static class Rollback {
  int mState=1;boolean mRestoreUserDataInProgress,mDiscarded;Runnable mStateChangedCallback;
  String mStateDescription="";Info info=new Info();int notifications;
  void assertInWorkerThread(){}void notifyStateChanged(){notifications++;}
  boolean isCommitted(){return mState==3;}boolean isDeleted(){return mState==4;}
  boolean isRestoreUserDataInProgress(){return mRestoreUserDataInProgress;}
  /*STATE*/
 }
 static class PackageInstaller {
  static class SessionInfo {
   int id;boolean staged=true,applied,committed=true,failed;
   SessionInfo(int i){id=i;}boolean isStaged(){return staged;}
   boolean isStagedSessionApplied(){check(staged);return applied;}
   boolean isCommitted(){return committed;}boolean isStagedSessionFailed(){check(staged);return failed;}
   int getSessionId(){return id;}
  }
  Map<Integer,SessionInfo> sessions=new HashMap<>();List<Integer> reads=new ArrayList<>(),abandons=new ArrayList<>();
  SessionInfo getSessionInfo(int id){reads.add(id);return sessions.get(id);}
  void abandonSession(int id){abandons.add(id);sessions.remove(id);}
 }
 static class PackageManager {PackageInstaller installer=new PackageInstaller();PackageInstaller getPackageInstaller(){return installer;}}
 static class Context {PackageManager pm=new PackageManager();PackageManager getPackageManager(){return pm;}}
 static class Manager {
  Context mContext=new Context();long installed=3;
  void assertInWorkerThread(){}long getInstalledPackageVersion(String p){return installed;}
  /*RECONCILE*/
 }
 static Rollback pending(){RollbackStore.writeOk=true;RollbackStore.backups=true;RollbackStore.deletes=0;RollbackStore.writes=0;Rollback r=new Rollback();check(r.persistCommitState(3,true,222,"",List.of(new VersionedPackage("cause",3))));return r;}
 public static void main(String[] args){
  Rollback r=new Rollback();RollbackStore.writeOk=false;
  check(!r.persistCommitState(3,true,222,"new",List.of(new VersionedPackage("cause",3))));
  check(r.mState==1&&!r.mRestoreUserDataInProgress&&r.info.sessionId==-1&&r.info.causes.isEmpty()&&r.notifications==0);
  r=pending();int notify=r.notifications;RollbackStore.writeOk=false;
  check(!r.completeCommit());check(r.isRestoreUserDataInProgress()&&r.info.sessionId==222&&r.notifications==notify&&RollbackStore.deletes==0);
  RollbackStore.writeOk=true;check(r.completeCommit());check(!r.isRestoreUserDataInProgress()&&RollbackStore.deletes==1&&r.info.causes.size()==1);
  r=pending();RollbackStore.backups=false;check(!r.restoreAvailableAfterCommitFailure("missing"));check(r.isCommitted()&&r.isRestoreUserDataInProgress());
  RollbackStore.backups=true;RollbackStore.writeOk=false;check(!r.restoreAvailableAfterCommitFailure("write"));check(r.isCommitted()&&r.info.sessionId==222);
  RollbackStore.writeOk=true;check(r.restoreAvailableAfterCommitFailure("abandoned"));check(r.mState==1&&!r.isRestoreUserDataInProgress()&&r.info.sessionId==-1&&r.info.causes.isEmpty());
  Manager manager=new Manager();PackageInstaller installer=manager.mContext.pm.installer;
  PackageInstaller.SessionInfo original=new PackageInstaller.SessionInfo(111);original.applied=true;installer.sessions.put(111,original);
  PackageInstaller.SessionInfo commit=new PackageInstaller.SessionInfo(222);installer.sessions.put(222,commit);
  r=pending();manager.reconcileCommittedSession(r);check(r.isRestoreUserDataInProgress()&&RollbackStore.deletes==0&&installer.reads.equals(List.of(222)));
  commit.staged=false;manager.reconcileCommittedSession(r);check(r.isRestoreUserDataInProgress()&&RollbackStore.deletes==0); // staged getters must not be called
  commit.staged=true;commit.applied=true;manager.reconcileCommittedSession(r);check(!r.isRestoreUserDataInProgress()&&RollbackStore.deletes==1);
  r=pending();commit.applied=false;commit.failed=true;manager.reconcileCommittedSession(r);check(r.mState==1&&!r.isRestoreUserDataInProgress()&&RollbackStore.backups);
  r=pending();installer.sessions.remove(222);manager.installed=2;manager.reconcileCommittedSession(r);check(!r.isRestoreUserDataInProgress()&&RollbackStore.deletes==1);
  r=pending();manager.installed=3;manager.reconcileCommittedSession(r);check(r.mState==1&&RollbackStore.backups);
  r=pending();commit.failed=false;commit.committed=false;installer.sessions.put(222,commit);manager.reconcileCommittedSession(r);check(installer.abandons.equals(List.of(222))&&r.mState==1);
  r=pending();manager.installed=99;manager.reconcileCommittedSession(r);check(r.isRestoreUserDataInProgress()&&RollbackStore.backups); // unknown state is not success
  r=pending();manager.installed=2;RollbackStore.writeOk=false;manager.reconcileCommittedSession(r);check(r.isRestoreUserDataInProgress()&&RollbackStore.deletes==0);
  r=pending();int writes=RollbackStore.writes;r.discard();check(!r.completeCommit());check(!r.persistCommitState(1,false,-1,"stale",List.of()));check(RollbackStore.writes==writes&&RollbackStore.deletes==0);
  r=pending();check(r.persistCommitState(3,true,222,"alias",r.info.getCausePackages()));check(r.info.causes.size()==1);
  System.out.println("PASS commit-state source trial (mock Android surroundings)");
 }
}
'''
