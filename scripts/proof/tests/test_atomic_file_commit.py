# SPDX-License-Identifier: Apache-2.0
"""Checked AtomicFile method trial with real host files and explicit Android mocks.

Not Android storage, directory durability, power-cut or complete framework proof.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_rollback_retention import method, sources, ROOT


class AtomicCommitTests(unittest.TestCase):
    def test_checked_api_separate_from_legacy_contract(self):
        source = sources()['AtomicFile.java']
        checked = method(source, 'public void finishWriteOrThrow(')
        self.assertIn('throws IOException', checked)
        self.assertNotIn('Log.e(', checked)
        self.assertNotIn('catch (', checked)
        self.assertLess(checked.index('FileUtils.sync('), checked.index('str.close()'))
        self.assertLess(checked.index('str.close()'), checked.index('mNewName.renameTo('))
        self.assertLess(checked.index('mNewName.renameTo('), checked.index('onFinishWrite()'))
        self.assertIn('mLegacyBackupName.exists()', checked)
        if os.environ.get('ANDRIX_RETENTION_PREVIEW'):
            legacy = method(source, 'public void finishWrite(FileOutputStream')
            self.assertIn('Log.e(', legacy)
            self.assertNotIn('finishWriteOrThrow', legacy)
        else:
            patch = (ROOT/'patches/android-17.0.0_r1/network-endpoints.patch').read_text()
            section = patch.split('diff --git a/frameworks/base/core/java/android/util/AtomicFile.java ', 1)[1]
            section = section.split('\ndiff --git ', 1)[0]
            self.assertFalse(any(line.startswith('-') and not line.startswith('---')
                                 for line in section.splitlines()), 'Legacy AtomicFile code changed')

    def test_real_host_file_replacement_and_injected_failures(self):
        javac = os.environ.get('JAVAC') or shutil.which('javac')
        java = os.environ.get('JAVA') or shutil.which('java')
        if not javac or not java:
            self.skipTest('JDK required')
        body = method(sources()['AtomicFile.java'], 'public void finishWriteOrThrow(')
        source = HARNESS.replace('/*CHECKED*/', body)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'AtomicCommitTrial.java').write_text(source)
            built = subprocess.run([javac, '-d', tmp, str(root/'AtomicCommitTrial.java')],
                                   capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout+built.stderr)
            run = subprocess.run([java, '-cp', tmp, 'AtomicCommitTrial', tmp],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
            self.assertIn('PASS checked atomic-file source trial', run.stdout)


HARNESS = r'''
import java.io.*;
import java.nio.file.*;
public class AtomicCommitTrial {
 static void check(boolean yes){if(!yes)throw new AssertionError();}
 static class FileUtils {
  static boolean syncAllowed=true;
  static boolean sync(FileOutputStream out){if(!syncAllowed)return false;try{out.getFD().sync();return true;}catch(IOException e){return false;}}
 }
 static class Logger {int count;void onFinishWrite(){count++;}}
 static class Atomic {
  File mBaseName,mNewName,mLegacyBackupName;Logger mCommitEventLogger=new Logger();
  Atomic(Path root,String name)throws Exception {mBaseName=root.resolve(name).toFile();mNewName=root.resolve(name+".new").toFile();mLegacyBackupName=root.resolve(name+".bak").toFile();}
  FileOutputStream start()throws IOException {return new FileOutputStream(mNewName);}
  /*CHECKED*/
 }
 interface Operation {void run()throws Exception;}
 static void fails(Operation action)throws Exception {try{action.run();throw new AssertionError("expected IOException");}catch(IOException expected){}}
 static class CloseFails extends FileOutputStream {
  CloseFails(File file)throws IOException{super(file);}
  public void close()throws IOException{throw new IOException("injected close failure");}
  void reallyClose()throws IOException{super.close();}
 }
 static byte[] bytes(String s){return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);}
 static void old(Atomic a)throws IOException {Files.write(a.mBaseName.toPath(),bytes("old"));}
 static void oldPreserved(Atomic a)throws IOException {check(Files.readString(a.mBaseName.toPath()).equals("old")&&a.mCommitEventLogger.count==0);}
 public static void main(String[] args)throws Exception {
  Path root=Path.of(args[0]);
  Atomic good=new Atomic(root,"good");old(good);FileOutputStream out=good.start();out.write(bytes("new"));good.finishWriteOrThrow(out);
  check(Files.readString(good.mBaseName.toPath()).equals("new")&&!good.mNewName.exists()&&good.mCommitEventLogger.count==1);
  Atomic missing=new Atomic(root,"null");old(missing);fails(()->missing.finishWriteOrThrow(null));oldPreserved(missing);
  Atomic sync=new Atomic(root,"sync");old(sync);out=sync.start();out.write(bytes("new"));FileOutputStream failedSync=out;FileUtils.syncAllowed=false;
  fails(()->sync.finishWriteOrThrow(failedSync));oldPreserved(sync);FileUtils.syncAllowed=true;out.close();Files.delete(sync.mNewName.toPath());
  Atomic close=new Atomic(root,"close");old(close);CloseFails badClose=new CloseFails(close.mNewName);badClose.write(bytes("new"));
  fails(()->close.finishWriteOrThrow(badClose));oldPreserved(close);badClose.reallyClose();Files.delete(close.mNewName.toPath());
  Atomic nonempty=new Atomic(root,"nonempty");Files.createDirectory(nonempty.mBaseName.toPath());Files.write(nonempty.mBaseName.toPath().resolve("keep"),bytes("old"));
  out=nonempty.start();out.write(bytes("new"));FileOutputStream dirStream=out;fails(()->nonempty.finishWriteOrThrow(dirStream));check(Files.readString(nonempty.mBaseName.toPath().resolve("keep")).equals("old")&&nonempty.mCommitEventLogger.count==0);
  Atomic empty=new Atomic(root,"empty");Files.createDirectory(empty.mBaseName.toPath());out=empty.start();out.write(bytes("new"));empty.finishWriteOrThrow(out);check(Files.readString(empty.mBaseName.toPath()).equals("new"));
  Atomic rename=new Atomic(root,"rename");old(rename);out=rename.start();out.write(bytes("new"));Files.delete(rename.mNewName.toPath());FileOutputStream renameStream=out;fails(()->rename.finishWriteOrThrow(renameStream));oldPreserved(rename);
  Atomic legacy=new Atomic(root,"legacy");old(legacy);Files.write(legacy.mLegacyBackupName.toPath(),bytes("backup"));out=legacy.start();out.write(bytes("new"));FileOutputStream legacyStream=out;fails(()->legacy.finishWriteOrThrow(legacyStream));oldPreserved(legacy);out.close();check(Files.readString(legacy.mLegacyBackupName.toPath()).equals("backup"));
  System.out.println("PASS checked atomic-file source trial (host files, injected Android surroundings)");
 }
}
'''
