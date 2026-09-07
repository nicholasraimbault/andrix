# SPDX-License-Identifier: Apache-2.0
"""Pinned changed-function trials, not a framework build or Android runtime proof.

The Java bodies come from the declared patch (or an explicit development preview).
Only Android value/container/service surroundings are mocked. Actual framework
compilation, persistence and PM/Watchdog execution are separate gates.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
NAMES = ('Rollback.java', 'RollbackStore.java', 'RollbackManagerServiceImpl.java',
         'RollbackManagerInternal.java', 'DeletePackageHelper.java')


def sources():
    preview = os.environ.get('ANDRIX_RETENTION_PREVIEW')
    if preview:
        return {name: (Path(preview) / name).read_text() for name in NAMES}
    series = json.loads((ROOT/'patches/android-17.0.0_r1/series.json').read_text())
    patch = (ROOT/'patches/android-17.0.0_r1'/series['patch']).read_text()
    result = {}; current = None
    for line in patch.splitlines(keepends=True):
        if line.startswith('diff --git '):
            current = Path(line.split()[2].removeprefix('a/')).name
            if current in NAMES:
                result[current] = ''
        elif current in NAMES and not line.startswith(('+++', '---', '@@')):
            if line.startswith(('+', ' ')):
                result[current] += line[1:]
    if set(result) != set(NAMES):
        raise AssertionError('Declared patch lacks exact retention files')
    return result


def method(text, signature):
    """Extract a complete Java body, skipping comments and quoted brace literals."""
    if text.count(signature) != 1:
        raise AssertionError('Missing/ambiguous method: ' + signature)
    start = text.index(signature); brace = text.index('{', start); depth = 0
    for token in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]',
                             text[brace:], re.S):
        value = token.group()
        if value == '{': depth += 1
        elif value == '}':
            depth -= 1
            if depth == 0:
                return re.sub(r'@(NonNull|Nullable)\s*', '',
                              text[start:brace+token.end()])
    raise AssertionError('Truncated Java body: ' + signature)


class RetentionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = sources()

    def test_wait_free_query_and_lifecycle_wiring(self):
        rms = self.src['RollbackManagerServiceImpl.java']
        query = method(rms, 'public boolean isStaticSharedLibraryRequired(')
        for forbidden in ('awaitResult', 'getHandler', 'synchronized', 'LocalServices', 'File('):
            self.assertNotIn(forbidden, query)
        self.assertIn('volatile Set<VersionedPackage>', rms)
        self.assertIn('Collections.unmodifiableSet(retained)', rms)
        self.assertGreaterEqual(rms.count('attachRollbackStateCallbacks();'), 2)
        self.assertIn('awaitResult(() -> {\n            mRollbacks.addAll(mRollbackStore.loadRollbacks());', rms)
        model = self.src['Rollback.java']
        self.assertIn('mRestoreUserDataInProgress = true;\n            setState(ROLLBACK_STATE_COMMITTED', model)
        self.assertIn('notifyStateChanged();', model)
        self.assertIn('getStaticSharedLibraryDependencies()', model)

    def test_old_apk_identity_and_persistent_metadata_guards(self):
        rms = self.src['RollbackManagerServiceImpl.java']
        capture = method(rms, 'private Set<VersionedPackage> readStaticSharedLibraryDependencies(')
        self.assertIn('installed.applicationInfo.sourceDir', capture)
        self.assertIn('installed.getLongVersionCode() != parsed.getResult().getLongVersionCode()', capture)
        self.assertIn('installed.packageName.equals(parsed.getResult().getPackageName())', capture)
        self.assertIn('getUsesStaticLibrariesVersions()', capture)
        self.assertIn('if (!rollback.saveRollback())', rms)
        self.assertIn('if (!rollback.makeAvailable())', rms)
        store = self.src['RollbackStore.java']
        self.assertIn('dataJson.has("staticSharedLibraryDependencies")', store)
        self.assertIn('dataJson.getJSONArray("staticSharedLibraryDependencies")', store)
        self.assertNotIn('optJSONArray("staticSharedLibraryDependencies")', store)
        self.assertIn('file.finishWrite(fos);\n            return true;', store)
        self.assertIn('return false;', store)

    def test_pm_chokepoint_keeps_exact_version_and_rechecks(self):
        pm = self.src['DeletePackageHelper.java']
        self.assertGreaterEqual(pm.count('if (isStaticLibraryRequiredForRollback('), 2)
        guard = method(pm, 'private boolean isStaticLibraryRequiredForRollback(')
        self.assertIn('pkg.getStaticSharedLibraryVersion()', guard)
        self.assertIn('rollbackManager != null', guard)
        self.assertIn('retained by rollback', guard)
        self.assertIn('return PackageManager.DELETE_FAILED_USED_SHARED_LIBRARY;', pm)

    def test_extractor_rejects_ambiguous_and_truncated(self):
        self.assertIn('return "}";', method('int f() { return "}"; }', 'int f('))
        for text in ('int f() {', 'int f() {} int f() {}'):
            with self.assertRaises(AssertionError): method(text, 'int f(')

    def test_actual_java_bodies_with_mocked_android_surroundings(self):
        javac = os.environ.get('JAVAC') or shutil.which('javac')
        java = os.environ.get('JAVA') or shutil.which('java')
        if not javac or not java:
            self.skipTest('JDK required for changed-function Java trial')
        model = self.src['Rollback.java']; rms = self.src['RollbackManagerServiceImpl.java']
        store = self.src['RollbackStore.java']; pm = self.src['DeletePackageHelper.java']
        model_methods = '\n'.join(method(model, sig) for sig in (
            'void setStateChangedCallback(', 'private void notifyStateChanged(',
            'void addStaticSharedLibraryDependencies(',
            'Set<VersionedPackage> getStaticSharedLibraryDependencies(',
            'boolean retainsStaticSharedLibraries('))
        manager_methods = '\n'.join(method(rms, sig) for sig in (
            'public boolean isStaticSharedLibraryRequired(',
            'private void updateStaticSharedLibraryRetention(',
            'private void attachRollbackStateCallbacks(',
            'private Set<VersionedPackage> readStaticSharedLibraryDependencies('))
        parser = method(store, 'static Set<VersionedPackage> staticSharedLibraryDependenciesFromJson(')
        guard = method(pm, 'private boolean isStaticLibraryRequiredForRollback(')
        start = store.index('            JSONArray dependencies = new JSONArray();')
        end_text = '            dataJson.put("staticSharedLibraryDependencies", dependencies);'
        end = store.index(end_text, start)+len(end_text)
        serializer = store[start:end]
        source = HARNESS.replace('/*MODEL*/', model_methods).replace('/*MANAGER*/', manager_methods)
        source = source.replace('/*PARSER*/', parser).replace('/*GUARD*/', guard).replace('/*SERIALIZER*/', serializer)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'RetentionTrial.java').write_text(source)
            compile_ = subprocess.run([javac, '-d', str(root), str(root/'RetentionTrial.java')],
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compile_.returncode, 0, compile_.stdout+compile_.stderr)
            result = subprocess.run([java, '-cp', str(root), 'RetentionTrial'],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('PASS: retention source trial', result.stdout)


HARNESS = r'''
import java.util.*;
import java.util.concurrent.*;
import java.io.File;
public class RetentionTrial {
 static void check(boolean yes) { if (!yes) throw new AssertionError(); }
 // Mock Android value/JSON/service surroundings, never a PM or AtomicFile result.
 static final class VersionedPackage {
  final String name; final long version;
  VersionedPackage(String n,long v) { name=n;version=v; }
  String getPackageName(){return name;} long getLongVersionCode(){return version;}
  public int hashCode(){return Objects.hash(name,version);}
  public boolean equals(Object o){return o instanceof VersionedPackage && name.equals(((VersionedPackage)o).name) && version==((VersionedPackage)o).version;}
 }
 static final class ApplicationInfo {String sourceDir="/mock/old.apk";}
 static final class PackageInfo {String packageName="consumer";long version=12;ApplicationInfo applicationInfo=new ApplicationInfo();long getLongVersionCode(){return version;}}
 static final class ApkLite {String name="consumer";long version=12;List<String> names=new ArrayList<>();long[] versions=new long[0];String getPackageName(){return name;}long getLongVersionCode(){return version;}List<String> getUsesStaticLibraries(){return names;}long[] getUsesStaticLibrariesVersions(){return versions;}}
 static final class ParseTypeImpl {static ParseTypeImpl forDefaultParsing(){return new ParseTypeImpl();}ParseTypeImpl reset(){return this;}}
 static final class ParseResult<T> {T value;boolean error;ParseResult(T v){value=v;}boolean isError(){return error;}T getResult(){return value;}String getErrorMessage(){return "mock parse failure";}}
 static final class ApkLiteParseUtils {static ParseResult<ApkLite> result=new ParseResult<>(new ApkLite());static ParseResult<ApkLite> parseApkLite(ParseTypeImpl input,File file,int flags){check(file.getPath().equals("/mock/old.apk") && flags==0);return result;}}
 static final class JSONException extends Exception { JSONException(String m){super(m);} }
 static final class JSONObject {
  final Map<String,Object> values=new HashMap<>();
  JSONObject put(String n,Object v){values.put(n,v);return this;}
  Object get(String n)throws JSONException {if(!values.containsKey(n))throw new JSONException(n);return values.get(n);}
  JSONArray getJSONArray(String n)throws JSONException {Object o=get(n);if(!(o instanceof JSONArray))throw new JSONException(n);return (JSONArray)o;}
 }
 static final class JSONArray {
  final List<Object> values=new ArrayList<>();
  JSONArray put(Object v){values.add(v);return this;} int length(){return values.size();}
  JSONObject getJSONObject(int i)throws JSONException {Object o=values.get(i);if(!(o instanceof JSONObject))throw new JSONException("type");return (JSONObject)o;}
 }
 static class Rollback {
  final Thread owner=Thread.currentThread(); int state=0; boolean progress;
  final Set<VersionedPackage> mStaticSharedLibraryDependencies=new HashSet<>();
  Runnable mStateChangedCallback;
  void assertInWorkerThread(){check(Thread.currentThread()==owner);}
  boolean isEnabling(){return state==0;} boolean isAvailable(){return state==1;}
  boolean isRestoreUserDataInProgress(){return progress;}
  // These state setters model Android lifecycle. The retention bodies are exact.
  void state(int s,boolean p){state=s;progress=p;notifyStateChanged();}
  /*MODEL*/
 }
 interface RollbackManagerInternal {boolean isStaticSharedLibraryRequired(String n,long v);}
 static final class Manager implements RollbackManagerInternal {
  final Thread owner=Thread.currentThread(); final List<Rollback> mRollbacks=new ArrayList<>();
  volatile Set<VersionedPackage> mRetainedStaticSharedLibraries=Collections.emptySet();
  void assertInWorkerThread(){check(Thread.currentThread()==owner);}
  /*MANAGER*/
 }
 static class AndroidPackage {
  String name;long version;
  AndroidPackage(String n,long v){name=n;version=v;}
  String getStaticSharedLibraryName(){return name;}long getStaticSharedLibraryVersion(){return version;}
  String getManifestPackageName(){return "mock.library";}
 }
 static final class LocalServices {static RollbackManagerInternal service;static <T>T getService(Class<T> type){return type.cast(service);}}
 static final class Slog {static void w(String t,String m){}static void e(String t,String m){}}
 static final String TAG="test";
 /*GUARD*/
 /*PARSER*/
 static JSONArray serialize(Rollback rollback)throws Exception {
  JSONObject dataJson=new JSONObject();
  /*SERIALIZER*/
  return dataJson.getJSONArray("staticSharedLibraryDependencies");
 }
 static JSONObject entry(Object n,Object v){return new JSONObject().put("libraryName",n).put("libraryVersion",v);}
 public static void main(String[] args)throws Exception {
  Manager manager=new Manager();Rollback one=new Rollback();Rollback two=new Rollback();
  PackageInfo installed=new PackageInfo();ApkLite apk=ApkLiteParseUtils.result.value;
  check(manager.readStaticSharedLibraryDependencies(installed).isEmpty());
  apk.versions=null;check(manager.readStaticSharedLibraryDependencies(installed).isEmpty());
  apk.names=List.of("dep");apk.versions=new long[]{7};check(manager.readStaticSharedLibraryDependencies(installed).equals(Set.of(new VersionedPackage("dep",7))));
  apk.version=13;check(manager.readStaticSharedLibraryDependencies(installed)==null);apk.version=12;
  apk.name="other";check(manager.readStaticSharedLibraryDependencies(installed)==null);apk.name="consumer";
  apk.names=null;check(manager.readStaticSharedLibraryDependencies(installed)==null);
  apk.names=List.of("dep");apk.versions=new long[0];check(manager.readStaticSharedLibraryDependencies(installed)==null);
  ApkLiteParseUtils.result.error=true;check(manager.readStaticSharedLibraryDependencies(installed)==null);
  ApkLiteParseUtils.result.error=false;installed.applicationInfo=null;check(manager.readStaticSharedLibraryDependencies(installed)==null);
  VersionedPackage a=new VersionedPackage("library",1),b=new VersionedPackage("library",2);
  manager.mRollbacks.add(one);manager.attachRollbackStateCallbacks();
  one.addStaticSharedLibraryDependencies(Set.of(a));check(manager.isStaticSharedLibraryRequired("library",1));
  check(!manager.isStaticSharedLibraryRequired("library",2));check(!manager.isStaticSharedLibraryRequired("other",1));
  Set<VersionedPackage> old=manager.mRetainedStaticSharedLibraries;
  one.state(1,false);one.state(3,true);check(manager.isStaticSharedLibraryRequired("library",1));
  one.state(1,false);check(manager.isStaticSharedLibraryRequired("library",1)); // failed commit
  two.addStaticSharedLibraryDependencies(Set.of(a,b));two.state(1,false);
  manager.mRollbacks.add(two);manager.attachRollbackStateCallbacks();
  one.state(4,false);check(manager.isStaticSharedLibraryRequired("library",1));
  check(manager.isStaticSharedLibraryRequired("library",2));
  two.state(3,true);check(manager.isStaticSharedLibraryRequired("library",2)); // staged restore
  two.state(3,false);check(!manager.isStaticSharedLibraryRequired("library",1));
  check(old.contains(a));check(!old.contains(b)); // immutable old snapshot
  try{old.clear();throw new AssertionError();}catch(UnsupportedOperationException expected){}
  Set<VersionedPackage> parsed=staticSharedLibraryDependenciesFromJson(serialize(two));check(parsed.equals(Set.of(a,b)));
  check(staticSharedLibraryDependenciesFromJson(new JSONArray()).isEmpty());
  check(staticSharedLibraryDependenciesFromJson(new JSONArray().put(entry("x",Long.MAX_VALUE))).contains(new VersionedPackage("x",Long.MAX_VALUE)));
  for(Object[] bad:new Object[][]{{"",1},{null,1},{42,1},{"x",-1},{"x","1"},{"x",1.0},{"x",true},{"x",null}}){
   try{staticSharedLibraryDependenciesFromJson(new JSONArray().put(entry(bad[0],bad[1])));throw new AssertionError();}catch(JSONException expected){}
  }
  try{staticSharedLibraryDependenciesFromJson(new JSONArray().put("bad"));throw new AssertionError();}catch(JSONException expected){}
  RetentionTrial trial=new RetentionTrial();LocalServices.service=null;
  check(!trial.isStaticLibraryRequiredForRollback(new AndroidPackage("library",1)));
  LocalServices.service=manager;two.state(1,false);
  check(trial.isStaticLibraryRequiredForRollback(new AndroidPackage("library",2)));
  check(!trial.isStaticLibraryRequiredForRollback(null));check(!trial.isStaticLibraryRequiredForRollback(new AndroidPackage(null,1)));
  ExecutorService reader=Executors.newSingleThreadExecutor();
  // A PM reader does not need the rollback worker to run at all.
  check(reader.submit(()->manager.isStaticSharedLibraryRequired("library",2)).get(2,TimeUnit.SECONDS));
  Future<?> reads=reader.submit(()->{for(int i=0;i<100000;i++)manager.isStaticSharedLibraryRequired("library",2);});
  for(int i=0;i<3000;i++){two.state(i%2==0?1:3,false);}
  reads.get(5,TimeUnit.SECONDS);reader.shutdownNow();
  two.state(4,false);check(!manager.isStaticSharedLibraryRequired("library",2));
  manager.mRollbacks.clear();manager.attachRollbackStateCallbacks();check(manager.mRetainedStaticSharedLibraries.isEmpty());
  System.out.println("PASS: retention source trial (mock Android surroundings)");
 }
}
'''
