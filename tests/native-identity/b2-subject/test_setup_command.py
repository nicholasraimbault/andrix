# SPDX-License-Identifier: Apache-2.0
"""Run the actual shell command source against an explicit host object model, not Android.

The model intentionally returns a stored alias even for a fake remote interface. It tests that
our explicit Parcel copy and guards, rather than a supposed transport copy, prevent mutation
before the user update comparison. It does not emulate Android IPC, Parcelable or persistence.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile
import unittest

import fixtures as f
import observations as obs
import produce
import protocol as p
import stored

HERE = Path(__file__).resolve().parent

# These test only classes are generated in scratch, never included by produce.py.
STUBS = {
    'android/os/Process.java': '''package android.os;
public final class Process {
  public static int myUid() { return Integer.parseInt(System.getProperty("probe.uid", "2000")); }
}
''',
    'android/os/IInterface.java': '''package android.os;
public interface IInterface { }
''',
    'android/os/IBinder.java': '''package android.os;
public interface IBinder {
  boolean isBinderAlive(); IInterface queryLocalInterface(String descriptor);
}
''',
    'android/os/Parcel.java': '''package android.os;
public final class Parcel {
  private final java.util.ArrayList<Integer> data = new java.util.ArrayList<>();
  private int position;
  public static Parcel obtain() { return new Parcel(); }
  public void setDataPosition(int at) { position = at; }
  public void recycle() { }
  public void writeInt(int value) { data.add(value); }
  public int readInt() { return data.get(position++); }
}
''',
    'android/app/NotificationChannel.java': '''package android.app;
import android.os.Parcel;
public final class NotificationChannel {
  public int bubbles = -1, locked;
  public static final Creator CREATOR = new Creator();
  public static final class Creator {
    public NotificationChannel createFromParcel(Parcel parcel) {
      NotificationChannel copy = new NotificationChannel();
      copy.bubbles = parcel.readInt(); copy.locked = parcel.readInt(); return copy;
    }
  }
  public void writeToParcel(Parcel parcel, int flags) {
    parcel.writeInt(bubbles); parcel.writeInt(locked);
  }
  public String getId() { return "andrix.b2.state"; }
  public CharSequence getName() { return "Andrix B2 state"; }
  public String getDescription() { return null; }
  public int getImportance() { return 2; }
  public Object getSound() { return null; }
  public boolean shouldVibrate() { return false; }
  public boolean shouldShowLights() { return false; }
  public boolean canShowBadge() { return true; }
  public String getGroup() { return null; }
  public String getParentChannelId() { return null; }
  public String getConversationId() { return null; }
  public boolean canBubble() { return bubbles == 1; }
  public void setAllowBubbles(boolean allow) { bubbles = allow ? 1 : 0; }
  public String toString() {
    return "NotificationChannel{mId='andrix.b2.state', mUserLockedFields="
        + Integer.toHexString(locked) + ", mAllowBubbles=" + bubbles + ", end=false}";
  }
}
''',
    'android/app/INotificationManager.java': '''package android.app;
import android.os.IBinder;
public interface INotificationManager {
  NotificationChannel getNotificationChannel(String caller, int user, String pkg, String channel);
  void updateNotificationChannelForPackage(String pkg, int uid, NotificationChannel channel);
  public static final class Stub {
    public static INotificationManager asInterface(IBinder binder) {
      return android.os.ServiceManager.manager;
    }
  }
}
''',
    'android/os/ServiceManager.java': '''package android.os;
import android.app.INotificationManager;
import android.app.NotificationChannel;
public final class ServiceManager {
  public static final Manager manager = new Manager();
  public static final class Manager implements INotificationManager {
    public NotificationChannel stored = new NotificationChannel();
    public int gets, sets;
    public NotificationChannel getNotificationChannel(String caller, int user, String pkg, String id) {
      if (!caller.equals("com.android.shell") || user != 0
          || !pkg.equals("dev.andrix.proof.principalclosed") || !id.equals("andrix.b2.state")) {
        throw new IllegalStateException("scope");
      }
      gets++; return stored; // Deliberately a stored alias, NOT a real remote Binder model.
    }
    public void updateNotificationChannelForPackage(String pkg, int uid, NotificationChannel update) {
      if (!pkg.equals("dev.andrix.proof.principalclosed") || uid != 10123) {
        throw new IllegalStateException("scope");
      }
      sets++;
      // Selected rule from PreferencesHelper.lockFieldsForUpdateLocked, not an NMS emulator.
      update.locked |= stored.locked;
      if (stored.bubbles != update.bubbles) update.locked |= 0x100;
      stored = update;
    }
  }
  public static IBinder getService(String name) {
    if (!name.equals("notification")) throw new IllegalStateException("wrong service");
    if (Boolean.getBoolean("probe.missing")) return null;
    return new IBinder() {
      public boolean isBinderAlive() { return true; }
      public IInterface queryLocalInterface(String descriptor) {
        return Boolean.getBoolean("probe.local") ? new IInterface() { } : null;
      }
    };
  }
}
''',
    'org/json/JSONObject.java': '''package org.json;
public final class JSONObject {
  private final java.util.LinkedHashMap<String,Object> fields = new java.util.LinkedHashMap<>();
  public JSONObject put(String key, Object value) { fields.put(key, value); return this; }
  public String toString() {
    StringBuilder out = new StringBuilder("{");
    for (java.util.Map.Entry<String,Object> row : fields.entrySet()) {
      if (out.length() != 1) out.append(',');
      out.append('"').append(row.getKey()).append("\\\":");
      if (row.getValue() instanceof String) out.append('"').append(row.getValue()).append('"');
      else out.append(row.getValue());
    }
    return out.append('}').toString();
  }
}
''',
    'Probe.java': '''import android.app.NotificationChannel;
import android.os.ServiceManager;
import dev.andrix.proof.b2setup.NotificationSetup;
import org.json.JSONObject;
public final class Probe {
  public static void main(String[] args) throws Exception {
    ServiceManager.Manager manager = ServiceManager.manager;
    String mode = System.getProperty("probe.mode", "copy");
    boolean accepted = false;
    String error = "none";
    if (mode.equals("preexisting")) manager.stored.bubbles = 1;
    try {
      if (mode.equals("old-shell")) {
        NotificationChannel alias = manager.getNotificationChannel("com.android.shell", 0,
            "dev.andrix.proof.principalclosed", "andrix.b2.state");
        alias.setAllowBubbles(true);
        manager.updateNotificationChannelForPackage("dev.andrix.proof.principalclosed", 10123, alias);
      } else {
        System.out.println("ANDRIX_B2_NOTIFICATION_SETUP: " + NotificationSetup.run(args));
        accepted = true;
      }
    } catch (Exception problem) { error = problem.getClass().getSimpleName(); }
    System.out.println(new JSONObject().put("accepted", accepted).put("getter_calls", manager.gets)
        .put("setter_calls", manager.sets).put("bubbles", manager.stored.bubbles)
        .put("lock", manager.stored.locked).put("error", error));
  }
}
'''}


class SetupCommandModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get('B2_JDK_BIN')
        if not value:
            raise unittest.SkipTest('B2_JDK_BIN is required for the separately bounded JVM model')
        cls.jdk = Path(value)
        tools = json.loads((HERE / 'tools.json').read_text())
        for tool in ('javac', 'java'):
            actual = hashlib.sha256((cls.jdk / tool).read_bytes()).hexdigest()
            if actual != tools[produce.JDK + tool]:
                raise ValueError('model needs the pinned JDK')
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if soft == resource.RLIM_INFINITY or not (1536 << 20) <= soft <= (2 << 30):
            raise ValueError('run JVM model with a bounded 2 GiB parent address space')
        cls.temporary = tempfile.TemporaryDirectory(prefix='b2-shell-model-')
        cls.root = Path(cls.temporary.name)
        cls.vm = ['-Xmx128m', *produce.VM, '-Djava.io.tmpdir=' + str(cls.root),
                  '-Duser.home=' + str(cls.root)]
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(cls.root), 'TMPDIR': str(cls.root),
                   'LANG': 'C.UTF-8'}
        source = (HERE / produce.SETUP_SOURCE).read_text()
        cls.classes = []
        for index, text in enumerate((source, source.replace(
                'NotificationChannel changed = copyChannel(original);',
                'NotificationChannel changed = original;'))):
            directory = cls.root / str(index); directory.mkdir()
            sources = []
            for path, content in STUBS.items():
                output = directory / path; output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(content); sources.append(output)
            command = directory / 'NotificationSetup.java'; command.write_text(text)
            output = directory / 'classes'; output.mkdir(); cls.classes.append(output)
            args = [cls.jdk / 'javac', '-J-Xmx128m', *['-J' + x for x in cls.vm[1:]],
                    '--release', '17', '-proc:none', '-d', output, command, *sources]
            result = subprocess.run(list(map(str, args)), cwd=cls.root, env=cls.env,
                                    capture_output=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr.decode())

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'temporary'):
            cls.temporary.cleanup()

    def probe(self, mutant=False, properties=(), args=None):
        result = subprocess.run(list(map(str, [self.jdk / 'java', *self.vm, *properties, '-cp',
            self.classes[1 if mutant else 0], 'Probe', *(args if args is not None else [
                str(f.UID), f.NONCE, f.CONTRACT['setup'], f.CONTRACT['contract_sha256']])])),
            cwd=self.root, env=self.env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        lines = result.stdout.decode().splitlines()
        return lines[:-1], json.loads(lines[-1])

    def test_actual_command_copies_even_a_stored_alias_before_update(self):
        lines, state = self.probe()
        self.assertTrue(state['accepted'])
        self.assertEqual((state['bubbles'], state['lock'], state['setter_calls']), (1, 256, 1))
        cap = f.capture(p.notification_setup_argv(f.CONTRACT, f.NONCE), '\n'.join(lines) + '\n')
        self.assertIs(obs.notification_setup(cap, f.CONTRACT, f.NONCE)['state_proven'], False)

    def test_old_in_place_route_produces_unlocked_state_and_both_oracles_refuse(self):
        lines, state = self.probe(properties=['-Dprobe.mode=old-shell'])
        self.assertEqual((state['bubbles'], state['lock'], state['setter_calls']), (1, 0, 1))
        self.assertEqual(lines, [])
        with self.assertRaises(ValueError):
            obs.notification(f.capture(['dumpsys', 'notification', '--noredact', '--package', p.PACKAGE],
                                       f.notification_text(preference='old-shell')), f.UID)
        with self.assertRaises(ValueError):
            stored.notification_policy(f.notification_xml(preference='old-shell'), f.UID)

    def test_clone_bypass_mutant_is_refused_before_any_mutation(self):
        lines, state = self.probe(mutant=True)
        self.assertFalse(state['accepted'])
        self.assertEqual((state['bubbles'], state['lock'], state['setter_calls']), (-1, 0, 0))
        self.assertEqual(lines, [])

    def test_root_app_uid_local_missing_binder_and_preexisting_preference_refused(self):
        for properties in (['-Dprobe.uid=0'], ['-Dprobe.uid=10123'], ['-Dprobe.local=true'],
                           ['-Dprobe.missing=true'], ['-Dprobe.mode=preexisting']):
            with self.subTest(properties=properties):
                lines, state = self.probe(properties=properties)
                self.assertFalse(state['accepted'])
                self.assertEqual(state['setter_calls'], 0)
                self.assertEqual(lines, [])
        for args in ([], [str(f.UID), 'bad', f.CONTRACT['setup'], f.CONTRACT['contract_sha256']],
                     ['9999', f.NONCE, f.CONTRACT['setup'], f.CONTRACT['contract_sha256']]):
            with self.subTest(args=args):
                lines, state = self.probe(args=args)
                self.assertFalse(state['accepted'])
                self.assertEqual((state['getter_calls'], state['setter_calls']), (0, 0))
                self.assertEqual(lines, [])


if __name__ == '__main__':
    unittest.main()
