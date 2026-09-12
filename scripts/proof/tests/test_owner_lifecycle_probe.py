# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'tests/owner-lifecycle-probe'
JAVA=BASE/'src/dev/andrix/proof/lifecycle'
ANDROID='{http://schemas.android.com/apk/res/android}'


class LifecycleProbeTests(unittest.TestCase):
    def test_ordinary_explicit_foreground_probe_not_owner_authority(self):
        root=ET.parse(BASE/'AndroidManifest.xml').getroot()
        self.assertEqual(root.get('package'),'dev.andrix.proof.lifecycle')
        self.assertNotIn(ANDROID+'sharedUserId',root.attrib)
        self.assertEqual({x.get(ANDROID+'name') for x in root.findall('uses-permission')},
                         {'android.permission.FOREGROUND_SERVICE',
                          'android.permission.FOREGROUND_SERVICE_SPECIAL_USE',
                          'android.permission.POST_NOTIFICATIONS'})
        app=root.find('application')
        self.assertEqual(app.get(ANDROID+'testOnly'),'true')
        self.assertIsNone(app.get(ANDROID+'persistent'))
        self.assertIsNone(app.get(ANDROID+'usesNonSdkApi'))
        service=app.find('service')
        self.assertEqual(service.get(ANDROID+'exported'),'false')
        self.assertEqual(service.get(ANDROID+'process'),':witness')
        self.assertEqual(service.get(ANDROID+'foregroundServiceType'),'specialUse')
        self.assertEqual(service.get(ANDROID+'stopWithTask'),'false')
        self.assertIsNone(app.find('receiver')) # No auto-start after reboot.
        self.assertNotIn('AndrixLifecycleProbe',(ROOT/'products/andrix_gos_cf_arm64_only_phone.mk').read_text())
        for path in JAVA.glob('*.java'):
            text=path.read_text()
            for forbidden in ['adoptShellPermissionIdentity','ServiceManager','dev.andrix.session','/data/misc_ce','MANAGE_USERS']:
                self.assertNotIn(forbidden,text)

    def test_service_sampling_and_generation_guards_are_explicit(self):
        source=(JAVA/'WitnessService.java').read_text()
        self.assertEqual(source.count('users.isUserRunning(Process.myUserHandle())'),2)
        self.assertIn('users.isUserUnlocked()',source)
        self.assertIn('Binder.getCallingUid() != Process.myUid()',source)
        self.assertIn('copy.getLong("epoch", -1) == epoch',source)
        self.assertIn('if (!active || epoch != generation) return;',source)
        self.assertIn('if (epoch == generation) stopProbe();',source)
        self.assertIn('START_NOT_STICKY',source)
        self.assertIn('MAX_DURATION_MS = 15 * 60 * 1000',source)
        self.assertIn('PendingIntent.FLAG_IMMUTABLE',source)
        self.assertIn('areNotificationsEnabled()',source)
        activity=(JAVA/'ProbeActivity.java').read_text()
        self.assertIn('requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}',activity)
        self.assertIn('Process.killProcess(Process.myPid())',activity)
        self.assertNotIn('BIND_AUTO_CREATE',activity)
        self.assertIn('connection, 0)',activity)

    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'),'host JDK required')
    def test_real_sample_predicate_does_not_confuse_unlocked_with_running(self):
        with tempfile.TemporaryDirectory() as temp:
            work=Path(temp);main=work/'Check.java'
            main.write_text('''import dev.andrix.proof.lifecycle.LifecycleSample;
public final class Check {
  public static void main(String[] args) {
    for (int mask=0;mask<16;mask++) {
      boolean result=LifecycleSample.usable((mask&1)!=0,(mask&2)!=0,(mask&4)!=0,(mask&8)!=0);
      if (result != (mask==15)) throw new AssertionError(mask);
    }
    if (!LifecycleSample.fresh(100,0,101)) throw new AssertionError();
    if (LifecycleSample.fresh(100,0,100)) throw new AssertionError();
    if (LifecycleSample.fresh(100,101,10)) throw new AssertionError();
    if (LifecycleSample.fresh(100,-1,10)) throw new AssertionError();
    if (LifecycleSample.fresh(0,0,0)) throw new AssertionError();
    if (LifecycleSample.fresh(Long.MAX_VALUE,0,Long.MAX_VALUE)) throw new AssertionError();
    if (!LifecycleSample.fresh(Long.MAX_VALUE,Long.MAX_VALUE,1)) throw new AssertionError();
  }
}
''')
            subprocess.run(['javac','-d',str(work),str(JAVA/'LifecycleSample.java'),str(main)],
                           check=True,capture_output=True,timeout=30)
            subprocess.run(['java','-cp',str(work),'Check'],check=True,capture_output=True,timeout=20)


if __name__=='__main__':unittest.main()
