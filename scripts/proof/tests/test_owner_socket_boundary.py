# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'tests/owner-socket-boundary'
ANDROID='{http://schemas.android.com/apk/res/android}'


class SocketBoundaryTests(unittest.TestCase):
    def test_optional_ordinary_identity_and_no_permission_borrowing(self):
        root=ET.parse(BASE/'AndroidManifest.xml').getroot()
        self.assertEqual(root.get('package'),'dev.andrix.proof.socketboundary')
        self.assertIsNone(root.find('uses-permission'))
        self.assertNotIn(ANDROID+'sharedUserId',root.attrib)
        self.assertNotIn('AndrixSocketBoundary',(ROOT/'products/andrix_gos_cf_arm64_only_phone.mk').read_text())
        source=(BASE/'src/dev/andrix/proof/socketboundary/SocketBoundary.java').read_text()
        self.assertIn('DENIAL_OBSERVED_REQUIRE_LIVE_OWNER_SOCKET_CONTROLS',source)
        self.assertIn('"self_errno") == 0',source)
        self.assertNotIn('adoptShellPermissionIdentity',source)
        native=(BASE/'probe.c').read_text()
        self.assertNotIn('kill(',native)
        self.assertIn('MSG_NOSIGNAL',native)

    def test_actual_host_named_socket_positive_and_missing_control(self):
        compiler=shutil.which('cc');self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='andrix-sock-',dir='/tmp') as temp:
            work=Path(temp);binary=work/'probe'
            result=subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-O2',
                '-DANDRIX_SOCKET_HOST_TEST',str(BASE/'probe.c'),'-o',str(binary)],
                capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            ran=subprocess.run([str(binary),str(work)],capture_output=True,text=True,timeout=10)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertIn('SELF_NAMED_SOCKET_CONNECT_OK',ran.stdout)
            self.assertEqual(list(work.iterdir()),[binary])
            invalid=subprocess.run([str(binary)],capture_output=True,timeout=5)
            self.assertEqual(invalid.returncode,2)
            too_long=subprocess.run([str(binary),'/'+'x'*120],capture_output=True,text=True,timeout=5)
            self.assertEqual(too_long.returncode,1)
            self.assertIn('self error=',too_long.stderr)


if __name__=='__main__':unittest.main()
