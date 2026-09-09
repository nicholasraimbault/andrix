# SPDX-License-Identifier: Apache-2.0
"""Host-only probe parser/profile and permission-flow tests; no Android or network."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / 'tests/webview-probe'
JAVA = PROBE / 'src/dev/andrix/proof/webview'


class WebViewProbeProfileTests(unittest.TestCase):
    def test_real_java_url_and_platform_metadata_contracts(self):
        java = os.environ.get('JAVA') or shutil.which('java')
        javac = os.environ.get('JAVAC') or shutil.which('javac')
        if not java or not javac:
            self.skipTest('JDK required')
        with tempfile.TemporaryDirectory() as tmp:
            sources = [JAVA / 'ProbeConfig.java', JAVA / 'ProbePlatformProfile.java',
                       PROBE / 'host-tests/ProbeConfigTest.java',
                       PROBE / 'host-tests/ProbePlatformProfileTest.java']
            result = subprocess.run([javac, '-d', tmp, *map(str, sources)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ('ProbeConfigTest', 'ProbePlatformProfileTest'):
                with self.subTest(name=name):
                    result = subprocess.run([java, '-cp', tmp, 'dev.andrix.proof.webview.' + name],
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('host-only', result.stdout)

    def test_permission_flow_source_contracts(self):
        result = subprocess.run([sys.executable, '-B',
                                 str(PROBE / 'host-tests/test_permission_contract.py')],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('OK', result.stderr)
