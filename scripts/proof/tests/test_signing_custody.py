# SPDX-License-Identifier: Apache-2.0
"""Lab source and plain Java state checks, not Android authorization evidence."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / 'tests/signing-custody'
PACKAGE = FIXTURE / 'src/dev/andrix/proof/signingcustody'
ANDROID = '{http://schemas.android.com/apk/res/android}'


class SigningCustodyTests(unittest.TestCase):
    def test_exact_request_state_with_copy_and_concurrency_controls(self):
        javac, java = shutil.which('javac'), shutil.which('java')
        self.assertIsNotNone(javac); self.assertIsNotNone(java)
        with tempfile.TemporaryDirectory() as directory:
            args = [javac, '-J-Xmx128m', '--release', '17', '-Xlint:all', '-Werror',
                    '-d', directory, str(PACKAGE / 'SigningRequest.java'),
                    str(FIXTURE / 'SigningRequestTest.java')]
            compiled = subprocess.run(args, capture_output=True, text=True, timeout=40)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run([java, '-Xmx128m', '-ea', '-cp', directory,
                                  'dev.andrix.proof.signingcustody.SigningRequestTest'],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('SIGNING_REQUEST_MODEL_PASS races=400', ran.stdout)

    def test_lab_apks_do_not_join_a_shared_uid_or_platform_product(self):
        for path in [FIXTURE / 'AndroidManifest.xml', FIXTURE / 'negative/AndroidManifest.xml']:
            root = ET.parse(path).getroot()
            self.assertNotIn(ANDROID + 'sharedUserId', root.attrib)
            self.assertEqual(root.find('application').get(ANDROID + 'allowBackup'), 'false')
        bp = (FIXTURE / 'Android.bp').read_text()
        self.assertNotIn('certificate: "platform"', bp)
        self.assertNotIn('privileged: true', bp)
        for product in (ROOT / 'products').glob('*.mk'):
            self.assertNotIn('AndrixSigningCustodyProof', product.read_text())
            self.assertNotIn('AndrixSigningCustodyNegative', product.read_text())

    def test_caller_check_precedes_request_decode_and_import(self):
        source = (PACKAGE / 'ProofProvider.java').read_text()
        self.assertIn('int caller = Binder.getCallingUid()', source)
        self.assertIn('caller != 2000', source)
        self.assertNotIn('getCallingPid', source)
        call = source[source.index('@Override public Bundle call'):source.index('@Override public ParcelFileDescriptor openFile')]
        self.assertLess(call.index('enforceLabCaller()'), call.index('Binder.clearCallingIdentity()'))
        self.assertLess(call.index('enforceLabCaller()'), call.index('Base64.decode'))
        stream = source[source.index('@Override public ParcelFileDescriptor openFile'):source.index('@Override public Cursor query')]
        self.assertLess(stream.index('enforceLabCaller()'), stream.index('broker.importPipe()'))
        self.assertIn('Binder.restoreCallingIdentity(identity)', call)
        self.assertIn('Binder.restoreCallingIdentity(identity)', stream)

    def test_authentication_is_bound_to_stored_operation_not_an_ambient_flag(self):
        source = (PACKAGE / 'ProofBroker.java').read_text()
        self.assertIn('.setUserAuthenticationParameters(0, KeyProperties.AUTH_DEVICE_CREDENTIAL)', source)
        self.assertIn('ERROR_USER_AUTHENTICATION_REQUIRED', source)
        self.assertIn('result.getCryptoObject().getSignature() == signature', source)
        self.assertIn('active == current', source)
        self.assertIn('request.claimSigning()', source)
        self.assertIn('current.request.state() == SigningRequest.State.SIGNING', source)
        self.assertIn('key.getEncoded() == null && key.getFormat() == null', source)
        self.assertNotIn('setUserAuthenticationValidityDurationSeconds(', source)
        activity = (PACKAGE / 'ApprovalActivity.java').read_text()
        self.assertIn('broker.find(id)', activity)
        self.assertNotIn('getByteArrayExtra', activity)
        self.assertIn('FLAG_SECURE', activity)
        self.assertIn('setFilterTouchesWhenObscured(true)', activity)
        self.assertIn('broker.approve(this, request)', activity)


if __name__ == '__main__': unittest.main()
