# SPDX-License-Identifier: Apache-2.0
"""Host tests of the producer: its refusals before any output, the manifest and compiled manifest
contracts, the pins and the pinned Binder signature, and the artifact checks.

ANDRIX_NOTICE_ANDROID_ROOT names the pinned tree for the source pin checks, and
ANDRIX_NOTICE_BUILD a finished producer output directory for the artifact checks on real bytes.
Without them those cases are skipped, which qualifies nothing. No case runs a tool."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import produce  # noqa: E402

ANDROID = os.environ.get('ANDRIX_NOTICE_ANDROID_ROOT')
BUILD = os.environ.get('ANDRIX_NOTICE_BUILD')


class ManifestTests(unittest.TestCase):
    def test_the_source_manifest_is_exactly_the_contract(self):
        produce.manifest_contract((HERE / 'AndroidManifest.xml').read_bytes())

    def test_changed_manifests_are_refused(self):
        good = (HERE / 'AndroidManifest.xml').read_text()
        changes = {
            'a requested permission': good.replace('<application', '<uses-permission android:name="android.permission'
                                                   '.INTERNET" />\n    <application'),
            'a shared UID': good.replace('android:versionCode="1"',
                                         'android:versionCode="1" android:sharedUserId="a.b"'),
            'a process': good.replace('android:hasCode="true"', 'android:hasCode="true" android:process=":x"'),
            'no DUMP on the provider': good.replace(
                'android:exported="true" android:permission="android.permission.DUMP"\n'
                '            android:directBootAware="true" android:grant',
                'android:exported="true"\n            android:directBootAware="true" android:grant'),
            'not direct boot aware': good.replace('android:directBootAware="true"',
                                                  'android:directBootAware="false"', 1),
            'not shown when locked': good.replace('android:showWhenLocked="true"', 'android:showWhenLocked="false"'),
            'an intent filter': good.replace('NoActionBar" />', 'NoActionBar">\n<intent-filter />\n</activity>'),
            'debuggable': good.replace('android:debuggable="false"', 'android:debuggable="true"'),
            'not test only': good.replace('android:testOnly="true"', 'android:testOnly="false"'),
            'another package': good.replace('package="dev.andrix.lab.notice"', 'package="dev.andrix.lab.other"'),
            'a doctype': '<!DOCTYPE x>\n' + good.split('\n', 1)[1],
        }
        for name, text in changes.items():
            with self.subTest(name):
                self.assertNotEqual(text, good)
                with self.assertRaises(ValueError):
                    produce.manifest_contract(text.encode())

    def test_the_pinned_tools_compiled_manifest_dump_is_the_contract(self):
        tree = (HERE / 'goldens/compiled-manifest.txt').read_text()
        produce.compiled_manifest(tree)
        changes = {
            'the provider permission': tree.replace(
                '            A: http://schemas.android.com/apk/res/android:permission(0x01010006)="android.permission.'
                'DUMP" (Raw: "android.permission.DUMP")\n            A: http://schemas.android.com/apk/res/android:'
                'exported(0x01010010)=true\n            A: http://schemas.android.com/apk/res/android:multiprocess',
                '            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true\n'
                '            A: http://schemas.android.com/apk/res/android:multiprocess'),
            'turned off screen': tree.replace('turnScreenOn(0x0101056a)=true', 'turnScreenOn(0x0101056a)=false'),
            'an app theme': tree.replace('=@0x01030129', '=@0x7f050000'),
            'a target SDK': tree.replace('targetSdkVersion(0x01010270)=37', 'targetSdkVersion(0x01010270)=36'),
            'a duplicate attribute': tree.replace('            A: http://schemas.android.com/apk/res/android:'
                                                  'multiprocess(0x01010013)=false\n',
                                                  '            A: http://schemas.android.com/apk/res/android:'
                                                  'multiprocess(0x01010013)=false\n' * 2),
        }
        for name, text in changes.items():
            with self.subTest(name):
                self.assertNotEqual(text, tree)
                with self.assertRaises(ValueError):
                    produce.compiled_manifest(text)


class PinTests(unittest.TestCase):
    def test_the_pins_are_whole_and_the_helper_looks_up_the_pinned_signature(self):
        pins = produce.pins_contract(produce.strict_json((HERE / 'pins.json').read_bytes()))
        binder = pins['binder']
        source = (HERE / 'present-src/dev/andrix/lab/notice/NoticePresent.java').read_text()
        call = re.search(r'getMethod\("startActivityAndWait", (.*?)\);', source, re.S)[1]
        found = []
        for part in [p.strip() for p in call.replace('\n', ' ').split(',')]:
            named = re.fullmatch(r'Class\.forName\("([\w.]+)"\)', part)
            simple = {'String.class': 'java.lang.String', 'Intent.class': 'android.content.Intent',
                      'IBinder.class': 'android.os.IBinder', 'Bundle.class': 'android.os.Bundle', 'int.class': 'int'}
            found.append(named[1] if named else simple[part])
        self.assertEqual(found, binder['parameters'])
        self.assertIn('Class.forName("%s")' % binder['returns'], source)
        self.assertEqual(json.loads((HERE / 'pins.json').read_text()), pins)
        self.assertEqual(pins['helper_jar']['name'], 'andrix-notice-present.jar')

    @unittest.skipUnless(ANDROID, 'needs ANDRIX_NOTICE_ANDROID_ROOT, the pinned tree')
    def test_the_pinned_sources_and_the_aidl_declaration_are_the_helpers(self):
        root = Path(ANDROID)
        references = produce.strict_json((HERE / 'framework-api.json').read_bytes())
        for path, digest in references.items():
            self.assertEqual(produce.digest(root / path), digest, path)
        binder = produce.strict_json((HERE / 'pins.json').read_bytes())['binder']
        lines = (root / binder['aidl']).read_bytes().split(b'\n')
        first, last = binder['lines']
        text = b'\n'.join(lines[first - 1:last]).decode()
        self.assertEqual(hashlib.sha256((text + '\n').encode()).hexdigest(), binder['lines_sha256'])
        m = re.fullmatch(r'\s*WaitResult startActivityAndWait\((.*)\);\s*', text, re.S)
        types = [re.fullmatch(r'(?:in )?([\w.]+) \w+', p.strip())[1] for p in m[1].split(',')]
        qualified = {'IApplicationThread': 'android.app.IApplicationThread', 'String': 'java.lang.String',
                     'Intent': 'android.content.Intent', 'IBinder': 'android.os.IBinder', 'int': 'int',
                     'ProfilerInfo': 'android.app.ProfilerInfo', 'Bundle': 'android.os.Bundle'}
        self.assertEqual([qualified[t] for t in types], binder['parameters'])


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='notice-preflight-')
        self.addCleanup(self.temporary.cleanup)
        self.dir = Path(self.temporary.name).resolve()
        self.cert = self.dir / 'cert.der'
        self.cert.write_bytes(b'\x30' + bytes(range(200)))
        self.signer = hashlib.sha256(self.cert.read_bytes()).hexdigest()
        self.key = self.dir / 'key.pk8'
        self.key.write_bytes(b'not a key')
        self.android = self.dir / 'android'
        for tool in produce.TOOLS:
            path = self.android / tool
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'another tool')
        self.out = self.dir / 'out'

    def refused(self, message, **changes):
        args = dict(android_root=self.android, source=HERE, key=self.key, cert=self.cert, signer=self.signer,
                    output=self.out)
        args.update(changes)
        with self.assertRaises(ValueError) as caught:
            produce.preflight(**args)
        self.assertIn(message, str(caught.exception))
        self.assertFalse(self.out.exists(), 'nothing is written before every check passed')

    def test_each_refusal_comes_before_any_output(self):
        self.refused('explicit signer', signer='AB' * 32)
        self.refused('not the named signer', signer='ab' * 32)
        self.refused('output must be absent', output=self.dir)
        self.refused('outside source', output=HERE / 'out')
        self.refused('pinned tool digest mismatch')
        broken = self.dir / 'broken.der'
        broken.write_bytes(b'-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n')
        with self.assertRaises(ValueError):
            produce.preflight(self.android, HERE, self.key, broken, self.signer, self.out)

    def test_the_build_refuses_a_missing_revision_claim_before_writing(self):
        with self.assertRaises(ValueError):
            produce.build(self.android, HERE, self.key, self.cert, self.signer, self.out, 'HEAD')
        self.assertFalse(self.out.exists())


@unittest.skipUnless(BUILD, 'needs ANDRIX_NOTICE_BUILD, a finished producer output directory')
class ArtifactTests(unittest.TestCase):
    def test_the_finished_output_passes_the_artifact_checks(self):
        summary = produce.check_output(Path(BUILD))
        pins = produce.strict_json((HERE / 'pins.json').read_bytes())
        self.assertEqual(summary['helper_jar_sha256'], pins['helper_jar']['sha256'])

    def test_changed_outputs_and_references_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='notice-artifact-') as temporary:
            copy = Path(temporary) / 'out'
            shutil.copytree(BUILD, copy)
            with zipfile.ZipFile(copy / produce.APK) as archive:
                dex = archive.read('classes.dex')
            helper = zipfile.ZipFile(copy / produce.HELPER_JAR).read('classes.dex')
            with self.assertRaises(ValueError):
                produce.class_contract(dex, produce.DEX_CLASSES[:-1], produce.APP_REQUIRED, produce.APP_FORBIDDEN)
            with self.assertRaises(ValueError):
                produce.class_contract(helper, produce.HELPER_CLASSES, produce.HELPER_REQUIRED,
                                       produce.FORBIDDEN + ('startActivityAndWait',))
            with self.assertRaises(ValueError):
                produce.class_contract(dex, produce.DEX_CLASSES, produce.APP_REQUIRED + ('requestDismissKeyguard',),
                                       produce.APP_FORBIDDEN)
            jar = bytearray((copy / produce.HELPER_JAR).read_bytes())
            jar[-30] ^= 1
            (copy / produce.HELPER_JAR).write_bytes(bytes(jar))
            with self.assertRaises(Exception):
                produce.check_output(copy)
            shutil.rmtree(copy)
            shutil.copytree(BUILD, copy)
            artifact = json.loads((copy / 'artifact.json').read_text())
            artifact['certificate_sha256'] = 'ab' * 32
            (copy / 'artifact.json').write_text(json.dumps(artifact))
            with self.assertRaises(ValueError):
                produce.check_output(copy)


if __name__ == '__main__':
    unittest.main()
