# SPDX-License-Identifier: Apache-2.0
"""Exact source fault controls for preparation. No device or general JVM OOM claim."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_principal_pins as integration


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('preparation source seam drift')
    return text.replace(old, new, 1)


class NativePreparationFaultTests(unittest.TestCase):
    def test_index_faults_original_ownership_and_sensitivity(self):
        self.assertTrue(shutil.which('javac') and shutil.which('java'), 'preparation qualification requires JDK')
        integration.profile()
        core = (ROOT / 'owner/platform/framework/NativePrincipalPins.java').read_text()
        manager = (ROOT / 'owner/platform/framework/NativePrincipalManager.java').read_text()
        self.assertNotIn('NativePreparationFaults', core + manager)
        for statement in (
                'packages.put(record.packageName, entry);', 'appIds.put(record.appId, entry);',
                'entry.users.put(record.userId, pin);', 'ids.put(record.id, pin);',
                'entry.users.remove(record.userId);', 'packages.remove(record.packageName);',
                'appIds.remove(record.appId);', 'ids.remove(record.id);'):
            core = replace_once(core, statement, statement + ' NativePreparationFaults.mapChanged();')
        manager = replace_once(manager, 'pin = pins.prepare(proposal, issuance);',
                               'pin = pins.prepare(proposal, issuance); NativePreparationFaults.afterIssuance();')
        unsafe = core.replace('Index next = copyIndex();', 'Index next = index;')
        self.assertEqual(core.count('Index next = copyIndex();'), 2)
        no_owner = replace_once(core, 'Pin pin = new Pin(this, record, issuance);',
                               'Pin pin = new Pin(this, record, null);')
        no_epoch = replace_once(core, 'if (proposal.owner != this || proposal.epoch != preparationEpoch)',
                               'if (false)')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for mode, text, test in [('controlled', core, 'NativePreparationFaultTest'),
                                     ('unsafe-index', unsafe, 'NativePreparationFaultTest'),
                                     ('discard-owner', no_owner, 'NativePreparationFaultTest'),
                                     ('ignore-epoch', no_epoch, 'NativePreparationAdmissionTest')]:
                work = base / mode
                work.mkdir()
                pins = work / 'NativePrincipalPins.java'
                pins.write_text(text)
                adapter = work / 'NativePrincipalManager.java'
                adapter.write_text(manager)
                fixtures = []
                for name in ['AppIdSettingMap', 'ResilientAtomicFile']:
                    target = work / (name + '.java')
                    target.write_bytes(integration.FIXTURES[integration.PREFIX + name + '.java'].read_bytes())
                    fixtures.append(target)
                stubs = {}
                for directory in ['native_principal_stubs', 'native_principal_xml_stubs']:
                    path = ROOT / 'owner/tests/platform' / directory
                    for source in path.rglob('*.java'):
                        if source.name != 'Xml.java':
                            stubs[source.relative_to(path).as_posix()] = source
                sources = [pins, adapter, *fixtures, *stubs.values(),
                           *[ROOT / 'owner/platform/framework' / (name + '.java') for name in
                             ['NativeIdentityRecords', 'NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalRecovery']],
                           *[ROOT / 'owner/tests/platform' / (name + '.java') for name in
                             ['NativePreparationFaults', 'NativePreparationFaultTest', 'NativePreparationAdmissionTest', 'NativePinTestSupport']]]
                compile_result = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                                                 '-d', str(work), *map(str, sources)],
                                                capture_output=True, text=True, timeout=120)
                self.assertEqual(compile_result.returncode, 0, compile_result.stdout + compile_result.stderr)
                result = subprocess.run(['java', '-Xmx256m', '-ea', '-Djava.io.tmpdir=' + str(work), '-cp', str(work),
                                         'com.android.server.pm.' + test], capture_output=True, text=True, timeout=90)
                if mode == 'controlled':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('Android OOM unqualified', result.stdout)
                    disabled = subprocess.run(['java', '-Xmx256m', '-cp', str(work), 'com.android.server.pm.' + test],
                                              capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(disabled.returncode, 0)
                    self.assertIn('-ea', disabled.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, mode + ' defect was not caught')
                    self.assertIn('AssertionError', result.stderr, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
