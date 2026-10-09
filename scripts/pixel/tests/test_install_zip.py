# SPDX-License-Identifier: Apache-2.0
"""The checks that need no phone, on small SYNTHETIC install zips built in scratch.

Keys are generated for the test and thrown away. The zips copy the layout that
optimize-factory-image writes, with dummy firmware and dummy super splits. Nothing is
downloaded and no real kit is read.

Cases that build or verify vbmeta need external/avb/avbtool.py of the pinned tree. Name
that tree with ANDRIX_PIXEL_TREES (2026081300=TREE) or ANDRIX_GRAPHENEOS_ROOT.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from caiman import Refusal  # noqa: E402
import install_zip as iz  # noqa: E402
import official  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent / 'fixtures'
RECORD = json.loads((FIXTURES / 'adevtool/records/2026100600.json').read_text())
INFO = (FIXTURES / 'adevtool/2026100600/vendor-skels/google_devices/caiman/firmware/'
        'android-info.txt').read_bytes()
PINNED_SIGNERS = ROOT / 'scripts/proof/tests/fixtures/grapheneos_carry/allowed_signers'
TREES = dict(item.split('=', 1) for item in os.environ.get('ANDRIX_PIXEL_TREES', '').split(':')
             if '=' in item)
PINNED_TREE = TREES.get('2026081300') or os.environ.get('ANDRIX_GRAPHENEOS_ROOT')
AVBTOOL = Path(PINNED_TREE) / 'external/avb/avbtool.py' if PINNED_TREE else None
HAVE_AVBTOOL = bool(AVBTOOL and AVBTOOL.is_file() and shutil.which('openssl'))
HAVE_SSH = bool(shutil.which('ssh-keygen'))
RELEASE = '2026100600'
BL, BB = 'ripcurrentpro-17.0-15819938', 'g5400c-260604-260807-B-16035863'
OLD_BL, OLD_BB = 'ripcurrentpro-17.0-15199480', 'g5400c-260317-260429-B-15308590'
ROLLBACK = 1791158400   # 2026-10-05T00:00:00Z
FINGERPRINT = 'google/caiman/caiman:17/CP3A.261005.005/{}:user/release-keys'
STATIC = ('boot', 'init_boot', 'dtbo', 'vendor_kernel_boot', 'pvmfw', 'vendor_boot')
PLAN_GOOD_LINE = ('Good "factory images" signature for contact@grapheneos.org with ED25519 key '
                  'SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM')


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=300, **kwargs)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Kit:
    """One synthetic kit: keys, images, vbmeta and the zip members."""

    def __init__(self, work, avb):
        self.work = Path(work)
        self.avb = avb
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', self.work / 'ssh')
        kind, blob = (self.work / 'ssh.pub').read_text().split()[:2]
        self.signers = self.work / 'allowed_signers'
        self.signers.write_text(f'contact@grapheneos.org {kind} {blob}\n')
        self.fingerprint = run('ssh-keygen', '-l', '-f', self.work / 'ssh.pub').stdout.decode().split()[1]
        self.bases = self.work / 'bases'
        self.bases.mkdir()
        base = json.loads((ROOT / 'upstream/bases/2026100600.json').read_text())
        base['manifest']['allowed_signers_sha256'] = sha(self.signers.read_bytes())
        (self.bases / '2026100600.json').write_text(json.dumps(base))
        self.stable = self.stable_file('2026100600')
        legacy = official.render_legacy(RELEASE, BL, BB)
        self.members = {
            'flash-all.sh': official.capture(legacy, splits=2), 'flash-all.bat': b'synthetic\r\n',
            'script.txt': b'synthetic\n', 'android-info.txt': INFO, 'android-info.zip': b'synthetic',
            f'bootloader-caiman-{BL}.img': b'synthetic bootloader',
            f'radio-caiman-{BB.lower()}.img': b'synthetic radio',
            'super_1.img': b'synthetic super 1', 'super_2.img': b'synthetic super 2'}
        if avb:
            self.rsa = self.key('avb')
            run(sys.executable, '-B', AVBTOOL, 'extract_public_key', '--key', self.rsa, '--output',
                self.work / 'avb_pkmd.bin')
            self.members['avb_pkmd.bin'] = (self.work / 'avb_pkmd.bin').read_bytes()
            for name in STATIC:
                self.members[f'{name}.img'] = self.image(name)
            self.members['vbmeta.img'] = self.vbmeta()
        else:
            self.members['avb_pkmd.bin'] = b'synthetic avb key'
            for name in STATIC + ('vbmeta',):
                self.members[f'{name}.img'] = f'synthetic {name}'.encode()
        self.count = 0

    def key(self, name):
        path = self.work / f'{name}.pem'
        run('openssl', 'genrsa', '-out', path, '4096')
        return path

    def stable_file(self, release):
        path = self.work / f'stable-{release}'
        path.write_text(f'{release} 1791230000 caiman stable\n')
        return path

    def image(self, name, size=4096, kind='hash'):
        path = self.work / f'{name}.img'
        path.write_bytes(bytes([len(name)]) * size)
        props = (['--prop', f'com.android.build.boot.fingerprint:{FINGERPRINT.format(RELEASE)}']
                 if name == 'boot' else [])
        if kind == 'hash':
            run(sys.executable, '-B', AVBTOOL, 'add_hash_footer', '--image', path, '--partition_name',
                name, '--partition_size', 262144, *props)
        else:
            run(sys.executable, '-B', AVBTOOL, 'add_hashtree_footer', '--image', path,
                '--partition_name', name, '--partition_size', 1048576, '--do_not_generate_fec')
        return path.read_bytes()

    def vbmeta(self, key=None, algorithm='SHA256_RSA4096', rollback=ROLLBACK, flags=0, props=None,
               include=STATIC, extra=(), location=0):
        if props is None:
            props = [('com.android.build.system.fingerprint', FINGERPRINT.format(RELEASE)),
                     ('com.android.build.system.security_patch', '2026-10-05')]
        for name in include:
            (self.work / f'{name}.img').write_bytes(self.members.get(f'{name}.img') or
                                                    (self.work / f'{name}.img').read_bytes())
        args = ['make_vbmeta_image', '--output', self.work / 'vbmeta.img', '--rollback_index',
                rollback, '--flags', flags, '--rollback_index_location', location]
        if algorithm != 'NONE':
            args += ['--key', key or self.rsa, '--algorithm', algorithm]
        for prop, value in props:
            args += ['--prop', f'{prop}:{value}']
        for name in include:
            args += ['--include_descriptors_from_image', self.work / f'{name}.img']
        run(sys.executable, '-B', AVBTOOL, *args, *extra)
        return (self.work / 'vbmeta.img').read_bytes()

    def zip(self, release=RELEASE, name=None, prefix=None, sign=True, namespace='factory images',
            entries=(), **changes):
        self.count += 1
        folder = self.work / f'zip{self.count}'
        folder.mkdir()
        members = dict(self.members)
        for member, data in changes.items():
            member = member.replace('__', '.').replace('_dash_', '-')
            if data is None:
                members.pop(member, None)
            else:
                members[member] = data
        path = folder / (name or f'caiman-install-{release}.zip')
        prefix = prefix if prefix is not None else f'caiman-install-{release}/'
        with zipfile.ZipFile(path, 'w') as archive, warnings.catch_warnings():
            warnings.simplefilter('ignore')   # a duplicate entry is one of the controls
            for member, data in members.items():
                archive.writestr(prefix + member, data)
            for info, data in entries:
                archive.writestr(info, data)
        if sign:
            run('ssh-keygen', '-Y', 'sign', '-n', namespace, '-f', self.work / 'ssh', path)
        return path

    def check(self, path, **overrides):
        arguments = dict(signature=f'{path}.sig', signers=self.signers, release=RELEASE,
                         stable=self.stable, security_patch='2026-10-05', record=RECORD,
                         avbtool=AVBTOOL if self.avb else self.work / 'no-avbtool',
                         bases=self.bases, scratch=self.work)
        arguments.update(overrides)
        with mock.patch.object(iz, 'PKMD_SHA256', sha(self.members['avb_pkmd.bin'])), \
                mock.patch.object(iz, 'KEY_FINGERPRINT', self.fingerprint):
            return iz.check(path, **arguments)


class ConstantTests(unittest.TestCase):
    def test_values_from_the_plan(self):
        self.assertEqual(iz.PKMD_SHA256, 'f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86')
        self.assertEqual(iz.good_line(), PLAN_GOOD_LINE)
        self.assertEqual(iz.signature_command('allowed_signers', 'caiman-install-VERSION.zip.sig'),
                         ['ssh-keygen', '-Y', 'verify', '-f', 'allowed_signers', '-I',
                          'contact@grapheneos.org', '-n', 'factory images', '-s',
                          'caiman-install-VERSION.zip.sig'])

    def test_allowed_signers_digest_is_the_upstream_pin(self):
        self.assertEqual(iz.pinned_signers_digest(),
                         '344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0')
        self.assertEqual(iz.check_signers(PINNED_SIGNERS)['sha256'], iz.pinned_signers_digest())
        with tempfile.TemporaryDirectory() as work:
            changed = Path(work) / 'allowed_signers'
            changed.write_bytes(PINNED_SIGNERS.read_bytes() + b'\n')
            with self.assertRaises(Refusal):
                iz.check_signers(changed)
            bases = Path(work) / 'bases'
            bases.mkdir()
            for index, digest in enumerate(('a' * 64, 'b' * 64)):
                (bases / f'{index}.json').write_text(json.dumps({'manifest': {'allowed_signers_sha256': digest}}))
            with self.assertRaisesRegex(Refusal, '2 different'):
                iz.pinned_signers_digest(bases)

    def test_patch_timestamp(self):
        self.assertEqual(iz.patch_timestamp('2026-10-05'), ROLLBACK)
        for level in ('2026-10-5', '2026-13-01', '05-10-2026', '', None):
            with self.subTest(level=level), self.assertRaises(Refusal):
                iz.patch_timestamp(level)

    def test_malformed_vbmeta_is_refused(self):
        header = bytearray(256)
        header[0:4] = b'AVB0'
        for data in (b'', b'AVB0', bytes(256), bytes(header[:200]),
                     bytes(header[:12]) + (64).to_bytes(8, 'big') + bytes(header[20:])):
            with self.subTest(size=len(data)), self.assertRaises(Refusal):
                iz.parse_vbmeta(data)

    def test_descriptor_policy(self):
        good = [{'type': 'hash', 'partition': 'boot', 'digest_size': 32},
                {'type': 'hashtree', 'partition': 'system', 'digest_size': 20},
                {'type': 'property', 'key': 'k', 'value': 'v'}, {'type': 'kernel_cmdline'}]
        self.assertEqual(iz.images_to_verify({'descriptors': good}), ['boot', 'system'])
        cases = {
            'unknown tag': [{'type': 'unknown', 'tag': 9}],
            'chain': [{'type': 'chain', 'partition': 'vbmeta_system'}],
            'no digest': [{'type': 'hash', 'partition': 'boot', 'digest_size': 0}],
            'repeated': [good[0], good[0]],
            'path in name': [{'type': 'hash', 'partition': '../boot', 'digest_size': 32}],
            'vbmeta itself': [{'type': 'hash', 'partition': 'vbmeta', 'digest_size': 32}],
            'empty name': [{'type': 'hashtree', 'partition': '', 'digest_size': 32}],
        }
        for name, descriptors in cases.items():
            with self.subTest(name), self.assertRaises(Refusal):
                iz.images_to_verify({'descriptors': descriptors})

    @unittest.skipUnless(HAVE_AVBTOOL, 'needs external/avb/avbtool.py of the pinned tree')
    def test_avbtool_is_the_pinned_file(self):
        self.assertEqual(sha(AVBTOOL.read_bytes()), iz.AVBTOOL_SHA256)


@unittest.skipUnless(HAVE_SSH, 'needs ssh-keygen')
class ChecksWithoutVbmetaTests(unittest.TestCase):
    """Every check but vbmeta and the identity it carries. Runs without avbtool."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.kit = Kit(cls.tmp.name, avb=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def assert_only_failing(self, report, *names):
        failing = sorted(name for name, result in report['checks'].items() if not result['ok'])
        self.assertEqual(failing, sorted(set(names) | {'vbmeta', 'release_identity'}), report['reasons'])
        self.assertEqual(report['verdict'], 'REFUSE')

    def test_base_kit(self):
        self.assert_only_failing(self.kit.check(self.kit.zip()))

    def test_signature_controls(self):
        kit = self.kit
        good = kit.zip()
        tampered = kit.zip(sign=False, flash_dash_all__sh=kit.members['flash-all.sh'] + b'\n')
        shutil.copyfile(f'{good}.sig', f'{tampered}.sig')
        self.assert_only_failing(kit.check(tampered), 'signature', 'flash_script')
        self.assert_only_failing(kit.check(kit.zip(namespace='file')), 'signature')
        other = kit.work / 'other_signers'
        other.write_text(kit.signers.read_text().replace('contact@grapheneos.org', 'other@example.invalid'))
        other_bases = kit.work / 'other-bases'
        other_bases.mkdir(exist_ok=True)
        base = json.loads((kit.bases / '2026100600.json').read_text())
        base['manifest']['allowed_signers_sha256'] = sha(other.read_bytes())
        (other_bases / '2026100600.json').write_text(json.dumps(base))
        report = kit.check(good, signers=other, bases=other_bases)
        self.assertFalse(report['checks']['signature']['ok'])
        with mock.patch.object(iz, 'KEY_FINGERPRINT', 'SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM'):
            self.assertFalse(iz.check(good, signature=f'{good}.sig', signers=kit.signers, release=RELEASE,
                                      stable=kit.stable, security_patch='2026-10-05', record=RECORD,
                                      avbtool=kit.work / 'none', bases=kit.bases)['checks']['signature']['ok'])
        missing = kit.zip(sign=False)
        self.assert_only_failing(kit.check(missing), 'signature')

    def test_allowed_signers_must_be_the_pinned_file(self):
        self.assert_only_failing(self.kit.check(self.kit.zip(), bases=ROOT / 'upstream/bases'),
                                 'allowed_signers')

    def test_layout_controls(self):
        kit = self.kit
        symlink = zipfile.ZipInfo(f'caiman-install-{RELEASE}/link')
        symlink.external_attr = 0o120777 << 16
        cases = [
            kit.zip(name=f'caiman-install-2026100200.zip'),
            kit.zip(prefix='other/'),
            kit.zip(entries=[(f'caiman-install-{RELEASE}/../escape', b'x')]),
            kit.zip(entries=[(f'caiman-install-{RELEASE}/nested/file', b'x')]),
            kit.zip(entries=[(symlink, b'target')]),
            kit.zip(entries=[(f'caiman-install-{RELEASE}/script.txt', b'again')]),
        ]
        for path in cases:
            with self.subTest(path=path.name):
                report = kit.check(path)
                self.assertFalse(report['checks']['zip_layout']['ok'])
                self.assertEqual(report['verdict'], 'REFUSE')

    def test_more_layout_controls(self):
        kit = self.kit
        garbage = kit.work / 'garbage' / f'caiman-install-{RELEASE}.zip'
        garbage.parent.mkdir()
        garbage.write_bytes(b'not a zip at all')
        report = kit.check(garbage)
        self.assertIn('not a readable zip', report['checks']['zip_layout']['reason'])
        path = kit.zip(sign=False)
        data = bytearray(path.read_bytes())
        central = data.rfind(b'PK\x01\x02')   # the last central directory entry
        data[central + 8] |= 0x01                 # its general purpose flag: encrypted
        path.write_bytes(bytes(data))
        run('ssh-keygen', '-Y', 'sign', '-n', 'factory images', '-f', kit.work / 'ssh', path)
        self.assertIn('is encrypted', kit.check(path)['checks']['zip_layout']['reason'])
        with mock.patch.object(iz, 'SMALL', 64):
            report = kit.check(kit.zip())
        self.assertIn('is larger than 64 bytes', report['checks']['android_info']['reason'])

    def test_patch_level_comes_from_the_base_record(self):
        kit = self.kit
        report = kit.check(kit.zip(), security_patch='2026-09-05')
        self.assertEqual(report['checks'], {})
        self.assertIn('not the 2026-10-05 of upstream/bases/2026100600.json', report['reasons'][0])
        report = kit.check(kit.zip(), security_patch=None)
        self.assertEqual(report['checks']['inputs']['detail']['security_patch'], '2026-10-05')
        self.assertEqual(len(report['sha256']), 64)

    def test_avb_pkmd_must_have_the_published_digest(self):
        kit = self.kit
        report = iz.check(kit.zip(), signature=f'{kit.zip()}.sig', signers=kit.signers, release=RELEASE,
                          stable=kit.stable, security_patch='2026-10-05', record=RECORD,
                          avbtool=kit.work / 'none', bases=kit.bases)
        self.assertIn('not f729cab8', report['checks']['avb_pkmd']['reason'])

    def test_android_info_controls(self):
        kit = self.kit
        for text in (INFO.replace(b'16035863', b'15308590'), INFO.replace(b'board=caiman', b'board=komodo'),
                     INFO.replace(b'ripcurrentpro-17.0-15819938', b'ripcurrentpro-17.0-15199480'),
                     INFO + b'require partition-exists=vendor_dlkm\n'):
            with self.subTest(text=text):
                self.assert_only_failing(kit.check(kit.zip(android_dash_info__txt=text)), 'android_info')
        # the optimized script reads android-info.zip, so only the android-info check fails
        self.assert_only_failing(kit.check(kit.zip(android_dash_info__txt=None)), 'android_info')

    def test_flash_script_controls(self):
        kit = self.kit
        script = kit.members['flash-all.sh']
        locked = script.replace(b'fastboot erase dpm_b\n', b'fastboot erase dpm_b\nfastboot flashing lock\n')
        self.assert_only_failing(kit.check(kit.zip(flash_dash_all__sh=locked)), 'flash_script')
        self.assert_only_failing(kit.check(kit.zip(super_2__img=None)), 'flash_script')
        older = kit.zip(**{f'bootloader-caiman-{BL}.img'.replace('.', '__').replace('-', '_dash_'): None})
        self.assert_only_failing(kit.check(older), 'flash_script')

    def test_inputs_are_checked_first(self):
        kit = self.kit
        other = json.loads(json.dumps(RECORD))
        other['release'] = '2026081300'
        for overrides in ({'record': other}, {'release': '2026100602'},
                          {'stable': kit.work / 'missing'}, {'record': {'schema': 'x'}}):
            with self.subTest(overrides=list(overrides)):
                report = kit.check(kit.zip(), **overrides)
                self.assertEqual((report['verdict'], report['checks']), ('REFUSE', {}))


@unittest.skipUnless(HAVE_AVBTOOL and HAVE_SSH, 'needs ssh-keygen, openssl and the pinned avbtool.py')
class FullKitTests(unittest.TestCase):
    """The complete checks with real signatures made by the pinned avbtool."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.kit = Kit(cls.tmp.name, avb=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def refused(self, path, check, pattern=None, **overrides):
        report = self.kit.check(path, **overrides)
        self.assertEqual(report['verdict'], 'REFUSE')
        self.assertFalse(report['checks'][check]['ok'], report['checks'][check])
        if pattern:
            self.assertRegex(report['checks'][check]['reason'], pattern)
        return report

    def test_synthetic_kit_passes(self):
        report = self.kit.check(self.kit.zip())
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        identity = report['checks']['release_identity']['detail']
        self.assertEqual((identity['build_number'], identity['stock_build']), (RELEASE, 'CP3A.261005.005'))
        self.assertEqual(sorted(report['checks']['vbmeta']['detail']['verified_images']), sorted(STATIC))
        self.assertEqual(report['checks']['flash_script']['detail']['super_splits'], 2)
        self.assertEqual(report['checks']['signature']['detail']['output'],
                         iz.good_line().replace(iz.KEY_FINGERPRINT, self.kit.fingerprint))

    def test_vbmeta_controls(self):
        kit = self.kit
        other = kit.key('other')
        cases = [
            ('unsigned', {'algorithm': 'NONE'}, 'NONE, not SHA256_RSA4096'),
            ('other key', {'key': other}, 'not byte identical to avb_pkmd.bin'),
            ('rollback', {'rollback': 0}, 'rollback index is 0'),
            ('flags', {'flags': 1}, 'flags 1'),
            ('patch level', {'props': [('com.android.build.system.fingerprint', FINGERPRINT.format(RELEASE)),
                                       ('com.android.build.system.security_patch', '2026-09-05')]},
             'security patch'),
            ('chain', {'extra': ('--chain_partition', f'vbmeta_system:1:{kit.work / "avb_pkmd.bin"}')},
             'chains to vbmeta_system'),
        ]
        for name, arguments, pattern in cases:
            with self.subTest(name):
                self.refused(kit.zip(vbmeta__img=kit.vbmeta(**arguments)), 'vbmeta', pattern)

    def test_kernel_command_line_descriptor_is_reported(self):
        vbmeta = self.kit.vbmeta(extra=('--kernel_cmdline', 'synthetic=1'))
        report = self.kit.check(self.kit.zip(vbmeta__img=vbmeta))
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['vbmeta']['detail']['kernel_cmdline_descriptors'], 1)

    def fake_tools(self, system, b_copy=b'', extra=None, fail=False):
        """Synthetic stand-ins for simg2img and lpunpack; neither real tool is built yet."""
        directory = Path(tempfile.mkdtemp(dir=self.kit.work))
        prepared = directory / 'system-prepared.img'
        prepared.write_bytes(system)
        simg2img = directory / 'simg2img'
        simg2img.write_text('#!/usr/bin/env python3\nimport sys\n' + ('sys.exit(3)\n' if fail else '') +
                            "open(sys.argv[-1], 'wb').write(b''.join(open(p, 'rb').read() for p in sys.argv[1:-1]))\n")
        lpunpack = directory / 'lpunpack'
        lpunpack.write_text('#!/usr/bin/env python3\nimport pathlib, shutil, sys\nout = pathlib.Path(sys.argv[2])\n'
                            f'shutil.copyfile({str(prepared)!r}, out / "system_a.img")\n'
                            f'(out / "system_b.img").write_bytes({b_copy!r})\n'
                            + (f'(out / {extra!r}).write_bytes(b"x")\n' if extra else ''))
        for tool in (simg2img, lpunpack):
            tool.chmod(0o755)
        return {'simg2img': str(simg2img), 'lpunpack': str(lpunpack)}

    def pinned(self, tools):
        return (mock.patch.object(iz, 'SIMG2IMG_SHA256', sha(Path(tools['simg2img']).read_bytes())),
                mock.patch.object(iz, 'LPUNPACK_SHA256', sha(Path(tools['lpunpack']).read_bytes())))

    def test_descriptor_without_its_image_is_refused(self):
        kit = self.kit
        system = kit.image('system', size=16384, kind='hashtree')
        vbmeta = kit.vbmeta(include=STATIC + ('system',))
        self.refused(kit.zip(vbmeta__img=vbmeta), 'vbmeta', 'needs the pinned simg2img')
        self.refused(kit.zip(vbmeta__img=vbmeta), 'vbmeta', 'simg2img is not built and pinned yet',
                     tools=self.fake_tools(system))
        self.assertEqual(kit.check(kit.zip(vbmeta__img=vbmeta, system__img=system))['verdict'], 'PASS')

    def test_dynamic_images_are_rebuilt_from_the_super_splits(self):
        kit = self.kit
        system = kit.image('system', size=16384, kind='hashtree')
        vbmeta = kit.vbmeta(include=STATIC + ('system',))
        path = kit.zip(vbmeta__img=vbmeta)
        tools = self.fake_tools(system)
        first, second = self.pinned(tools)
        with first, second:
            report = kit.check(path, tools=tools)
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['vbmeta']['detail']['rebuilt_from_super'], ['system'])
        cases = [('full b copy', self.fake_tools(system, b_copy=b'data'), 'is not empty'),
                 ('other file', self.fake_tools(system, extra='notes.txt'), 'not a slot image'),
                 ('undescribed partition', self.fake_tools(system, extra='product_a.img'),
                  'holds product, which vbmeta does not describe'),
                 ('failing simg2img', self.fake_tools(system, fail=True), 'simg2img exited 3')]
        for name, tools, pattern in cases:
            with self.subTest(name):
                first, second = self.pinned(tools)
                with first, second:
                    self.refused(path, 'vbmeta', pattern, tools=tools)
        tools = self.fake_tools(system)
        first, _ = self.pinned(tools)
        with first, mock.patch.object(iz, 'LPUNPACK_SHA256', '0' * 64):
            self.refused(path, 'vbmeta', 'is not the pinned lpunpack', tools=tools)
        changed = system[:100] + bytes([system[100] ^ 1]) + system[101:]   # a data byte
        tools = self.fake_tools(changed)
        first, second = self.pinned(tools)
        with first, second:
            self.refused(path, 'vbmeta', 'avbtool verify_image exited 1', tools=tools)

    def test_rollback_location_and_image_size(self):
        self.refused(self.kit.zip(vbmeta__img=self.kit.vbmeta(location=1)), 'vbmeta',
                     'rollback index location 1')
        with mock.patch.object(iz, 'IMAGE', 1000):
            self.refused(self.kit.zip(), 'vbmeta', 'is larger than 1000 bytes')

    def andrix_zip(self, props=None, name='2026100600-andrix1', extra=None):
        kit = self.kit
        if props is None:
            props = [('com.android.build.system.fingerprint',
                      'google/caiman/caiman:17/CP3A.261005.005/andrix1:userdebug/release-keys'),
                     ('com.android.build.system.security_patch', '2026-10-05'),
                     ('com.andrix.build.base_tag', '2026100600')]
        vbmeta = kit.vbmeta(props=props, include=tuple(item for item in STATIC if item != 'boot'))
        changes = {'vbmeta.img': vbmeta, **(extra or {})}
        return kit.zip(release=name, sign=False, **{member.replace('-', '_dash_').replace('.', '__'): data
                                                  for member, data in changes.items()})

    def andrix_check(self, path, **overrides):
        """andrix_image with this kit's key as the workshop key and this kit as the official one."""
        import version_criterion as vc
        kit = self.kit
        official = overrides.pop('official', None) or kit.zip()
        details = {'records': {'2026100600': RECORD}, 'signers': kit.signers, 'stable': kit.stable,
                   'avbtool': AVBTOOL, 'official': official}
        details.update(overrides.pop('details', {}))
        key = overrides.pop('workshop', sha(kit.members['avb_pkmd.bin']))
        table = vc.load_table([RECORD], require_tree_head=False)
        with mock.patch.object(iz, 'PKMD_SHA256', sha(kit.members['avb_pkmd.bin'])), \
                mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint), \
                mock.patch.object(iz, 'BASES', kit.bases), \
                mock.patch.object(iz, 'WORKSHOP_PKMD_SHA256', key):
            return vc.andrix_image(path, details, table)

    def test_andrix_identity_is_cross_checked(self):
        kit = self.kit
        path = self.andrix_zip()
        identity = self.andrix_check(path)
        self.assertEqual((identity.kind, identity.release.number, identity.stock_build),
                         ('andrix', '2026100600', 'CP3A.261005.005'))
        self.assertEqual(identity.sha256, sha(path.read_bytes()))
        fingerprint = ('com.android.build.system.fingerprint',
                       'google/caiman/caiman:17/CP3A.261005.005/andrix1:userdebug/release-keys')
        patch = ('com.android.build.system.security_patch', '2026-10-05')
        tag = ('com.andrix.build.base_tag', '2026100600')
        for name, props, pattern in (
                ('no base tag', [fingerprint, patch], 'no single signed com.andrix.build.base_tag'),
                ('preview base tag', [fingerprint, patch, (tag[0], '2026100601')], 'security preview'),
                ('test keys', [(fingerprint[0], fingerprint[1].replace('release-keys', 'test-keys')), patch, tag],
                 'not one caiman release-keys'),
                ('other stock build', [(fingerprint[0], fingerprint[1].replace('CP3A.261005.005', 'CP3A.260905.009')),
                                       patch, tag], 'not the CP3A.261005.005 recorded')):
            with self.subTest(name), self.assertRaisesRegex(Refusal, pattern):
                self.andrix_check(self.andrix_zip(props, name=f'2026100600-{name.replace(" ", "-")}'))
        with self.assertRaisesRegex(Refusal, 'workshop key for this phone is not recorded'):
            self.andrix_check(path, workshop=None)
        with self.assertRaisesRegex(Refusal, 'not signed with the workshop key'):
            self.andrix_check(path, workshop='0' * 64)
        with self.assertRaisesRegex(Refusal, 'needs the official GrapheneOS kit'):
            self.andrix_check(path, details={'official': None})
        other = self.andrix_zip(name='2026100600-otherfirmware',
                                extra={f'bootloader-caiman-{BL}.img': b'other bootloader bytes'})
        with self.assertRaisesRegex(Refusal, 'not byte identical to the official kit'):
            self.andrix_check(other)

    def test_andrix_zip_with_other_firmware_is_refused(self):
        # the review's probe: base tag 2026100600 claimed, August firmware carried
        legacy = official.render_legacy(RELEASE, OLD_BL, OLD_BB)
        members = {'android-info.txt': official.android_info(OLD_BL, OLD_BB).encode(),
                   'flash-all.sh': official.capture(legacy, splits=2),
                   f'bootloader-caiman-{OLD_BL}.img': b'august bootloader',
                   f'radio-caiman-{OLD_BB.lower()}.img': b'august radio',
                   f'bootloader-caiman-{BL}.img': None, f'radio-caiman-{BB.lower()}.img': None}
        path = self.andrix_zip(name='2026100600-august', extra=members)
        with self.assertRaisesRegex(Refusal, 'is not the .* recorded for 2026100600'):
            self.andrix_check(path)

    def test_grapheneos_identity_for_the_criterion(self):
        import version_criterion as vc
        kit = self.kit
        path = kit.zip()
        details = {'records': {'2026100600': RECORD}, 'signers': kit.signers, 'stable': kit.stable,
                   'avbtool': AVBTOOL}
        with mock.patch.object(iz, 'PKMD_SHA256', sha(kit.members['avb_pkmd.bin'])), \
                mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint), \
                mock.patch.object(iz, 'BASES', kit.bases):
            identity = vc.grapheneos_image(path, details)
            self.assertEqual((identity.release.number, identity.stock_build, identity.sha256),
                             ('2026100600', 'CP3A.261005.005', sha(path.read_bytes())))
            locked = kit.zip(flash_dash_all__sh=kit.members['flash-all.sh'] + b'fastboot flashing lock\n')
            with self.assertRaisesRegex(Refusal, 'does not pass the checks that need no phone'):
                vc.grapheneos_image(locked, details)

    def test_changed_image_fails_avbtool(self):
        kit = self.kit
        boot = bytearray(kit.members['boot.img'])
        boot[100] ^= 0xff
        self.refused(kit.zip(boot__img=bytes(boot)), 'vbmeta', 'avbtool verify_image exited 1')

    def test_unpinned_avbtool_is_refused(self):
        copy = self.kit.work / 'avbtool-copy.py'
        copy.write_bytes(AVBTOOL.read_bytes() + b'\n')
        self.refused(self.kit.zip(), 'vbmeta', 'not external/avb/avbtool.py of the pinned tree', avbtool=copy)

    def test_release_identity_controls(self):
        kit = self.kit
        system = 'com.android.build.system.fingerprint'
        patch = ('com.android.build.system.security_patch', '2026-10-05')
        no_boot = tuple(name for name in STATIC if name != 'boot')   # boot.img carries its own
        cases = [
            ('older build', [(system, FINGERPRINT.format('2026100200')), patch], no_boot,
             'is 2026100200, not'),
            ('other device', [(system, 'google/komodo/komodo:17/CP3A.261005.005/2026100600:user/release-keys'),
                              patch], no_boot, 'not a caiman user release-keys'),
            ('userdebug', [(system, FINGERPRINT.format(RELEASE).replace(':user/', ':userdebug/')), patch],
             no_boot, 'not a caiman user release-keys'),
            ('test keys', [(system, FINGERPRINT.format(RELEASE).replace('release-keys', 'test-keys')), patch],
             no_boot, 'not a caiman user release-keys'),
            ('other stock build', [(system, FINGERPRINT.format(RELEASE).replace('CP3A.261005.005',
                                                                                'CP3A.260905.009')), patch],
             no_boot, 'adevtool records CP3A.261005.005'),
            ('fingerprints disagree', [(system, FINGERPRINT.format('2026100200')), patch], STATIC,
             'fingerprints inside the zip disagree'),
            ('no system fingerprint', [patch], STATIC, 'no com.android.build.system.fingerprint'),
        ]
        for name, props, include, pattern in cases:
            with self.subTest(name):
                self.refused(kit.zip(vbmeta__img=kit.vbmeta(props=props, include=include)),
                             'release_identity', pattern)
        self.refused(kit.zip(), 'release_identity', 'older than the zip release',
                     stable=kit.stable_file('2026100200'))

    def test_security_preview_kit(self):
        kit = self.kit
        props = [('com.android.build.system.fingerprint', FINGERPRINT.format('2026100601')),
                 ('com.android.build.system.security_patch', '2026-10-05')]
        # boot.img carries a 2026100600 fingerprint, so its descriptor stays out of this vbmeta
        vbmeta = kit.vbmeta(props=props, include=tuple(name for name in STATIC if name != 'boot'))
        path = kit.zip(release='2026100601', vbmeta__img=vbmeta)
        report = kit.check(path, release='2026100601')
        self.assertEqual(report['verdict'], 'PASS', report['reasons'])
        self.assertEqual(report['checks']['release_identity']['detail']['build_number'], '2026100601')


@unittest.skipUnless(HAVE_SSH, 'needs ssh-keygen')
class CommandLineTests(unittest.TestCase):
    def test_exit_code_and_report(self):
        with tempfile.TemporaryDirectory() as work:
            kit = Kit(work, avb=False)
            path = kit.zip()
            record = Path(work) / 'record.json'
            record.write_text(json.dumps(RECORD))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), \
                    mock.patch.object(iz, 'KEY_FINGERPRINT', kit.fingerprint), \
                    mock.patch.object(iz, 'BASES', kit.bases):
                status = iz.main(['--zip', str(path), '--allowed-signers', str(kit.signers),
                                  '--release', RELEASE, '--stable', str(kit.stable),
                                  '--security-patch', '2026-10-05', '--record', str(record),
                                  '--avbtool', str(Path(work) / 'none')])
            report = json.loads(output.getvalue())
            self.assertEqual((status, report['verdict']), (1, 'REFUSE'))
            self.assertTrue(report['checks']['signature']['ok'])


if __name__ == '__main__':
    unittest.main()
