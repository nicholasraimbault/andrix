#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The checks that need no phone, for a GrapheneOS caiman install zip.

"The way back" in plans/2026-10-09-caiman-workshop-phone.md lists them: the zip's SSH
signature through the pinned allowed signers, the release identity from the build number
inside the zip, the avb_pkmd.bin digest GrapheneOS publishes for the Pixel 9 Pro, the
android-info.txt requirements, the flash script, and avbtool verify_image on vbmeta with
an embedded key byte identical to avb_pkmd.bin. Every check runs and reports; the zip
passes only if all of them pass. The tool reads the zip and runs ssh-keygen and the
pinned avbtool.py. It contacts nothing.

The build number is read from the fingerprints in vbmeta's signed property descriptors.
avbtool verify_image needs every image that a vbmeta descriptor names beside vbmeta.img.
An install zip written by optimize-factory-image carries the dynamic partitions only
inside super splits, so for such a zip this check refuses and names the missing images.
"""
import argparse
import calendar
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adevtool_record  # noqa: E402
import caiman  # noqa: E402
from caiman import Refusal, refuse  # noqa: E402
import flash_script  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BASES = ROOT / 'upstream' / 'bases'
SIGNER = 'contact@grapheneos.org'
NAMESPACE = 'factory images'
KEY_FINGERPRINT = 'SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM'
# GrapheneOS's published avb_pkmd.bin SHA-256 for the Pixel 9 Pro
PKMD_SHA256 = 'f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86'
# external/avb/avbtool.py in the pinned tree, GrapheneOS 2026081300
AVBTOOL_SHA256 = '1aa6f2b462aa67aa3fdf488bee83ab517de8ad9d8228c7b45c35267ab2cf6781'
# simg2img and lpunpack built from the pinned tree. Neither is built yet, so the rebuild of the
# dynamic partitions refuses until their SHA-256 values are recorded here.
SIMG2IMG_SHA256 = None
LPUNPACK_SHA256 = None
# The workshop key set's avb_pkmd.bin for this phone (decision 2). It is not generated yet, so
# every Andrix zip is refused until its SHA-256 is recorded here.
WORKSHOP_PKMD_SHA256 = None
SHA256_RSA4096 = 2
SMALL = 1 << 20
IMAGE = 512 << 20
COMMAND_TIMEOUT = 1800

_FINGERPRINT_KEY = re.compile(r'com\.android\.build\.([a-z0-9_]+)\.fingerprint')
_FINGERPRINT = re.compile(r'([^/\s]+)/([^/\s]+)/([^/:\s]+):([^/\s]+)/(' + caiman.BUILD_ID.pattern
                          + r')/([0-9]{10}):([a-z]+)/([a-z-]+)')
_PARTITION = re.compile(r'[a-z0-9_]{1,64}')
# an Andrix build number need not be a release number, so only its form is checked
_ANDRIX_FINGERPRINT = re.compile(r'[^/\s]+/[^/\s]+/([^/:\s]+):[^/\s]+/(' + caiman.BUILD_ID.pattern
                                 + r')/[A-Za-z0-9._-]+:(user|userdebug)/([a-z-]+)')
ALGORITHMS = {0: 'NONE', 1: 'SHA256_RSA2048', 2: 'SHA256_RSA4096', 3: 'SHA256_RSA8192',
              4: 'SHA512_RSA2048', 5: 'SHA512_RSA4096', 6: 'SHA512_RSA8192', 7: 'MLDSA65',
              8: 'MLDSA87'}


def good_line():
    return f'Good "{NAMESPACE}" signature for {SIGNER} with ED25519 key {KEY_FINGERPRINT}'


def pinned_signers_digest(bases=None):
    """The allowed signers digest that every upstream base record pins."""
    digests = set()
    for path in sorted(Path(bases or BASES).glob('*.json')):
        record = json.loads(path.read_text(encoding='utf-8'))
        digest = (record.get('manifest') or {}).get('allowed_signers_sha256')
        if not isinstance(digest, str) or caiman.SHA256.fullmatch(digest) is None:
            refuse(f'{path.name} pins no allowed signers digest')
        digests.add(digest)
    if len(digests) != 1:
        refuse(f'the upstream base records pin {len(digests)} different allowed signers digests')
    return digests.pop()


def _environment():
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C',
                   'TMPDIR': tempfile.gettempdir()}
    if 'HOME' in os.environ:
        environment['HOME'] = os.environ['HOME']
    return environment


def signature_command(signers, signature):
    return ['ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', SIGNER, '-n', NAMESPACE,
            '-s', str(signature)]


def check_signature(zip_path, signature, signers):
    command = signature_command(signers, signature)
    with open(zip_path, 'rb') as stdin:
        process = subprocess.run(command, stdin=stdin, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=_environment(), timeout=COMMAND_TIMEOUT)
    output = process.stdout.decode('utf-8', 'replace')
    if process.returncode != 0 or output != good_line() + '\n':
        refuse(f'ssh-keygen exited {process.returncode} and printed {output.strip()!r}; '
               f'expected {good_line()!r}; stderr {process.stderr.decode("utf-8", "replace").strip()!r}')
    return {'command': shlex.join(command) + ' < ' + shlex.quote(str(zip_path)),
            'output': output.strip()}


def check_signers(signers, bases=None):
    digest = caiman.sha256(Path(signers).read_bytes())
    pinned = pinned_signers_digest(bases)
    if digest != pinned:
        refuse(f'allowed_signers hashes to {digest}, not the pinned {pinned}')
    return {'sha256': digest}


class Archive:
    """The members of one install zip, all directly under the directory its name gives."""

    def __init__(self, path, release=None):
        self.path = Path(path)
        if release is None:   # an Andrix zip: optimize-factory-image names the directory alike
            if re.fullmatch(r'caiman-install-[A-Za-z0-9._-]+\.zip', self.path.name) is None:
                refuse(f'{self.path.name} is not named caiman-install-BUILD.zip')
            release = self.path.name[len('caiman-install-'):-len('.zip')]
        self.prefix = f'{caiman.DEVICE}-install-{release}/'
        if self.path.name != f'{caiman.DEVICE}-install-{release}.zip':
            refuse(f'{self.path.name} is not named {caiman.DEVICE}-install-{release}.zip')
        try:
            self.zip = zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError) as error:
            refuse(f'{self.path.name} is not a readable zip: {error}')
        self.members = {}
        for info in self.zip.infolist():
            name = info.filename
            if name == self.prefix and info.is_dir():
                continue
            parts = PurePosixPath(name).parts
            if (not name.startswith(self.prefix) or '\\' in name or len(parts) != 2
                    or any(part in ('', '.', '..') for part in parts) or info.is_dir()):
                refuse(f'zip entry {name!r} is not a file directly under {self.prefix}')
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                refuse(f'zip entry {name!r} is a symbolic link')
            if info.flag_bits & 0x1:
                refuse(f'zip entry {name!r} is encrypted')
            base = parts[1]
            if base in self.members:
                refuse(f'zip entry {base!r} appears twice')
            self.members[base] = info

    def read(self, name, limit=None):
        limit = SMALL if limit is None else limit
        info = self.members.get(name)
        if info is None:
            refuse(f'the zip has no {name}')
        if info.file_size > limit:
            refuse(f'{name} is larger than {limit} bytes')
        with self.zip.open(info) as handle:
            data = handle.read(limit + 1)
        if len(data) != info.file_size:
            refuse(f'{name} does not have its recorded size')
        return data

    def extract(self, name, directory, limit=None):
        target = Path(directory) / name
        target.write_bytes(self.read(name, IMAGE if limit is None else limit))
        return target


def parse_vbmeta(data):
    """The fields of a vbmeta image these checks use. Bounds are checked, nothing assumed."""
    header = '!4s2L2QL2Q2Q2Q2Q2QQLL47sx80x'
    if len(data) < 256:
        refuse('vbmeta.img is shorter than its header')
    (magic, _, _, auth_size, aux_size, algorithm, hash_offset, hash_size, signature_offset,
     signature_size, key_offset, key_size, _, _, descriptors_offset, descriptors_size,
     rollback_index, flags, rollback_location, _) = struct.unpack(header, data[:256])
    if magic != b'AVB0':
        refuse('vbmeta.img does not start with AVB0')
    if auth_size % 64 or aux_size % 64 or 256 + auth_size + aux_size > len(data):
        refuse('vbmeta.img block sizes are malformed')
    for offset, size, block in ((hash_offset, hash_size, auth_size),
                                (signature_offset, signature_size, auth_size),
                                (key_offset, key_size, aux_size),
                                (descriptors_offset, descriptors_size, aux_size)):
        if offset + size > block:
            refuse('vbmeta.img points outside its blocks')
    aux = data[256 + auth_size:256 + auth_size + aux_size]
    blob = aux[descriptors_offset:descriptors_offset + descriptors_size]
    descriptors = []
    position = 0
    while position < len(blob):
        if position + 16 > len(blob):
            refuse('a vbmeta descriptor header is cut short')
        tag, following = struct.unpack('!QQ', blob[position:position + 16])
        if following % 8 or position + 16 + following > len(blob):
            refuse('a vbmeta descriptor is malformed')
        descriptors.append(_descriptor(tag, blob[position:position + 16 + following]))
        position += 16 + following
    return {'algorithm': algorithm, 'algorithm_name': ALGORITHMS.get(algorithm, str(algorithm)),
            'rollback_index': rollback_index, 'flags': flags,
            'rollback_index_location': rollback_location,
            'public_key': aux[key_offset:key_offset + key_size], 'descriptors': descriptors}


def _named(raw, fixed, layout, kind):
    if len(raw) < fixed:
        refuse(f'a vbmeta {kind} descriptor is cut short')
    values = struct.unpack(layout, raw[:fixed])
    return values


def _descriptor(tag, raw):
    if tag == 0:
        _, _, key_size, value_size = _named(raw, 32, '!QQQQ', 'property')
        if 32 + key_size + 1 + value_size + 1 > len(raw):
            refuse('a vbmeta property descriptor is malformed')
        key = raw[32:32 + key_size].decode('utf-8', 'replace')
        value = raw[33 + key_size:33 + key_size + value_size]
        return {'type': 'property', 'key': key, 'value': value.decode('utf-8', 'replace')}
    if tag in (1, 2):
        if tag == 1:
            fields = _named(raw, 180, '!QQLQQQLLLQQ32sLLLL60s', 'hashtree')
            name_size, salt_size, digest_size = fields[12], fields[13], fields[14]
            fixed, kind = 180, 'hashtree'
        else:
            fields = _named(raw, 132, '!QQQ32sLLLL60s', 'hash')
            name_size, salt_size, digest_size = fields[4], fields[5], fields[6]
            fixed, kind = 132, 'hash'
        if fixed + name_size + salt_size + digest_size > len(raw):
            refuse(f'a vbmeta {kind} descriptor is malformed')
        name = raw[fixed:fixed + name_size].decode('utf-8', 'replace')
        return {'type': kind, 'partition': name, 'digest_size': digest_size}
    if tag == 3:
        _named(raw, 24, '!QQLL', 'kernel command line')
        return {'type': 'kernel_cmdline'}
    if tag == 4:
        fields = _named(raw, 92, '!QQLLLL60s', 'chain')
        name = raw[92:92 + fields[3]].decode('utf-8', 'replace')
        return {'type': 'chain', 'partition': name}
    return {'type': 'unknown', 'tag': tag}


def patch_timestamp(level):
    try:
        day = datetime.date.fromisoformat(level)
    except (TypeError, ValueError):
        refuse(f'security patch level {level!r} is not YYYY-MM-DD')
    if day.isoformat() != level:
        refuse(f'security patch level {level!r} is not YYYY-MM-DD')
    # the build sets the rollback index to the patch level's midnight in GMT, in seconds
    return calendar.timegm((day.year, day.month, day.day, 0, 0, 0))


def check_identity(vbmeta, release, stable, record_stock=None):
    fingerprints = {}
    for descriptor in vbmeta['descriptors']:
        if descriptor['type'] == 'property':
            match = _FINGERPRINT_KEY.fullmatch(descriptor['key'])
            if match:
                if match.group(1) in fingerprints:
                    refuse(f'vbmeta repeats the {match.group(1)} fingerprint')
                fingerprints[match.group(1)] = descriptor['value']
    if 'system' not in fingerprints:
        refuse('vbmeta carries no com.android.build.system.fingerprint, so no build number '
               'inside the zip names its release')
    numbers, builds = set(), set()
    for part, value in sorted(fingerprints.items()):
        match = _FINGERPRINT.fullmatch(value)
        if match is None:
            refuse(f'the {part} fingerprint {value!r} is not a build fingerprint')
        device, build_id, number, kind, tags = (match.group(3), match.group(5), match.group(6),
                                                match.group(7), match.group(8))
        if device != caiman.DEVICE or kind != 'user' or tags != 'release-keys':
            refuse(f'the {part} fingerprint {value!r} is not a {caiman.DEVICE} user release-keys build')
        numbers.add(number)
        builds.add(build_id)
    if len(numbers) != 1 or len(builds) != 1:
        refuse(f'the fingerprints inside the zip disagree: {sorted(fingerprints.values())}')
    inside = caiman.parse_release(numbers.pop(), what='build number inside the zip')
    if inside.number != release.number:
        refuse(f'the build number inside the zip is {inside}, not the expected {release}')
    stock = builds.pop()
    if record_stock is not None and stock != record_stock:
        refuse(f'the zip is built from stock build {stock}, but adevtool records {record_stock}')
    if caiman.newer(inside, stable):
        refuse(f'caiman-stable names {stable}, which is older than the zip release {inside}')
    return {'build_number': inside.number, 'stock_build': stock, 'stable': stable.number,
            'fingerprints': sorted(fingerprints)}


def images_to_verify(vbmeta):
    """The partitions whose images avbtool verify_image reads, after the descriptor policy."""
    images = []
    for descriptor in vbmeta['descriptors']:
        if descriptor['type'] == 'chain':
            refuse(f'vbmeta chains to {descriptor["partition"]}; caiman has a single vbmeta')
        if descriptor['type'] == 'unknown':
            refuse(f'vbmeta has a descriptor with unknown tag {descriptor["tag"]}')
        if descriptor['type'] in ('hash', 'hashtree'):
            name = descriptor['partition']
            if _PARTITION.fullmatch(name) is None or name in images or name == 'vbmeta':
                refuse(f'vbmeta names partition {name!r}, which is malformed or repeated')
            if descriptor['digest_size'] == 0:
                refuse(f'the {name} descriptor has no digest, so avbtool would not check it')
            images.append(name)
    return images


def _pinned_tool(tools, name, pinned):
    path = (tools or {}).get(name)
    if not path:
        refuse(f'rebuilding the dynamic partitions needs the pinned {name}')
    if pinned is None:
        refuse(f'{name} is not built and pinned yet, so the dynamic partitions cannot be rebuilt')
    if caiman.sha256(Path(path).read_bytes()) != pinned:
        refuse(f'{path} is not the pinned {name}')
    return str(path)


def rebuild_dynamic(archive, work, tools, described):
    """The dynamic partition images, rebuilt from the super splits with the pinned tools.

    simg2img merges every split into one image, because lpunpack refuses sparse input
    (lpunpack.cc). lpunpack writes NAME_a.img and NAME_b.img; each _a image is renamed to
    NAME.img beside vbmeta.img, and every _b image must be empty.
    """
    simg2img = _pinned_tool(tools, 'simg2img', SIMG2IMG_SHA256)
    lpunpack = _pinned_tool(tools, 'lpunpack', LPUNPACK_SHA256)
    numbers = sorted(int(m.group(1)) for m in (re.fullmatch(r'super_([1-9][0-9]{0,2})\.img', name)
                                               for name in archive.members) if m)
    if not numbers or numbers != list(range(1, len(numbers) + 1)):
        refuse(f'the zip does not hold one numbered run of super splits: {numbers}')
    splits = work / 'splits'
    splits.mkdir()
    paths = [str(archive.extract(f'super_{number}.img', splits)) for number in numbers]
    unpacked = work / 'unpacked'
    unpacked.mkdir()
    for command in ([simg2img, *paths, str(work / 'super.img')],
                    [lpunpack, str(work / 'super.img'), str(unpacked)]):
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=_environment(), timeout=COMMAND_TIMEOUT, cwd=work)
        if process.returncode != 0:
            refuse(f'{Path(command[0]).name} exited {process.returncode}: '
                   f'{process.stderr.decode("utf-8", "replace").strip()[-300:]!r}')
    rebuilt = set()
    for path in sorted(unpacked.iterdir()):
        match = re.fullmatch(r'([a-z0-9_]+)_(a|b)\.img', path.name)
        if match is None or path.is_symlink() or not path.is_file():
            refuse(f'lpunpack wrote {path.name}, which is not a slot image')
        if match.group(2) == 'b':
            if path.stat().st_size != 0:
                refuse(f'{path.name} is not empty; the install zip writes slot a only')
            continue
        name = match.group(1)
        if name not in described:
            refuse(f'the super image holds {name}, which vbmeta does not describe')
        if f'{name}.img' in archive.members or name == 'vbmeta':
            refuse(f'the super image holds {name}, which the zip also holds outside it')
        path.rename(work / f'{name}.img')
        rebuilt.add(name)
    shutil.rmtree(splits, ignore_errors=True)
    (work / 'super.img').unlink()
    return rebuilt


def check_vbmeta(archive, vbmeta_data, pkmd, security_patch, avbtool, scratch, tools=None):
    vbmeta = parse_vbmeta(vbmeta_data)
    if vbmeta['algorithm'] != SHA256_RSA4096:
        refuse(f'vbmeta is signed with {vbmeta["algorithm_name"]}, not SHA256_RSA4096')
    if vbmeta['public_key'] != pkmd:
        refuse('the public key embedded in vbmeta is not byte identical to avb_pkmd.bin')
    if vbmeta['flags'] != 0 or vbmeta['rollback_index_location'] != 0:
        refuse(f'vbmeta flags {vbmeta["flags"]} and rollback index location '
               f'{vbmeta["rollback_index_location"]} are not both 0')
    wanted = patch_timestamp(security_patch)
    if vbmeta['rollback_index'] != wanted:
        refuse(f'the rollback index is {vbmeta["rollback_index"]}, not {wanted}, the patch '
               f'timestamp of {security_patch}')
    levels = [d['value'] for d in vbmeta['descriptors']
              if d['type'] == 'property' and d['key'] == 'com.android.build.system.security_patch']
    if levels != [security_patch]:
        refuse(f'vbmeta records system security patch {levels}, not [{security_patch!r}]')
    images = images_to_verify(vbmeta)
    tool = Path(avbtool)
    if caiman.sha256(tool.read_bytes()) != AVBTOOL_SHA256:
        refuse(f'{tool} is not external/avb/avbtool.py of the pinned tree')
    work = Path(tempfile.mkdtemp(prefix='avb-', dir=scratch))
    try:
        missing = [name for name in images if f'{name}.img' not in archive.members]
        rebuilt = rebuild_dynamic(archive, work, tools, set(images)) if missing else set()
        absent = [name for name in missing if name not in rebuilt]
        if absent:
            refuse('vbmeta has descriptors for images neither the zip nor its super splits '
                   f'hold: {", ".join(absent)}')
        image = archive.extract('vbmeta.img', work, SMALL)
        for name in images:
            if name not in rebuilt:
                archive.extract(f'{name}.img', work)
        process = subprocess.run([sys.executable, '-B', str(tool), 'verify_image', '--image',
                                  str(image)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=_environment(), timeout=COMMAND_TIMEOUT, cwd=work)
        output = process.stdout.decode('utf-8', 'replace').split('\n')
        verified = {line.split(':', 1)[0] for line in output
                    if re.fullmatch(r'[a-z0-9_]+: Successfully verified .+', line)}
        expected = f'vbmeta: Successfully verified SHA256_RSA4096 vbmeta struct in {image}'
        if process.returncode != 0 or expected not in output or verified != {'vbmeta', *images}:
            refuse(f'avbtool verify_image exited {process.returncode}: '
                   f'{process.stderr.decode("utf-8", "replace").strip()[-400:]!r}')
        key = work / 'embedded_key.bin'
        process = subprocess.run([sys.executable, '-B', str(tool), 'info_image', '--image',
                                  str(image), '--output_pubkey', str(key)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=_environment(), timeout=COMMAND_TIMEOUT, cwd=work)
        if process.returncode != 0 or not key.is_file() or key.read_bytes() != pkmd:
            refuse("the key avbtool extracts from vbmeta is not byte identical to avb_pkmd.bin")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return vbmeta, {'algorithm': 'SHA256_RSA4096', 'rollback_index': wanted,
                    'verified_images': images, 'rebuilt_from_super': sorted(rebuilt),
                    'kernel_cmdline_descriptors': sum(d['type'] == 'kernel_cmdline'
                                                      for d in vbmeta['descriptors'])}


def patch_level(release, given=None, bases=None):
    """The release's security patch level, from its base record where one exists."""
    try:
        recorded = adevtool_record.base_record(release.base, bases)['security_patch_level']['value']
    except Refusal:
        recorded = None
    if recorded is not None and given is not None and recorded != given:
        refuse(f'the given patch level {given} is not the {recorded} of upstream/bases/{release.base}.json')
    level = recorded or given
    if level is None:
        refuse(f'no base record gives the patch level of {release.base}, and none was given')
    patch_timestamp(level)
    return level


def check(zip_path, *, signature, signers, release, stable, record, avbtool, security_patch=None,
          tools=None, scratch=None, bases=None):
    """Runs every check. Returns the report; the verdict is PASS only if all pass."""
    checks = {}

    def run(name, function):
        try:
            checks[name] = {'ok': True, 'detail': function()}
        except Refusal as error:
            checks[name] = {'ok': False, 'reason': str(error)}
        except Exception as error:  # anything unexpected is a refusal, never a pass
            checks[name] = {'ok': False, 'reason': f'{type(error).__name__}: {error}'}
        return checks[name]['ok']

    state = {}
    try:
        state['release'] = caiman.parse_release(release, what='expected release')
        state['stable'] = caiman.parse_stable_channel(Path(stable).read_bytes())
        _, state['stock'], _, state['info'] = adevtool_record.validate_record(record, bases=bases)
        if caiman.parse_release(record['release']).number != state['release'].base:
            refuse(f'the adevtool record is for {record["release"]}, not {state["release"].base}')
        security_patch = patch_level(state['release'], security_patch, bases)
        state['sha256'] = file_sha256(zip_path)
    except (Refusal, OSError) as error:
        return {'verdict': 'REFUSE', 'reasons': [str(error)], 'checks': {}}
    checks['inputs'] = {'ok': True, 'detail': {'zip': Path(zip_path).name,
                                               'sha256': state['sha256'],
                                               'release': state['release'].number,
                                               'stable': state['stable'].number,
                                               'security_patch': security_patch,
                                               'record_stock_build': state['stock']}}
    run('signature', lambda: check_signature(zip_path, signature, signers))
    run('allowed_signers', lambda: check_signers(signers, bases))

    def layout():
        state['archive'] = Archive(zip_path, state['release'].number)
        return {'members': len(state['archive'].members)}

    if not run('zip_layout', layout):
        return _finish(checks, state['sha256'])
    archive = state['archive']

    def pkmd():
        data = archive.read('avb_pkmd.bin')
        if caiman.sha256(data) != PKMD_SHA256:
            refuse(f'avb_pkmd.bin hashes to {caiman.sha256(data)}, not {PKMD_SHA256}')
        state['pkmd'] = data
        return {'sha256': PKMD_SHA256}

    def android_info():
        info = caiman.parse_android_info(archive.read('android-info.txt'), 'the zip android-info.txt')
        if info != state['info']:
            refuse(f'the zip android-info.txt {info.as_dict()} differs from adevtool\'s '
                   f'{state["info"].as_dict()}')
        return info.as_dict()

    def vbmeta():
        if 'pkmd' not in state:
            refuse('avb_pkmd.bin did not pass, so the embedded key cannot be compared')
        parsed, detail = check_vbmeta(archive, archive.read('vbmeta.img'), state['pkmd'],
                                      security_patch, avbtool, scratch, tools)
        state['vbmeta'] = parsed
        return detail

    def identity():
        if 'vbmeta' not in state:
            refuse('vbmeta did not pass, so the build number inside it is not trusted')
        return check_identity(state['vbmeta'], state['release'], state['stable'], state['stock'])

    def script():
        expect = flash_script.Expectation(state['info'].bootloader, state['info'].baseband,
                                          state['release'].number)
        report = flash_script.read(archive.read('flash-all.sh'), expect)
        if report['verdict'] != 'PASS':
            refuse('flash-all.sh: ' + '; '.join(report['reasons']))
        absent = [name for name in report['files'] if name not in archive.members]
        if absent:
            refuse(f'flash-all.sh writes files the zip does not contain: {absent}')
        return {key: report[key] for key in ('form', 'super_splits', 'os_images', 'unconfirmed')
                if key in report}

    try:
        run('avb_pkmd', pkmd)
        run('android_info', android_info)
        run('vbmeta', vbmeta)
        run('release_identity', identity)
        run('flash_script', script)
    finally:
        archive.zip.close()
    return _finish(checks, state['sha256'])


def _finish(checks, digest=None):
    reasons = [f'{name}: {result["reason"]}' for name, result in checks.items() if not result['ok']]
    return {'verdict': 'PASS' if not reasons else 'REFUSE', 'reasons': reasons, 'checks': checks,
            'sha256': digest}


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def andrix_identity(zip_path, *, avbtool, tools=None, scratch=None, bases=None):
    """An Andrix zip's identity from its signed vbmeta: base tag, stock build and versions.

    The base tag is the signed vbmeta property com.andrix.build.base_tag, which Andrix's
    release signing must add (design item 6). Until it does, every Andrix zip is refused.
    """
    digest = file_sha256(zip_path)
    archive = Archive(zip_path)
    try:
        pkmd = archive.read('avb_pkmd.bin')
        if WORKSHOP_PKMD_SHA256 is None:
            refuse('the workshop key for this phone is not recorded yet, so no Andrix zip is trusted')
        if caiman.sha256(pkmd) != WORKSHOP_PKMD_SHA256:
            refuse('the Andrix zip is not signed with the workshop key recorded for this phone')
        vbmeta = parse_vbmeta(archive.read('vbmeta.img'))
        tags = [d['value'] for d in vbmeta['descriptors']
                if d['type'] == 'property' and d['key'] == 'com.andrix.build.base_tag']
        if len(tags) != 1:
            refuse('the Andrix zip carries no single signed com.andrix.build.base_tag property')
        base = caiman.parse_release(tags[0], allow_preview=False, what='Andrix base tag')
        level = patch_level(base, None, bases)
        _, detail = check_vbmeta(archive, archive.read('vbmeta.img'), pkmd, level, avbtool,
                                 scratch, tools)
        fingerprints = [d['value'] for d in vbmeta['descriptors'] if d['type'] == 'property'
                        and _FINGERPRINT_KEY.fullmatch(d['key'])]
        parsed = [_ANDRIX_FINGERPRINT.fullmatch(value) for value in fingerprints]
        if not parsed or None in parsed or {m.group(1) for m in parsed} != {caiman.DEVICE} \
                or {m.group(4) for m in parsed} != {'release-keys'} or len({m.group(2) for m in parsed}) != 1:
            refuse(f'the Andrix fingerprints {fingerprints} are not one caiman release-keys build')
        info = caiman.parse_android_info(archive.read('android-info.txt'), 'the Andrix android-info.txt')
        report = flash_script.read(archive.read('flash-all.sh'),
                                   flash_script.Expectation(info.bootloader, info.baseband))
        if report['verdict'] != 'PASS':
            refuse('the Andrix flash-all.sh: ' + '; '.join(report['reasons']))
        firmware = _firmware(archive, info)
    finally:
        archive.zip.close()
    return {'sha256': digest, 'base_tag': base.number, 'stock_build': parsed[0].group(2),
            'android_info': info, 'vbmeta': detail, 'firmware': firmware}


def _firmware(archive, info):
    expect = flash_script.Expectation(info.bootloader, info.baseband)
    return {name: caiman.sha256(archive.read(name, IMAGE))
            for name in (expect.bootloader_file, expect.radio_file)}


def kit_firmware(zip_path, info):
    """The SHA-256 of a verified kit's bootloader and radio images."""
    archive = Archive(zip_path, Path(zip_path).name[len('caiman-install-'):-len('.zip')])
    try:
        return _firmware(archive, info)
    finally:
        archive.zip.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--zip', required=True, help='caiman-install-RELEASE.zip')
    parser.add_argument('--sig', help='its signature; default ZIP.sig')
    parser.add_argument('--allowed-signers', required=True)
    parser.add_argument('--release', required=True, help='the expected release')
    parser.add_argument('--stable', required=True, help='caiman-stable, as read at this moment')
    parser.add_argument('--security-patch', help="the release's YYYY-MM-DD, when no base record "
                        'gives it; a given value must equal the base record')
    parser.add_argument('--simg2img', help='the pinned simg2img, to rebuild the super splits')
    parser.add_argument('--lpunpack', help='the pinned lpunpack, to rebuild the super splits')
    parser.add_argument('--record', required=True, help="the release's adevtool record")
    parser.add_argument('--avbtool', required=True, help='external/avb/avbtool.py of the pinned tree')
    args = parser.parse_args(argv)
    try:
        record = json.loads(Path(args.record).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        sys.stdout.write(caiman.dump({'verdict': 'REFUSE', 'reasons': [str(error)]}))
        return 1
    report = check(args.zip, signature=args.sig or args.zip + '.sig', signers=args.allowed_signers,
                   release=args.release, stable=args.stable, security_patch=args.security_patch,
                   record=record, avbtool=args.avbtool,
                   tools={'simg2img': args.simg2img, 'lpunpack': args.lpunpack})
    sys.stdout.write(caiman.dump(report))
    return 0 if report['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
