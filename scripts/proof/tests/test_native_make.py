# SPDX-License-Identifier: Apache-2.0
"""Source/archive/ELF controls for the native Make recipe, not Android execution."""
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))
spec = importlib.util.spec_from_file_location('native_make', Path(__file__).parents[1]/'native_make.py')
make = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make)


class NativeMakeTests(unittest.TestCase):
    def tar(self, rows):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as archive:
            for name, kind, content in rows:
                item = tarfile.TarInfo(name); item.type = kind
                item.size = len(content) if kind == tarfile.REGTYPE else 0
                item.mode = 0o755; item.linkname = '../../escape'
                archive.addfile(item, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
        return out.getvalue()

    def test_safe_regular_source_and_no_links_or_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self.tar([('make-4.4.1/configure', tarfile.REGTYPE, b'actual source')])
            rows = make.unpack(data, root/'good')
            self.assertEqual(rows[0]['sha256'], hashlib.sha256(b'actual source').hexdigest())
            self.assertEqual((root/'good/make-4.4.1/configure').read_bytes(), b'actual source')
            self.assertTrue((root/'good/make-4.4.1/configure').stat().st_mode & 0o111)
            cases = [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                     ('make-4.4.1/../escape', tarfile.REGTYPE), ('other/file', tarfile.REGTYPE),
                     ('make-4.4.1/link', tarfile.SYMTYPE), ('make-4.4.1/hard', tarfile.LNKTYPE),
                     ('make-4.4.1/fifo', tarfile.FIFOTYPE), ('make-4.4.1//odd', tarfile.REGTYPE)]
            for i, (name, kind) in enumerate(cases):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    make.unpack(self.tar([(name, kind, b'x')]), root/str(i))
            duplicate = self.tar([('make-4.4.1/f', tarfile.REGTYPE, b'a')]*2)
            with self.assertRaises(ValueError): make.unpack(duplicate, root/'duplicate')

    def test_captured_manifest_and_sdk_file_set_are_digest_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); p = root/'header'; p.write_bytes(b'header')
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            manifest = {'files': [{'path':'header','size':6,'sha256':digest}]}
            (root/'manifest.json').write_text(json.dumps(manifest))
            pin = hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest()
            self.assertEqual(make.verify_sdk(root, pin), manifest)
            with self.assertRaises(ValueError): make.verify_sdk(root, '0'*64)
            (root/'extra').write_text('unexpected')
            with self.assertRaises(ValueError): make.verify_sdk(root, pin)
            (root/'extra').unlink(); p.write_bytes(b'drift!')
            with self.assertRaises(ValueError): make.verify_sdk(root, pin)
            p.unlink(); p.symlink_to(root/'manifest.json')
            with self.assertRaises(ValueError): make.verify_sdk(root, pin)

    def test_elf_gate_rejects_foreign_runtime_and_missing_hardening(self):
        elf = '''ELF Header:
  Class:                             ELF64
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
      [Requesting program interpreter: /system/bin/linker64]
  LOAD 0x000000 0x0000 0x0000 0x1000 0x1000 R E 0x4000
  GNU_RELRO 0x001000 0x1000 0x1000 0x1000 0x1000 R 0x1
  GNU_STACK 0x000000 0x0000 0x0000 0x0000 0x0000 RW 0x0
  0x1 (NEEDED) Shared library: [libc.so]
  0x1 (NEEDED) Shared library: [libdl.so]
  0x1e (FLAGS) BIND_NOW
  0x6ffffffb (FLAGS_1) Flags: NOW PIE
'''
        self.assertEqual(make.elf_facts(elf)['needed'], ['libc.so','libdl.so'])
        for old, new in [('AArch64','X86-64'), ('ELF64','ELF32'),
                         ('/system/bin/linker64','/lib/ld-linux-aarch64.so.1'),
                         ('libc.so','libc_musl.so'), ('0x4000','0x1000'),
                         ('BIND_NOW',''), ('NOW PIE','NOW'), ('RW 0x0','RWE 0x0')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                make.elf_facts(elf.replace(old,new))
        with self.assertRaises(ValueError): make.elf_facts(elf+' 0x1d (RUNPATH) [/host/lib]\n')

    def test_profile_and_patch_keep_bionic_and_unmodified_non_bionic_path(self):
        profile = json.loads(make.PROFILE.read_text())
        patch = make.PROFILE.parent/profile['patch']['file']
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), profile['patch']['sha256'])
        text = patch.read_text()
        self.assertIn('#ifdef __BIONIC__', text)
        self.assertIn('p = _PATH_DEFPATH;', text)
        self.assertIn('confstr (_CS_PATH', text)
        self.assertNotIn('/usr/bin', text)
        self.assertIn('-fsanitize=cfi-icall', profile['cflags'])
        self.assertIn('-flto=thin', profile['cflags'])
        self.assertEqual(profile['default_runtime_cxx'], 'c++')
        self.assertIn('--disable-load', profile['configure'])
        self.assertIn('--without-guile', profile['configure'])
        self.assertNotIn('-static', profile['ldflags'])
