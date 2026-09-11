# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_compiler as compiler


class NativeCompilerPreparationTests(unittest.TestCase):
    def test_profile_is_android_arm64_not_host_or_legacy_llvm(self):
        profile=json.loads((compiler.ROOT/'toolchain/native-compiler.json').read_text())
        self.assertEqual(profile['target'],'aarch64-linux-android37')
        self.assertEqual(profile['llvm_project'],'external/opencl/llvm-project')
        self.assertEqual(profile['bootstrap_directory'],'clang-r584948b')
        self.assertFalse(profile['public_on_device_compiler_proved'])
        cmake=(compiler.ROOT/'toolchain/AndroidBionic.cmake').read_text()
        for required in ['aarch64-linux-android37','-nostdlib++','-lc++_shared',
                         '-fstack-protector-strong','-D_FORTIFY_SOURCE=2',
                         '-ftrivial-auto-var-init=zero','-flto=thin','-fsanitize=cfi-icall',
                         'CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY',
                         'CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY']:
            self.assertIn(required,cmake)
        self.assertNotIn('ALLOW_MISSING_DEPENDENCIES',cmake)
        self.assertIn('-DLLVM_PARALLEL_LINK_JOBS=1',compiler.common_flags())
        self.assertIn('-DLLVM_ENABLE_CURL=OFF',compiler.common_flags())

    def test_sdk_changed_bytes_extra_file_and_escape_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'header';p.write_bytes(b'input')
            row={'path':'header','size':5,'sha256':hashlib.sha256(b'input').hexdigest()}
            manifest={'profile_sha256':compiler.compiler_sdk.sha(compiler.ROOT/'toolchain/native-compiler.json'),
                      'files':[row]}
            (root/'manifest.json').write_text(json.dumps(manifest))
            digest=compiler.compiler_sdk.sha(root/'manifest.json')
            compiler.verify_sdk(root,digest)
            p.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'bytes changed'):compiler.verify_sdk(root,digest)
            p.write_bytes(b'input');extra=root/'extra';extra.touch()
            with self.assertRaisesRegex(ValueError,'Unexpected'):compiler.verify_sdk(root,digest)
            extra.unlink();p.unlink();p.symlink_to('/dev/null')
            with self.assertRaisesRegex(ValueError,'symlink'):compiler.verify_sdk(root,digest)
            p.unlink();row['path']='../outside';(root/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'manifest differs'):compiler.verify_sdk(root,digest)
            with self.assertRaisesRegex(ValueError,'path'):
                compiler.verify_sdk(root,compiler.compiler_sdk.sha(root/'manifest.json'))

    def test_profile_mismatch_fails_before_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'manifest.json').write_text(json.dumps({'profile_sha256':'0'*64,'files':[]}))
            with self.assertRaisesRegex(ValueError,'profile changed'):
                compiler.verify_sdk(root,compiler.compiler_sdk.sha(root/'manifest.json'))


if __name__=='__main__':unittest.main()
