# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import compiler_package as package


class CompilerPackageTests(unittest.TestCase):
    def test_generated_blueprint_matches_map_and_keeps_directories(self):
        rows=package.load(package.TOOLCHAIN/'payload.json')['files']
        self.assertEqual(package.blueprint(rows),(package.TOOLCHAIN/'Android.bp').read_text())
        self.assertEqual(len(rows),len({r['path'] for r in rows}))
        bp=package.blueprint(rows)
        self.assertNotIn('dsts:',bp)
        self.assertNotIn('prebuilt_any',bp)
        self.assertIn('enabled: false',bp)
        self.assertIn('owner_compiler: { enabled: true }',bp)
        dirs={str(Path(r['path']).parent) for r in rows if r['path'].startswith('etc/')}
        for directory in dirs:self.assertIn('relative_install_path: '+json.dumps(directory[4:]),bp)
        paths={r['path'] for r in rows}
        self.assertIn('etc/andrix/sdk/usr/include/aarch64-linux-android/c++/v1/__config_site',paths)
        self.assertNotIn('etc/andrix/sdk/usr/include/c++/v1/__config_site',paths)
        self.assertNotIn('etc/andrix/sdk/usr/lib/aarch64-linux-android/37/crtbegin_static.o',paths)

    def test_regular_digest_path_and_json_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'input';p.write_bytes(b'actual');digest=hashlib.sha256(b'actual').hexdigest()
            self.assertEqual(package.regular(root,'input',digest,6),p)
            with self.assertRaises(ValueError):package.regular(root,'input','0'*64,6)
            with self.assertRaises(ValueError):package.regular(root,'../input',digest,6)
            p.unlink();p.symlink_to('/dev/null')
            with self.assertRaises(ValueError):package.regular(root,'input',digest)
            p.unlink();(root/'dir').mkdir();(root/'dir/file').write_bytes(b'actual');(root/'link').symlink_to(root/'dir')
            with self.assertRaises(ValueError):package.regular(root,'link/file',digest)
            for value in ['{"a":1,"a":2}','{"a":NaN}']:
                p.write_text(value)
                with self.assertRaises(ValueError):package.load(p)

    def test_manifest_replacement_after_path_validation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'manifest';p.write_text('{"files":[]}')
            pin={'manifest':'manifest','sha256':package.sha(p)}
            original=package.regular
            def replace_after_check(*args):
                result=original(*args);p.write_text('{"files":["replacement"]}');return result
            with mock.patch.object(package,'regular',side_effect=replace_after_check):
                with self.assertRaisesRegex(ValueError,'Manifest changed'):
                    package.pinned_manifest(root,pin)

    def test_staging_is_complete_before_publish_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'source';src.write_bytes(b'payload')
            row={'path':'etc/andrix/header','sha256':package.sha(src),'size':7};dest=root/'stage'
            package.stage([row],{row['path']:src},dest)
            self.assertEqual((dest/'root'/row['path']).read_bytes(),b'payload')
            package.verify_stage([row],dest)
            (dest/'root'/row['path']).write_bytes(b'changed')
            with self.assertRaises(ValueError):package.verify_stage([row],dest)
            with self.assertRaises(ValueError):package.stage([row],{row['path']:src},dest)
            row['sha256']='0'*64
            with self.assertRaises(ValueError):package.stage([row],{row['path']:src},root/'bad')
            self.assertFalse((root/'bad').exists())

    def test_product_guard_requires_owner_session(self):
        product=package.ROOT/'products/andrix_gos_cf_arm64_only_phone.mk'
        for owner,compiler,success in [('false','true',False),('true','true',True),('false','false',True),('true','false',True)]:
            with tempfile.TemporaryDirectory() as tmp:
                make=Path(tmp)/'Makefile'
                make.write_text('define soong_config_set_bool\n$(eval ENABLED := $(3))\nendef\n'+
                    'ANDRIX_OWNER_SESSION := '+owner+'\nANDRIX_OWNER_COMPILER := '+compiler+'\n'+
                    'include '+str(product)+'\nall:\n\t@echo enabled=$(ENABLED)\n')
                p=subprocess.run(['make','--no-print-directory','-f',str(make)],text=True,capture_output=True)
                self.assertEqual(p.returncode==0,success,p.stdout+p.stderr)
                if owner==compiler=='true':self.assertIn('enabled=true',p.stdout)
                if compiler=='false':self.assertNotIn('enabled=true',p.stdout)

    def test_owner_readonly_sdk_and_runtime_access_stays_in_andrix_types(self):
        policy=(package.ROOT/'owner/sepolicy/andrix_owner.te').read_text()
        self.assertIn('allow andrix_owner andrix_file:file { open read getattr map };',policy)
        self.assertIn('allow andrix_owner andrix_lib:file { open read getattr map execute };',policy)
        self.assertNotIn('allow andrix_owner app_data_file',policy)
        self.assertNotIn('allow andrix_owner andrix_lib:file { write',policy)
        base=(package.ROOT/'sepolicy/private/andrix.te').read_text()
        self.assertIn('allow shell andrix_lib:dir { getattr search };',base)
        self.assertNotIn('allow shell andrix_lib:dir { write',base)

    def test_cxx_driver_config_uses_link_only_ndk_mapping(self):
        cfg=(package.TOOLCHAIN/'cxx.cfg').read_text();wrapper=(package.TOOLCHAIN/'tool_driver.c').read_text()
        self.assertIn('-nostdlib++',cfg)
        self.assertIn('$-Wl,-L,<CFGDIR>/../../lib64',cfg)
        self.assertNotIn('$-L<CFGDIR>',cfg)
        self.assertIn('$-lc++_shared',cfg)
        self.assertIn('execv(args[0], args)',wrapper)
        self.assertNotIn('system(',wrapper)

    def test_native_wrapper_forwards_exact_arguments_and_error_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);h=root/'test.c'
            h.write_text('''#include <assert.h>
#include <errno.h>
#include <string.h>
int andrix_wrapper_main(int,char**);
static int called;
static const char *alias;
int andrix_test_execv(const char *path,char *const args[]) {
 if (alias) {
  assert(!strcmp(path,!strcmp(alias,"cc")?"/usr/bin/clang":"/usr/bin/llvm-ar"));
  assert(!strcmp(args[0],alias)); assert(!strcmp(args[1],"path with spaces"));
  assert(args[2]==0); called=1; errno=ENOENT; return -1;
 }
 assert(!strcmp(path,"/usr/bin/clang"));
 assert(!strcmp(args[0],path));
 assert(!strcmp(args[1],"--driver-mode=g++"));
 assert(!strcmp(args[2],"--config=/usr/etc/andrix/cxx.cfg"));
 assert(!strcmp(args[3],"space words;not a shell"));
 assert(!strcmp(args[4],"--config=/owner/custom"));
 assert(args[5]==0); called=1; errno=ENOENT; return -1;
}
int main(void) {
 char *a[]={"clang++","space words;not a shell","--config=/owner/custom",0};
 assert(andrix_wrapper_main(3,a)==127); assert(called);
 const char *names[]={"cc","ar","ranlib","llvm-ranlib"};
 for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) {
  alias=names[i]; called=0; char *b[]={(char*)alias,"path with spaces",0};
  assert(andrix_wrapper_main(2,b)==127); assert(called);
 }
 return 0;
}
''')
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-Dmain=andrix_wrapper_main',
                '-Dexecv=andrix_test_execv','-c',str(package.TOOLCHAIN/'tool_driver.c'),'-o',str(root/'wrapper.o')],check=True,capture_output=True)
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(h),str(root/'wrapper.o'),'-o',str(root/'test')],check=True,capture_output=True)
            p=subprocess.run([str(root/'test')],text=True,capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr)


if __name__=='__main__':unittest.main()
