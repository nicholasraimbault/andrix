# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]


class ClientHangupTests(unittest.TestCase):
    def test_real_pty_hangup_owned_child_and_exec_failure(self):
        compiler=shutil.which('cc');self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temp:
            work=Path(temp);stub=work/'stub.c'
            stub.write_text('''#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
int probe_main(int,char**);
static int fail_exec;
int andrix_test_execv(const char *path,char *const argv[]) {
  assert(!strcmp(path,"/usr/bin/tmux"));
  assert(!strcmp(argv[0],"tmux") && !strcmp(argv[1],"-L"));
  assert(!strcmp(argv[2],"andrix-proof") && !strcmp(argv[3],"attach-session"));
  assert(!strcmp(argv[4],"-t") && !strcmp(argv[5],"lab") && !argv[6]);
  if (fail_exec) { errno=ENOENT; return -1; }
  const char bytes[]="ANDRIX_TMUX_STATE\\r\\n";
  assert(write(1,bytes,sizeof(bytes)-1)==sizeof(bytes)-1);
  for (;;) pause();
}
int main(int argc,char **argv) {
  (void)argv;
  char *args[]={"probe","ANDRIX_TMUX_STATE",0};
  if (argc==2) fail_exec=1;
  if (argc==3) signal(SIGCHLD,SIG_IGN);
  return probe_main(2,args);
}
''')
            obj=work/'probe.o';binary=work/'test'
            subprocess.run([compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror',
                '-Dmain=probe_main','-Dexecv=andrix_test_execv','-c',
                str(ROOT/'tests/owner-retained-terminal/client_hangup.c'),'-o',str(obj)],
                check=True,capture_output=True,timeout=30)
            subprocess.run([compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror',
                str(stub),str(obj),'-o',str(binary)],check=True,capture_output=True,timeout=30)
            good=subprocess.run([str(binary)],text=True,capture_output=True,timeout=20)
            self.assertEqual(good.returncode,0,good.stdout+good.stderr)
            self.assertIn('marker=1 reaped=1',good.stdout)
            bad=subprocess.run([str(binary),'fail'],text=True,capture_output=True,timeout=20)
            self.assertEqual(bad.returncode,1,bad.stdout+bad.stderr)
            self.assertIn('result=FAIL',bad.stdout)
            ignored=subprocess.run([str(binary),'ignore','SIGCHLD'],text=True,capture_output=True,timeout=10)
            self.assertEqual(ignored.returncode,2,ignored.stdout+ignored.stderr)


if __name__=='__main__':unittest.main()
