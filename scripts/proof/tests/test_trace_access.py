# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]


@unittest.skipUnless(shutil.which('cc'), 'host C compiler required')
class TraceAccessTests(unittest.TestCase):
    def test_real_seize_controls_and_child_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            main=tmp/'test.c'
            main.write_text(r'''#define _GNU_SOURCE
#include "trace_access.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static void no_children(void) {
  errno=0;
  assert(waitpid(-1,0,WNOHANG)==-1 && errno==ECHILD);
}
int main(void) {
  assert(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0);
  AndrixTraceAccess r=andrix_trace_access(0);
  printf("SELF complete=%d error=%d\n",r.complete,r.error);
  assert(r.complete==1 && r.error==0);
  no_children();
  r=andrix_trace_access(INT_MAX);
  assert(r.complete==1 && r.error==ESRCH);
  no_children();
  assert(andrix_trace_access(-1).complete==0);
  assert(andrix_trace_access(1).complete==0);
  assert(andrix_trace_access(getpid()).complete==0);
  struct sigaction old={0},ignored={0};
  ignored.sa_handler=SIG_IGN;
  assert(sigaction(SIGCHLD,&ignored,&old)==0);
  r=andrix_trace_access(0);
  assert(r.complete==0 && r.error==EINVAL);
  assert(sigaction(SIGCHLD,&old,0)==0);
  no_children();
  pid_t parent=getpid();
  pid_t target=fork();
  assert(target>=0);
  if (!target) {
    if (prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)!=0 || getppid()!=parent) _exit(1);
    poll(0,0,10000);
    _exit(0);
  }
  r=andrix_trace_access(target);
  // Host Yama/dumpability may reject sibling tracing; neither answer is an
  // Android policy claim. The helper must leave this live external target alone.
  assert(r.complete==1 && (r.error==0 || r.error==EPERM || r.error==EACCES));
  int status=0;
  assert(waitpid(target,&status,WNOHANG|WUNTRACED)==0);
  assert(kill(target,0)==0);
  assert(kill(target,SIGKILL)==0); // Only our own fresh test child.
  assert(waitpid(target,&status,0)==target);
  assert(WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
  no_children();
  struct sock_filter instructions[]={
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_ptrace,0,1),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
  };
  struct sock_fprog program={4,instructions};
  assert(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)==0);
  r=andrix_trace_access(0);
  assert(r.complete==1 && r.error==EPERM);
  no_children();
  puts("HOST_SEIZE_POSITIVE_DENIAL_AND_CLEANUP_OK_NOT_ANDROID_MAC");
  return 0;
}
''')
            binary=tmp/'test'
            subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                            '-I'+str(ROOT/'tests/owner-debugger'),str(main),
                            str(ROOT/'tests/owner-debugger/trace_access.c'),'-o',str(binary)],
                           check=True,capture_output=True,timeout=30)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=25)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('HOST_SEIZE_POSITIVE_DENIAL_AND_CLEANUP_OK_NOT_ANDROID_MAC',result.stdout)


if __name__=='__main__':unittest.main()
