#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Private cleanup process mechanism controls, not Android init integration."""
import ctypes
import json
import os
from pathlib import Path
import re
import resource
import runpy
import select
import signal
import socket
import subprocess
import sys
import time

H=runpy.run_path(str(Path(__file__).resolve().parents[1]/'work-factory/kernel_scopes.py'),run_name='andrix_factory_helpers')
require,send,receive=H['require'],H['send'],H['receive']
membership,payload=H['membership'],H['payload']


def main():
    own=Path('/sys/fs/cgroup')/membership().lstrip('/');root=own.parent
    require(own.name=='control' and re.fullmatch(r'andrix-delegated-worker-kernel-[0-9]{8}t[0-9]{6}z\.service',root.name),'owned cleanup worker proof delegation only')
    require(root.resolve()==root and root.is_relative_to(f'/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice'),'owned hierarchy')
    for name,value in [('memory.max','536870912'),('memory.swap.max','0'),('cpu.max','200000 100000'),('pids.max','128')]:require((root/name).read_text().strip()==value,name)
    require(resource.getrlimit(resource.RLIMIT_CORE)==(0,0),'zero cores')
    require(len(sys.argv)==2,'frozen driver supplied')
    require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0,'private subreaper')
    groups={};kills=[];children={};worker_pidfds={};sockets=[];drivers=[];records=[]
    def make(path):path.mkdir();groups[path]=path.stat().st_ino
    def capture_kill(path):
        fd=os.open(path/'cgroup.kill',os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW);kills.append(fd);return fd
    def spawn(path):
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);sockets.extend([parent,child]);pid=os.fork()
        if pid==0:
            parent.close()
            try:payload(child)
            except BaseException:os._exit(124)
        child.close();children[pid]=os.pidfd_open(pid);require(receive(parent)['pid']==pid,'owned child')
        (path/'cgroup.procs').write_text(str(pid));send(parent,{'command':'release'});row=receive(parent)
        require(row['cgroup']=='/'+path.relative_to('/sys/fs/cgroup').as_posix(),'actual payload membership')
        return pid,parent
    def reap_killed(pid):
        require(select.select([children[pid]],[],[],5)[0],'owned exit deadline');got,status=os.waitpid(pid,0)
        require(got==pid and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL,'actual SIGKILL')
    def ping(channel,pid):send(channel,{'command':'ping'});require(receive(channel)['pid']==pid,'live unrelated response')
    class Driver:
        def __init__(self,name):
            self.p=subprocess.Popen([sys.argv[1],name],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.pidfd=os.pidfd_open(self.p.pid);drivers.append(self)
            require(self.read()['event']=='ready','private cleanup worker started')
        def read(self):
            require(select.select([self.p.stdout],[],[],5)[0],'native response deadline');data=self.p.stdout.readline()
            require(data and len(data)<4096,'bounded response');row=json.loads(data);records.append(row);require(len(records)<5000,'bounded records')
            pid=row.get('worker_pid',0);key=(id(self),row.get('worker'),pid)
            if pid>1 and key not in worker_pidfds:
                worker_pidfds[key]=os.pidfd_open(pid)
                require(Path('/proc/'+str(pid)+'/cgroup').read_text().strip()=='0::'+membership(),'helper is inside this exact owned proof unit')
            return row
        def call(self,command):self.p.stdin.write((command+'\n').encode());self.p.stdin.flush();return self.read()
        def empty_without_process(self):
            self.call('finish-mutation');require(self.call('absent-fact')['accepted'],'no invented process exit');require(self.call('observe')['population']=='empty','actual kernel Empty')
        def quit(self):self.call('quit');require(self.p.wait(timeout=5)==0,'driver exit')
    try:
        scope=root/'worker_recovery';other=root/'independent'
        for path in [scope,scope/'control',scope/'work',scope/'work/one',other]:make(path)
        capture_kill(scope);other_kill=capture_kill(other)
        leader,leader_channel=spawn(scope/'control');descendant,desc_channel=spawn(scope/'work/one');peer,peer_channel=spawn(other)
        d=Driver(scope.name);require(d.call('observe')['population']=='populated','real nonempty root through worker')
        require(d.call('kill')['accepted'],'captured cohort kill through private worker');reap_killed(leader);reap_killed(descendant)
        d.call('exit-fact');d.call('reap-fact');d.call('finish-mutation');require(d.call('observe')['population']=='empty','fresh actual Empty')
        d.call('pause-worker');d.call('queue 8');require(d.call('timeout')['pending'],'timeout retains live worker slot')
        began=time.monotonic();state=d.call('inspect');response_delay=time.monotonic()-began
        require(state['pending'] and not state['restart_allowed'] and response_delay<1,'control responds while cleanup worker stopped')
        require(d.call('step 8')['event']=='step_rejected','no replacement cleanup operation')
        ping(peer_channel,peer);d.call('continue-worker');d.call('finish-step')
        for unused in range(2048):
            row=d.call('step 1');require(row['error']=='none','partial cleanup')
            if row['removed']>0:break
        else:raise RuntimeError('partial progress bound')
        require(scope.exists() and not row['restart_allowed'],'old root still owns cleanup')
        require(d.call('crash-worker')['accepted'],'actual worker death/reap')
        recovered=d.call('observe');require(recovered['worker']==2 and recovered['population']=='empty','fresh worker adopted same descriptor cohort')
        pongs=1
        for unused in range(1024):
            row=d.call('step 8');require(row['error']=='none','resumed native cleanup');ping(peer_channel,peer);pongs+=1
            if row['restart_allowed']:break
        else:raise RuntimeError('resumption bound')
        require(not scope.exists() and row['cleanup']=='retired','retirement only after physical removal')
        d.quit();os.write(other_kill,b'1');reap_killed(peer);other.rmdir()
        for name,reuse in [('lost_reply',False),('lost_reply_replaced',True)]:
            path=root/name;make(path);capture_kill(path)
            lost=Driver(name);lost.empty_without_process();lost.call('queue 32')
            end=time.monotonic()+5
            while path.exists() and time.monotonic()<end:time.sleep(.01)
            require(not path.exists(),'worker physically removed root before reply consumption')
            require(lost.call('inspect')['pending'],'lost result not fabricated as completion')
            lost.call('crash-worker')
            if reuse:
                make(path);new_kill=capture_kill(path);victim,victim_channel=spawn(path)
            reconciled=lost.call('confirm');require(reconciled['worker']==2,'new worker exact descriptor handoff')
            if reuse:
                require(reconciled['error']=='identity_changed' and not reconciled['restart_allowed'],'replacement keeps namespace violation blocked')
                require(lost.call('kill')['error']=='removed','old control never retargets replacement');ping(victim_channel,victim)
                lost.quit();os.write(new_kill,b'1');reap_killed(victim);path.rmdir()
            else:
                require(reconciled['error']=='none' and reconciled['restart_allowed'] and reconciled['cleanup']=='retired','captured removal confirmation resolves lost reply')
                lost.quit()
        print(json.dumps({'actual_private_worker_processes':True,'kernel_cleanup_via_transferred_descriptor_cohort':True,
          'control_response_with_stopped_worker_seconds':response_delay,'timeout_did_not_free_worker_slot':True,
          'worker_killed_and_reaped_before_replacement':True,'partial_cleanup_recovered_same_scope':True,
          'lost_final_reply_reconciled_via_captured_removed_object':True,'new_name_did_not_replace_old_identity':True,
          'unrelated_responses_during_steps':pongs,'records':records,'Android_init_or_MAC_qualified':False,
          'limits':['controlled SIGSTOP, not uninterruptible kernel I/O','host parent/worker share UID, no Android profile claim','no forced numeric PID reuse','exclusive parent namespace remains required']},indent=2))
    finally:
        for fd in worker_pidfds.values():
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
        for driver in drivers:
            if driver.p.poll() is None:signal.pidfd_send_signal(driver.pidfd,signal.SIGKILL);driver.p.wait(timeout=5)
            os.close(driver.pidfd)
        for fd in kills:
            try:os.write(fd,b'1')
            except OSError as error:
                if error.errno not in [2,19]:raise
        for fd in children.values():
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
        end=time.monotonic()+5
        while True:
            try:pid,_=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:break
            if pid==0:require(time.monotonic()<end,'owned child cleanup deadline');time.sleep(.01)
        for path,inode in sorted(groups.items(),key=lambda row:len(row[0].parts),reverse=True):
            if path.exists():require(path.stat().st_ino==inode,'only created groups removed');path.rmdir()
        for channel in sockets:channel.close()
        for fd in [*kills,*children.values(),*worker_pidfds.values()]:os.close(fd)


if __name__=='__main__':main()
