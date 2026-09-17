#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real cgroup controls through the native candidate, in one owned proof unit only."""
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

H = runpy.run_path(str(Path(__file__).resolve().parents[1]/'work-factory/kernel_scopes.py'),
                  run_name='andrix_factory_helpers')
require, send, receive = H['require'], H['send'], H['receive']
identify, membership, payload = H['identify'], H['membership'], H['payload']
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def manager(control, child_channel):
    os.setsid();signal.alarm(90)
    send(control, dict(event='ready', **identify()))
    require(receive(control) == {'command':'spawn'}, 'fixed spawn')
    child = os.fork()
    if child == 0:
        control.close();payload(child_channel);os._exit(125)
    child_channel.close();send(control, {'event':'child','pid':child})
    require(receive(control) == {'command':'exit'}, 'fixed manager exit')
    os._exit(37)


def main():
    own = Path('/sys/fs/cgroup') / membership().lstrip('/');root = own.parent
    require(own.name == 'control' and re.fullmatch(r'andrix-delegated-native-kernel-[0-9]{8}t[0-9]{6}z\.service', root.name), 'owned native proof delegation only')
    require(root.resolve() == root and root.is_relative_to('/sys/fs/cgroup/user.slice/user-1003.slice'), 'owned hierarchy')
    for file,value in [('memory.max',str(512*1024**2)),('memory.swap.max','0'),('cpu.max','200000 100000'),('pids.max','128')]:require((root/file).read_text().strip()==value,file)
    require(resource.getrlimit(resource.RLIMIT_CORE)==(0,0),'zero cores')
    require(len(sys.argv)==2,'explicit frozen native binary')
    require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0,'private subreaper')
    directory=os.open(root,FLAGS);pidfds={};groups={};kills=[];channels=[];drivers=[];records=[]
    def make(path):
        path.mkdir();groups[path]=path.stat().st_ino
    def kill_fd(path):
        fd=os.open(path/'cgroup.kill',os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW);kills.append(fd);return fd
    class Driver:
        def __init__(self,name,limits=(8,64,4096,8192,32),capture_error=None):
            self.p=subprocess.Popen([sys.argv[1],str(directory),name,*map(str,limits)],
                                    pass_fds=(directory,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.pidfd=os.pidfd_open(self.p.pid);drivers.append(self)
            self.first=self.read()
            if capture_error:
                require(self.first['event']=='capture_failed' and self.first['error']==capture_error,'expected native capture refusal')
                require(self.p.wait(timeout=5)==2,'capture refused status')
            else:require(self.first['event']=='captured','native captured root')
        def read(self):
            require(select.select([self.p.stdout],[],[],5)[0],'native response deadline')
            line=self.p.stdout.readline()
            require(line and len(line)<4096,'bounded native reply')
            result=json.loads(line);require(len(records)<10000,'bounded record count');records.append(result);return result
        def call(self,command):
            self.p.stdin.write((command+'\n').encode());self.p.stdin.flush();return self.read()
        def facts_closed(self):
            require(self.call('process-exit')['accepted'],'supplied process exit fact')
            require(self.call('reaped')['accepted'],'supplied reap fact')
            require(self.call('finish-mutation')['accepted'],'supplied closed mutation fact')
            require(self.call('observe')['sample']=='empty','fresh real empty')
        def quit(self):
            self.call('quit');require(self.p.wait(timeout=5)==0,'driver completed')
    def spawn(path):
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);channels.extend([parent,child])
        pid=os.fork()
        if pid==0:
            parent.close()
            try:payload(child)
            except BaseException:os._exit(124)
        child.close();pidfds[pid]=os.pidfd_open(pid)
        require(receive(parent)['pid']==pid,'owned payload ready')
        (path/'cgroup.procs').write_text(str(pid))
        send(parent,{'command':'release'});row=receive(parent)
        require(row['cgroup']=='/'+path.relative_to('/sys/fs/cgroup').as_posix(),'real payload membership')
        return pid,parent
    def reaped_sigkill(pid):
        require(select.select([pidfds[pid]],[],[],5)[0],'own pidfd exit')
        got,status=os.waitpid(pid,0);require(got==pid and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL,'actual own SIGKILL')
    def ping(channel,pid):
        send(channel,{'command':'ping'});require(receive(channel)['pid']==pid,'unrelated live response')
    try:
        scope=root/'captured_one';other_group=root/'unrelated'
        for path in [scope,scope/'control',scope/'work',scope/'work/deep',scope/'work/deep/leaf',other_group]:make(path)
        scope_kill=kill_fd(scope);kill_fd(other_group)
        control,child_control=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        work,child_work=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);channels.extend([control,child_control,work,child_work])
        leader=os.fork()
        if leader==0:
            control.close();work.close()
            try:manager(child_control,child_work)
            except BaseException:os._exit(124)
        child_control.close();child_work.close();pidfds[leader]=os.pidfd_open(leader)
        require(receive(control)['pid']==leader,'real manager ready')
        (scope/'control/cgroup.procs').write_text(str(leader));send(control,{'command':'spawn'})
        child=receive(control)['pid'];pidfds[child]=os.pidfd_open(child);require(receive(work)['pid']==child,'real nested child')
        (scope/'work/deep/leaf/cgroup.procs').write_text(str(child));send(work,{'command':'release'});receive(work)
        other,peer=spawn(other_group)
        d=Driver(scope.name)
        require(d.call('observe')['sample']=='populated','real native positive population')
        send(control,{'command':'exit'});require(select.select([pidfds[leader]],[],[],5)[0],'manager exit')
        got,status=os.waitpid(leader,0);require(got==leader and os.WIFEXITED(status) and os.WEXITSTATUS(status)==37,'manager reaped before cleanup')
        send(work,{'command':'ping'});require(receive(work)['parent']==os.getpid(),'live adopted nested descendant')
        d.call('process-exit');d.call('reaped')
        require(d.call('signal')['accepted'],'native captured kill')
        reaped_sigkill(child)
        require(d.call('read-begin')['sample']=='empty','old sample before mutation closure')
        make(scope/'late');late,late_peer=spawn(scope/'late')
        require(d.call('step 8')['event']=='step_rejected','pending mutation/observation fence')
        require(d.call('finish-mutation')['accepted'],'close late creator')
        require(not d.call('read-finish')['accepted'],'late Empty sample rejected')
        require(d.call('observe')['sample']=='populated','late member really exists')
        require(d.call('step 8')['event']=='step_rejected','live scope not reclaimed')
        require(d.call('signal')['accepted'],'exact repeated kill after late completion')
        reaped_sigkill(late);require(d.call('observe')['sample']=='empty','fresh stable Empty')
        d.call('queue 1');require(d.call('timeout')['cleanup_pending'],'timed out worker slot retained')
        require(d.call('step 1')['event']=='step_rejected','no replacement worker before result')
        require(d.call('finish-queued')['cleanup']=='blocked','late progress stays explicit')
        require(d.call('second-cursor')['error']=='busy','exclusive cursor')
        pongs=0;dropped=False
        for unused in range(2048):
            row=d.call('step 8');require(row['event']=='step' and row['error']=='none' and row['steps']<=8,'bounded native progress')
            ping(peer,other);pongs+=1
            if row['removed_directories'] and not dropped:
                d.call('drop');dropped=True
            if row['cleanup']=='retired':break
        else:raise RuntimeError('native progress bound')
        require(dropped and not scope.exists() and row['restart_allowed'],'native removal, cursor resumption and restart fence')
        make(scope);replacement=scope.stat().st_ino;require(replacement!=d.first['inode'],'new kernel root identity')
        replacement_kill=kill_fd(scope);(scope/'cgroup.procs').write_text(str(other))
        require(d.call('signal')['error']=='removed','old native root cannot retarget')
        ping(peer,other);os.write(replacement_kill,b'1');reaped_sigkill(other);d.quit()
        scope.rmdir();other_group.rmdir()
        # Empty fault cases supply lifecycle facts, but use actual kernel objects.
        for name,limits,command,expected_error in [
            ('depth_limit',(0,64,4096,8192,32),'step 32','limit'),
            ('entry_limit',(8,64,1,8192,32),'step 32','limit'),
            ('work_limit',(8,64,4096,1,32),'step 32','limit'),
            ('bad_quantum',(8,64,4096,8192,32),'step 0','invalid_argument')]:
            path=root/name;make(path);make(path/'child');kill_fd(path)
            limited=Driver(name,limits);limited.facts_closed()
            for unused in range(1024):
                row=limited.call(command)
                if row['cleanup']=='blocked':break
            else:raise RuntimeError('fault bound')
            require(row['error']==expected_error and path.exists() and not row['restart_allowed'],'limit fails without retirement')
            limited.quit()
            if (path/'child').exists():(path/'child').rmdir()
            path.rmdir()
        denied=root/'denied';make(denied);kill_fd(denied)
        mode=(denied/'cgroup.events').stat().st_mode & 0o777
        try:
            os.chmod(denied/'cgroup.events',0)
            refused=Driver(denied.name,capture_error='io');require(refused.first['errno']==13,'real EACCES at capture')
        finally:os.chmod(denied/'cgroup.events',mode)
        denied.rmdir()
        mismatch=root/'identity_mismatch';make(mismatch);kill_fd(mismatch)
        stale=Driver(mismatch.name);stale.facts_closed();last_entries=-1
        for unused in range(1024):
            row=stale.call('step 1');require(row['error']=='none' and row['cleanup']!='retired','pause before root unlink')
            if row['entry_visits']==last_entries:break
            last_entries=row['entry_visits']
        else:raise RuntimeError('EOF boundary not found')
        mismatch.rmdir();make(mismatch);new_kill=kill_fd(mismatch);victim,victim_peer=spawn(mismatch)
        raw=stale.call('raw-population');require(raw['sample']=='removed' and raw['errno']==19,'captured event FD reports removed object')
        row=stale.call('step 1');require(row['error']=='identity_changed' and row['cleanup']=='blocked' and not row['restart_allowed'],'changed entry rejected')
        require(stale.call('signal')['error']=='removed','captured deleted group kill refused')
        ping(victim_peer,victim);stale.quit();os.write(new_kill,b'1');reaped_sigkill(victim);mismatch.rmdir()
        print(json.dumps({'native_components_exercised':True,'manager_reaped_before_exact_group_kill':True,
                          'late_kernel_member_invalidated_old_empty':True,'cleanup_timeout_slot_preserved':True,
                          'unrelated_control_responses_during_steps':pongs,'cursor_resumed_from_captured_root':True,
                          'stale_root_and_changed_entry_did_not_target_replacement':True,'real_permission_denial':True,
                          'depth_entry_work_and_quantum_bounds_observed':True,'records':records,
                          'limits':['not Android init integration or MAC proof','no forced numeric PID reuse','deterministic name replacement, not atomic protection against concurrent replacement','no arbitrary kernel I/O latency guarantee'],
                          'combined_contract_qualified':False},indent=2))
    finally:
        for driver in drivers:
            if driver.p.poll() is None:
                signal.pidfd_send_signal(driver.pidfd,signal.SIGKILL);driver.p.wait(timeout=5)
            os.close(driver.pidfd)
        for fd in kills:
            try:os.write(fd,b'1')
            except OSError as error:
                if error.errno not in [2,19]:raise
        for fd in pidfds.values():
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
        until=time.monotonic()+5
        while True:
            try:pid,_=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:break
            if pid==0:
                require(time.monotonic()<until,'owned descendant cleanup deadline');time.sleep(.01)
        for path,inode in sorted(groups.items(),key=lambda item:len(item[0].parts),reverse=True):
            if path.exists():require(path.stat().st_ino==inode,'owned group identity at cleanup');path.rmdir()
        for channel in channels:channel.close()
        for fd in [directory,*kills,*pidfds.values()]:os.close(fd)


if __name__=='__main__':main()
