#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Captured-group cleanup steps on a real delegated host kernel, not Android init.

Only this exact proof unit's fresh groups and captured child pidfds are manipulated.
The observer keeps exclusive namespace/mutation ownership. Directory walking/removal
is bounded for this fixture; it is not a production asynchronous reclaimer.
"""
import ctypes
import errno
import os
from pathlib import Path
import re
import resource
import runpy
import select
import signal
import socket
import stat
import time
import json

H = runpy.run_path(str(Path(__file__).resolve().parents[1]/'work-factory/kernel_scopes.py'),
                  run_name='andrix_factory_helpers')
require, send, receive = H['require'], H['send'], H['receive']
membership, identify, payload = H['membership'], H['identify'], H['payload']
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def population(fd):
    control = os.open('cgroup.events', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
    try:data = os.read(control, 256).decode()
    finally:os.close(control)
    values = dict(row.split() for row in data.splitlines())
    require(values.get('populated') in ['0', '1'], 'fresh kernel population')
    return values['populated'] == '1'


def manager(control, child_channel):
    os.setsid();signal.alarm(40)
    send(control, {'event':'ready', **identify()})
    require(receive(control) == {'command':'spawn'}, 'fixed spawn gate')
    child = os.fork()
    if not child:
        control.close();payload(child_channel);os._exit(123)
    child_channel.close()
    send(control, {'event':'child', 'pid':child})
    require(receive(control) == {'command':'exit'}, 'fixed exit gate')
    os._exit(37)


def reclaim_steps(fd, parent_fd, name, device, depth=0):
    """One directory observation or removal per yield, only after a closed boundary.

    The platform/harness owns the parent namespace exclusively. fstat/unlinkat is
    NOT atomic protection against another actor replacing names concurrently.
    """
    require(depth <= 8, 'fixture depth bound')
    expected = os.fstat(fd)
    require(expected.st_dev == device and stat.S_ISDIR(expected.st_mode), 'same owned filesystem')
    with os.scandir(fd) as iterator:entries = list(iterator)
    require(len(entries) <= 128, 'fixture directory entry bound')
    children = []
    for entry in entries:
        attributes = entry.stat(follow_symlinks=False)
        require(attributes.st_dev == device and not stat.S_ISLNK(attributes.st_mode), 'no crossing or symlink')
        if stat.S_ISDIR(attributes.st_mode):children.append(entry.name)
    yield {'event':'inspected', 'name':name, 'child_directories':len(children)}
    for child in sorted(children):
        child_fd = os.open(child, FLAGS, dir_fd=fd)
        try:yield from reclaim_steps(child_fd, fd, child, device, depth+1)
        finally:os.close(child_fd)
    actual = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), 'exact entry before removal')
    os.rmdir(name, dir_fd=parent_fd)
    yield {'event':'removed', 'name':name, 'inode':expected.st_ino}


def main():
    own = Path('/sys/fs/cgroup') / membership().lstrip('/')
    root = own.parent
    require(own.name == 'control' and re.fullmatch(r'andrix-delegated-kernel-[0-9]{8}t[0-9]{6}z\.service', root.name), 'owned proof delegation only')
    require(root.resolve() == root and root.is_relative_to('/sys/fs/cgroup/user.slice'), 'real owned hierarchy')
    for name, value in [('memory.max', str(512*1024**2)), ('memory.swap.max','0'),
                        ('cpu.max','200000 100000'), ('pids.max','128')]:
        require((root/name).read_text().strip() == value, name+' bound')
    require(resource.getrlimit(resource.RLIMIT_CORE) == (0,0), 'zero core')
    require((root/'cgroup.procs').stat().st_uid == os.getuid() and not (root/'cgroup.procs').read_text().strip(), 'observer outside managed subtree')
    require(any(' /sys/fs/cgroup ' in row and ' - cgroup2 ' in row for row in Path('/proc/self/mountinfo').read_text().splitlines()), 'actual cgroup2 mount')
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, 'private subreaper')
    scope = root/'instance_one';other_group = root/'unrelated'
    created = {};pidfds = {};fds = [];kill_fds = [];channels = [];records = []
    def make(path):
        path.mkdir();created[path] = path.stat().st_ino
    def open_dir(path):
        fd = os.open(path, FLAGS);fds.append(fd);return fd
    def open_kill(fd):
        result = os.open('cgroup.kill', os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW, dir_fd=fd)
        fds.append(result);kill_fds.append(result);return result
    try:
        for path in [scope,scope/'control',scope/'work',scope/'work/one',scope/'work/branch',scope/'work/branch/empty',other_group]:make(path)
        root_fd = open_dir(root);scope_fd = open_dir(scope);kill_fd = open_kill(scope_fd)
        other_fd = open_dir(other_group);open_kill(other_fd)
        device = os.fstat(scope_fd).st_dev;old_inode = os.fstat(scope_fd).st_ino
        parent, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        work, child_work = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channels.extend([parent, child_control, work, child_work])
        leader = os.fork()
        if not leader:
            parent.close();work.close()
            try:manager(child_control, child_work)
            except BaseException:os._exit(121)
        child_control.close();child_work.close();pidfds[leader] = os.pidfd_open(leader)
        require(receive(parent)['pid'] == leader, 'exact manager')
        (scope/'control/cgroup.procs').write_text(str(leader))
        send(parent, {'command':'spawn'});child = receive(parent)['pid'];pidfds[child] = os.pidfd_open(child)
        require(receive(work)['pid'] == child, 'exact child')
        (scope/'work/one/cgroup.procs').write_text(str(child))
        send(work, {'command':'release'});released = receive(work)
        require(released['cgroup'] == '/'+(scope/'work/one').relative_to('/sys/fs/cgroup').as_posix(), 'actual contained payload')
        peer, child_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET);channels.extend([peer,child_peer])
        unrelated = os.fork()
        if not unrelated:
            peer.close();parent.close();work.close()
            try:payload(child_peer)
            except BaseException:os._exit(121)
        child_peer.close();pidfds[unrelated] = os.pidfd_open(unrelated)
        require(receive(peer)['pid'] == unrelated, 'owned unrelated child')
        (other_group/'cgroup.procs').write_text(str(unrelated))
        send(peer, {'command':'release'});require(receive(peer)['pid'] == unrelated, 'unrelated released')
        pongs = 0
        def ping():
            nonlocal pongs
            send(peer, {'command':'ping'});require(receive(peer)['pid'] == unrelated, 'unrelated control response');pongs += 1
        ping()
        send(parent, {'command':'exit'});require(select.select([pidfds[leader]],[],[],5)[0], 'manager exit deadline')
        pid, status = os.waitpid(leader, 0)
        require(pid == leader and os.WIFEXITED(status) and os.WEXITSTATUS(status)==37, 'actual manager reaped before remaining cleanup')
        send(work, {'command':'ping'});require(receive(work)['parent'] == os.getpid(), 'live adopted descendant')
        require(population(scope_fd), 'captured scope still populated after manager reap')
        records.append({'event':'manager_reaped_with_live_nested_payload','manager':leader,'payload':child})
        # No numeric PID/PGID signal is used here or in the stepped reclaimer.
        require(os.write(kill_fd, b'1') == 1, 'captured group kill after leader reap')
        require(select.select([pidfds[child]],[],[],5)[0], 'contained payload exit')
        pid, status = os.waitpid(child,0)
        require(pid == child and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL, 'actual recursive SIGKILL')
        require(not population(scope_fd), 'fresh quiescence after all fixture mutators ended')
        ping()
        cursor = reclaim_steps(scope_fd, root_fd, scope.name, device)
        for step in cursor:
            records.append(step);ping()
            if step['event']=='removed':break
        cursor.close()
        require(scope.exists(), 'root retained through interrupted directory progress')
        records.append({'event':'cursor_interrupted_root_handle_retained'})
        for step in reclaim_steps(scope_fd, root_fd, scope.name, device):records.append(step);ping()
        require(not scope.exists(), 'original root removed')
        make(scope);replacement = open_dir(scope);replacement_kill = open_kill(replacement)
        require(os.fstat(replacement).st_ino != old_inode, 'replacement root is a different kernel object')
        (scope/'cgroup.procs').write_text(str(unrelated))
        try:os.write(kill_fd,b'1')
        except OSError as error:require(error.errno == errno.ENODEV, 'removed control refuses old write');records.append({'event':'old_root_control_refused','errno':error.errno})
        else:raise RuntimeError('old root control unexpectedly accepted')
        ping();require(population(replacement), 'replacement remained live')
        os.write(replacement_kill,b'1');require(select.select([pidfds[unrelated]],[],[],5)[0], 'own replacement cleanup')
        pid,status = os.waitpid(unrelated,0);require(pid == unrelated and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL, 'replacement actual cleanup')
        require(not population(replacement), 'replacement empty');scope.rmdir();other_group.rmdir()
        print(json.dumps({'scope':'owned Linux kernel mechanism only','observations':records,
                          'unrelated_responses_between_cleanup_steps':pongs,
                          'captured_group_kill_after_leader_reap':True,
                          'interrupted_directory_cursor_resumed_on_same_root':True,
                          'old_handle_did_not_target_replacement':True,
                          'limits':['no forced numeric PID reuse','no Android MAC/init responsiveness proof','no hostile concurrent namespace mutation','fixture bounded tree, not a production walker'],
                          'combined_contract_qualified':False},indent=2))
    finally:
        for fd in kill_fds:
            try:os.write(fd,b'1')
            except OSError as error:
                if error.errno not in [errno.ENODEV,errno.ENOENT]:raise
        for fd in pidfds.values():
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
        until = time.monotonic()+5
        while True:
            try:pid,_ = os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:break
            if pid==0:
                require(time.monotonic()<until,'owned child cleanup deadline');time.sleep(.01)
        for path,inode in sorted(created.items(),key=lambda item:len(item[0].parts),reverse=True):
            if path.exists():
                require(path.stat().st_ino == inode,'only remove created object');path.rmdir()
        for channel in channels:channel.close()
        for fd in [*pidfds.values(),*fds]:os.close(fd)


if __name__ == '__main__':
    main()
