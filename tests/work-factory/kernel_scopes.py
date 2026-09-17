#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real Linux nested-cgroup mechanics in ONE explicitly delegated proof unit.

Not Android identity, init integration, a work-manager implementation or a backend verdict.
"""
import ctypes
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import time


def require(value, why):
    if not value:
        raise RuntimeError(why)


def receive(sock):
    require(select.select([sock], [], [], 5)[0], 'control deadline')
    data = sock.recv(4096)
    require(data, 'control EOF')
    return json.loads(data)


def send(sock, value):
    data = json.dumps(value).encode()
    require(len(data) < 4096 and sock.send(data) == len(data), 'bounded control write')


def membership():
    rows = [x.split(':', 2) for x in Path('/proc/self/cgroup').read_text().splitlines()]
    unified = [x[2] for x in rows if x[:2] == ['0', '']]
    require(len(unified) == 1, 'one real unified membership')
    return unified[0]


def identify():
    return dict(pid=os.getpid(), parent=os.getppid(), group=os.getpgrp(),
                session=os.getsid(0), cgroup=membership())


def payload(channel):
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(40)
    send(channel, dict(event='ready', **identify()))
    require(receive(channel) == {'command': 'release'}, 'closed payload gate')
    send(channel, dict(event='released', **identify()))
    while True:
        command = receive(channel)
        if command == {'command': 'ping'}:
            send(channel, dict(event='pong', **identify()))
        else:
            os._exit(122)


def manager(control, workers):
    os.setsid()
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(40)
    send(control, dict(event='manager_ready', **identify()))
    require(receive(control) == {'command': 'spawn'}, 'manager admission gate')
    children = []
    for index, channel in enumerate(workers):
        child = os.fork()
        if child == 0:
            control.close()
            for other in workers:
                if other is not channel:
                    other.close()
            payload(channel)
            os._exit(123)
        children.append(child)
        channel.close()
    send(control, dict(event='children', children=children))
    require(receive(control) == {'command': 'reap_a'}, 'exact first-child control')
    pid, status = os.waitpid(children[0], 0)
    send(control, dict(event='reaped_a', pid=pid, status=status))
    require(receive(control) == {'command': 'exit'}, 'manager exit control')
    os._exit(37)


def populated(group):
    values = dict(line.split() for line in (group/'cgroup.events').read_text().splitlines())
    require(values.get('populated') in ('0', '1'), 'kernel populated observation')
    return values['populated'] == '1'


def wait_empty(group):
    end = time.monotonic() + 5
    while populated(group):
        require(time.monotonic() < end, 'empty-group deadline')
        time.sleep(.01)


def main():
    # DelegateSubgroup places the unchanged heavy-admission helper and this observer
    # in control. Only this proof unit's fresh descendants are manipulated below.
    own = Path('/sys/fs/cgroup') / membership().lstrip('/')
    root = own.parent
    require(own.name == 'control' and re.fullmatch(r'andrix-factory-kernel-[0-9]{8}t[0-9]{6}z\.service', root.name),
            'refusing a cgroup outside the exact proof-unit shape')
    require(root.resolve() == root and root.is_relative_to('/sys/fs/cgroup/user.slice'), 'real owned hierarchy')
    require((root/'memory.max').read_text().strip() == str(512*1024**2), 'job memory bound')
    require((root/'memory.swap.max').read_text().strip() == '0', 'job zero swap')
    require((root/'cpu.max').read_text().strip() == '200000 100000', 'job CPU bound')
    require((root/'pids.max').read_text().strip() == '128', 'job task bound')
    require(resource.getrlimit(resource.RLIMIT_CORE) == (0,0), 'inherited zero core limits')
    require('memory' in (root/'cgroup.controllers').read_text().split(), 'available delegated memory controller')
    require(os.stat(root/'cgroup.procs').st_uid == os.getuid(), 'owned delegated controls')
    require((root/'cgroup.procs').read_text().strip() == '', 'helper and observer remain in control subgroup')
    (root/'cgroup.subtree_control').write_text('+memory')
    require('memory' in (root/'cgroup.subtree_control').read_text().split(), 'explicit delegated activation')
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, 'private subreaper')
    created = []
    handles = {}
    channels = []
    group_fds = []
    records = []
    scope = root/'fixture'
    try:
        for path in [scope, scope/'control', scope/'work_a', scope/'work_b']:
            path.mkdir();created.append(path)
        parent, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        a, child_a = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        b, child_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channels.extend([parent, child_control, a, child_a, b, child_b])
        child = os.fork()
        if child == 0:
            parent.close();a.close();b.close()
            try:
                manager(child_control, [child_a, child_b])
            except BaseException:
                os._exit(121)
        child_control.close();child_a.close();child_b.close()
        handles[child] = os.pidfd_open(child)
        hello = receive(parent);require(hello['pid'] == child, 'owned manager ready')
        (scope/'cgroup.procs').write_text(str(child))
        # Controller activation with an internal process must not be assumed possible.
        try:
            (scope/'cgroup.subtree_control').write_text('+memory')
        except OSError as error:
            records.append(dict(event='internal_process_activation_refused', errno=error.errno))
        else:
            raise RuntimeError('memory controller admitted internal process unexpectedly')
        require(not (scope/'work_a/memory.max').exists(), 'controller absent before activation')
        (scope/'control/cgroup.procs').write_text(str(child))
        (scope/'cgroup.subtree_control').write_text('+memory')
        for work in ['work_a', 'work_b']:
            (scope/work/'memory.max').write_text(str(128*1024**2))
            (scope/work/'memory.swap.max').write_text('0')
            (scope/work/'memory.oom.group').write_text('1')
        send(parent, {'command':'spawn'})
        announced = receive(parent);require(announced['event'] == 'children', 'manager child list')
        held = [receive(a), receive(b)]
        require([x['pid'] for x in held] == announced['children'], 'actual forked child observations')
        for row, name, channel in zip(held, ['work_a', 'work_b'], [a,b]):
            pid = row['pid'];handles[pid] = os.pidfd_open(pid)
            require(row['group'] == row['session'] == pid and pid != child, 'own detached session')
            (scope/name/'cgroup.procs').write_text(str(pid))
            send(channel, {'command':'release'})
            released = receive(channel)
            require(released['cgroup'] == '/' + (scope/name).relative_to('/sys/fs/cgroup').as_posix(),
                    'actual admitted subgroup membership')
            records.append(dict(event='released', name=name, pid=pid, session=released['session']))
        require((scope/'cgroup.procs').read_text().strip() == '', 'parent procs is not recursive')
        require(populated(scope), 'parent events accounts for descendants')
        old_a = os.open(scope/'work_a', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        old_kill = os.open('cgroup.kill', os.O_WRONLY | os.O_CLOEXEC, dir_fd=old_a)
        group_fds.extend([old_a, old_kill])
        old_inode = os.fstat(old_a).st_ino
        require(os.write(old_kill, b'1') == 1, 'exact captured group kill')
        require(select.select([handles[held[0]['pid']]], [], [], 5)[0], 'first payload exit')
        send(parent, {'command':'reap_a'});status = receive(parent)
        require(status['pid'] == held[0]['pid'] and os.WIFSIGNALED(status['status']) and
                os.WTERMSIG(status['status']) == signal.SIGKILL, 'actual individual group kill')
        wait_empty(scope/'work_a');(scope/'work_a').rmdir();created.remove(scope/'work_a')
        (scope/'work_a').mkdir();created.append(scope/'work_a')
        require((scope/'work_a').stat().st_ino != old_inode, 'replacement path is a different kernel object')
        try:
            os.write(old_kill, b'1')
        except OSError as error:
            records.append(dict(event='old_open_control_rejected_after_path_reuse', errno=error.errno))
        else:
            raise RuntimeError('removed group control unexpectedly accepted a write')
        try:
            stale = os.open('cgroup.kill', os.O_WRONLY | os.O_CLOEXEC, dir_fd=old_a)
        except OSError as error:
            records.append(dict(event='old_directory_handle_does_not_resolve_replacement', errno=error.errno))
        else:
            os.close(stale);raise RuntimeError('removed directory unexpectedly resolved a control')
        send(b, {'command':'ping'});require(receive(b)['pid'] == held[1]['pid'], 'unrelated group remains live')
        records.append(dict(event='independent_group_kill_with_live_b', first_wait_status=status['status']))
        send(parent, {'command':'exit'})
        require(select.select([handles[child]], [], [], 5)[0], 'manager exit')
        info = os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
        require(info.si_pid == child and info.si_status == 37, 'manager exit retained unreaped')
        send(b, {'command':'ping'});survivor = receive(b)
        require(survivor['parent'] == os.getpid(), 'private subreaper adopted live descendant')
        require((scope/'cgroup.procs').read_text().strip() == '' and populated(scope), 'nested work not in parent procs')
        # The kernel operation used by the available cgroup.kill path, not a model of it.
        (scope/'cgroup.kill').write_text('1')
        require(select.select([handles[held[1]['pid']]], [], [], 5)[0], 'recursive kernel kill')
        pid, status = os.waitpid(held[1]['pid'], 0)
        require(pid == held[1]['pid'] and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
                'recursive kill actual wait status')
        wait_empty(scope)
        stat = Path(f'/proc/{child}/stat').read_text()
        require(stat.rsplit(')',1)[1].split()[0] == 'Z', 'manager PID still pinned during cleanup')
        try:
            scope.rmdir()
        except OSError as error:
            records.append(dict(event='parent_rmdir_with_empty_children_refused', errno=error.errno,
                                populated=False, manager_PID_still_pinned=True))
        else:
            raise RuntimeError('parent unexpectedly removed with child directories')
        before = scope.stat().st_ino
        scope.mkdir(exist_ok=True)
        require(scope.stat().st_ino == before, 'EEXIST is not a fresh group identity')
        records.append(dict(event='existing_path_keeps_same_inode', old_inode=before))
        for path in [scope/'work_b', scope/'work_a', scope/'control', scope]:
            path.rmdir();created.remove(path)
        got, status = os.waitpid(child,0);require(got == child and os.WIFEXITED(status) and os.WEXITSTATUS(status)==37,
                                               'reap after complete directory cleanup')
        records.append(dict(event='recursive_process_kill_and_explicit_directory_cleanup_completed'))
        print(json.dumps({'scope':'Linux host kernel only; Android backends unqualified',
                          'observations':records,'backend_A_qualified':False,'backend_B_qualified':False},indent=2))
    finally:
        for fd in handles.values():
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
        if scope.exists():
            try:(scope/'cgroup.kill').write_text('1');wait_empty(scope)
            except OSError:pass
        until=time.monotonic()+5
        while True:
            try:pid,_=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:break
            if pid==0:
                require(time.monotonic()<until,'private child reaping deadline');time.sleep(.01)
        for path in reversed(created):
            path.rmdir()
        for channel in channels:channel.close()
        for fd in handles.values():os.close(fd)
        for fd in group_fds:os.close(fd)


if __name__ == '__main__':
    main()
