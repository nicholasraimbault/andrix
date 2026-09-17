#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test the actual native group observer on a delegated Linux kernel group, not Android."""
from pathlib import Path
import json
import os
import re
import select
import signal
import subprocess
import sys


def require(value, text):
    if not value:
        raise RuntimeError(text)


def main():
    rows = [line.split(':', 2) for line in Path('/proc/self/cgroup').read_text().splitlines()]
    memberships = [row[2] for row in rows if row[:2] == ['0', '']]
    require(len(memberships) == 1, 'one actual membership')
    own = Path('/sys/fs/cgroup') / memberships[0].lstrip('/')
    root = own.parent
    require(own.name == 'control' and re.fullmatch(r'andrix-factory-kernel-[0-9]{8}t[0-9]{6}z\.service', root.name), 'owned delegation only')
    require(root.resolve() == root and root.is_relative_to('/sys/fs/cgroup/user.slice'), 'real delegated hierarchy')
    require((root/'memory.max').read_text().strip() == str(512*1024**2), 'job memory bound')
    require((root/'memory.swap.max').read_text().strip() == '0', 'job zero swap')
    require(len(sys.argv) == 2, 'explicit frozen observer binary')
    path = root/'observation'
    path.mkdir()
    group = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(gate_write)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(30)
        os.read(gate_read, 1)
        os._exit(0)
    os.close(gate_read)
    child_fd = os.pidfd_open(child)
    observer = None
    results = []
    try:
        (path/'cgroup.procs').write_text(str(child))
        observer = subprocess.Popen([sys.argv[1], str(group)], pass_fds=(group,),
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def observed(expected, command=None):
            if command:
                observer.stdin.write(command);observer.stdin.flush()
            require(select.select([observer.stdout], [], [], 5)[0], 'native observer deadline')
            value = observer.stdout.readline().decode().strip()
            require(value == expected, 'native observation '+repr((value, expected)))
            results.append(value)
        observed('populated')
        event_mode = (path/'cgroup.events').stat().st_mode & 0o777
        try:
            os.chmod(path/'cgroup.events', 0)
            observed('unknown', b'r')
        finally:
            os.chmod(path/'cgroup.events', event_mode)
        observed('populated', b'r')
        (path/'cgroup.kill').write_text('1')
        pid, status = os.waitpid(child, 0)
        require(pid == child and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, 'actual SIGKILL')
        child = 0
        observed('empty', b'r')
        old_inode = os.fstat(group).st_ino
        path.rmdir()
        observed('removed', b'r')
        path.mkdir()
        require(path.stat().st_ino != old_inode, 'replacement kernel object')
        observed('removed', b'r')
        observer.stdin.write(b'q');observer.stdin.flush()
        require(observer.wait(timeout=5) == 0, 'native observer completed')
        path.rmdir()
        print(json.dumps({'native_observations':results,'replacement_not_retargeted':True,
                          'invalid_and_non_cgroup_descriptors_unknown':True,
                          'permission_denial_remains_unknown':True,
                          'Android_runtime_qualified':False},indent=2))
    finally:
        if observer is not None and observer.poll() is None:
            observer.kill();observer.wait(timeout=5)
        if child:
            try:signal.pidfd_send_signal(child_fd, signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(child, 0)
        os.close(gate_write);os.close(child_fd);os.close(group)
        if path.exists():path.rmdir()


if __name__ == '__main__':
    main()
