#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One isolated Linux lifetime experiment. Not Android authority or cleanup proof."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import secrets
import shlex
import signal
import socket
import struct
import subprocess
import tempfile
import time

BOUND = 6.0
CASES = ('pty_hangup', 'last_master', 'ignored_hup', 'parent_exit', 'setsid_scope',
         'bash_hangup', 'bash_nohup', 'bash_disown', 'bash_exit', 'bash_login_exit')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def readable(fd, timeout=BOUND):
    require(select.select([fd], [], [], timeout)[0], 'observation deadline')


class Fixture:
    def __init__(self, binary):
        self.binary = str(Path(binary).resolve())
        self.handles = {}
        self.processes = {}
        self.sockets = []
        self.fds = set()
        self.masters = set()
        self.records = []
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(36, 1, 0, 0, 0) == 0, 'private subreaper setup')

    def pair(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sockets.extend((a, b))
        require(max(a.fileno(), b.fileno()) < 64, 'fixture descriptor bound')
        return a, b

    def track(self, pid):
        require(pid > 1, 'valid owned PID')
        if pid not in self.handles:
            self.handles[pid] = os.pidfd_open(pid)

    def receive(self, channel):
        readable(channel)
        data = channel.recv(2048)
        require(data, 'control channel ended before acknowledgement')
        record = json.loads(data)
        require(record['event'] in ('ready', 'pong', 'write'), 'control event')
        require(record['nnp'] == 1 and record['filter'] == 2, 'worker filter missing')
        self.records.append(record)
        return record

    def request(self, channel, command):
        require(channel.send(command.encode()) == 1, 'control send')
        result = self.receive(channel)
        require(result['event'] == ('write' if command == 'W' else 'pong'), 'matching response')
        return result

    def pty(self):
        master, slave = os.openpty()
        self.fds.update((master, slave))
        self.masters.add(master)
        return master, slave

    def close(self, fd):
        os.close(fd)
        self.fds.remove(fd)

    def spawn(self, args, passed, slave=None, env=None):
        stdio = subprocess.DEVNULL if slave is None else slave
        proc = subprocess.Popen(args, stdin=stdio, stdout=stdio, stderr=stdio,
                                pass_fds=tuple(passed), start_new_session=True, env=env)
        self.processes[proc.pid] = proc
        self.track(proc.pid)
        if slave is not None:
            self.close(slave)
        return proc.pid

    def exited(self, pid):
        readable(self.handles[pid])
        # A shell may reap its child before exiting. pidfd exit is still observed,
        # but only a successful waitpid supplies the descendant's exit status.
        try:
            got, status = os.waitpid(pid, 0)
            require(got == pid, 'owned wait result')
        except ChildProcessError:
            status = None
        if pid in self.processes:
            self.processes[pid].returncode = 0 if status is None else os.waitstatus_to_exitcode(status)
        self.records.append({'event': 'exit', 'pid': pid, 'wait_status': status})
        return status

    def quit(self, pid, channel):
        require(channel.send(b'Q') == 1, 'quit send')
        status = self.exited(pid)
        require(status is not None and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                'adopted child clean exit')

    def empty(self):
        try:
            result = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            self.records.append({'event': 'empty', 'ECHILD': True})
            return
        raise RuntimeError(f'subreaper not empty: {result}')

    def diagnostics(self):
        for fd in self.masters & self.fds:
            if select.select([fd], [], [], 0)[0]:
                try:
                    data = os.read(fd, 4096)
                except OSError as error:
                    data = str(error).encode()
                self.records.append({'event': 'failure_pty', 'text': data.decode(errors='replace')})

    def cleanup(self):
        # Signal captured identities, not PID/PGID lookups. A dead pidfd cannot
        # target a reused PID, including a shell child already reaped by Bash.
        for fd in self.handles.values():
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + BOUND
        while True:
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    pid = -1
                if pid <= 0:
                    break
                if pid in self.processes:
                    self.processes[pid].returncode = 0
            if pid == -1:
                break
            # Only unreaped direct children of this isolated subreaper. Their
            # identities remain pinned until THIS process calls waitpid. This
            # handles setup failure before a worker's ready message was received.
            direct = Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()
            for item in direct:
                child = int(item)
                if child not in self.handles:
                    self.track(child)
                try:
                    signal.pidfd_send_signal(self.handles[child], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            require(time.monotonic() < deadline, 'private child cleanup deadline')
            time.sleep(.005)  # Bounded reaping loop, never a survival/readiness assertion.
        for proc in self.processes.values():
            if proc.returncode is None:
                proc.returncode = 0
        for sock in self.sockets:
            sock.close()
        for fd in self.fds | set(self.handles.values()):
            os.close(fd)


def native_case(f, case):
    control, peer = f.pair()
    if case in ('pty_hangup', 'last_master', 'ignored_hup'):
        master, slave = f.pty()
        pid = f.spawn([f.binary, 'terminal', str(peer.fileno()),
                       'ignore' if case == 'ignored_hup' else 'default'], [peer.fileno()], slave)
        peer.close()
        ready = f.receive(control)
        require(ready['pid'] == pid == ready['sid'] == ready['pgid'], 'terminal identity')
        require(ready['hup_ignored'] == (case == 'ignored_hup'), 'HUP disposition')
        if case == 'last_master':
            other = os.dup(master)
            f.fds.add(other)
            f.close(master)
            f.request(control, 'P')
            require(f.request(control, 'W')['written'] > 0, 'terminal write after one master closes')
            readable(other)
            require(b'WORK_LIFETIME_OUTPUT' in os.read(other, 1024), 'actual surviving PTY output')
            f.close(other)
        else:
            f.close(master)
        if case == 'ignored_hup':
            require(f.request(control, 'P')['pid'] == pid, 'ignored HUP survival')
            output = f.request(control, 'W')
            require(output['written'] == -1 and output['error'] == errno.EIO,
                    'ignored HUP did not restore terminal transport')
            f.quit(pid, control)
        else:
            status = f.exited(pid)
            require(status is not None and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGHUP,
                    'last PTY master caused actual SIGHUP termination')
        f.empty()
        return

    job, job_peer = f.pair()
    master, slave = f.pty() if case == 'setsid_scope' else (None, None)
    parent = f.spawn([f.binary, 'parent', str(peer.fileno()), str(job_peer.fileno()),
                      'detached' if case == 'setsid_scope' else 'ordinary'],
                     [peer.fileno(), job_peer.fileno()], slave)
    peer.close()
    job_peer.close()
    leader = f.receive(control)
    child = f.receive(job)
    require(leader['pid'] == parent and leader['child'] == child['pid'] and child['ppid'] == parent,
            'owned descendant identity')
    f.track(child['pid'])
    require(leader['pdeathsig'] == signal.SIGKILL and child['pdeathsig'] == 0,
            'parent death signal is cleared by fork')
    require(child['cgroup'] == leader['cgroup'], 'fork/setsid retained observed cgroup membership')
    if case == 'setsid_scope':
        require(child['sid'] == child['pgid'] == child['pid'] and child['sid'] != leader['sid'],
                'detached child made its own Unix session')
    else:
        require(child['sid'] == leader['sid'] and child['pgid'] == leader['pgid'], 'ordinary child session')
    f.quit(parent, control)
    if master is not None:
        f.close(master)
    alive = f.request(job, 'P')
    require(alive['ppid'] == os.getpid() and alive['pid'] == child['pid'], 'subreaper adopted live child')
    require(alive['cgroup'] == child['cgroup'], 'parent death did not change cgroup membership')
    require(os.waitpid(-1, os.WNOHANG) == (0, 0), 'live child is not an empty scope')
    if case == 'setsid_scope':
        require(f.request(job, 'W')['written'] > 0, 'redirected standard output survives')
    f.quit(child['pid'], job)
    f.empty()


def shell_case(f, case, bash, nohup):
    with tempfile.TemporaryDirectory(prefix='andrix-shell-lifetime-') as directory:
        output = Path(directory) / 'output'
        name = 'andrix-lifetime-' + secrets.token_hex(16)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        f.sockets.append(listener)
        listener.bind('\0' + name)
        listener.listen(1)
        ack_read, ack_write = os.pipe()
        f.fds.update((ack_read, ack_write))
        require(ack_write < 64, 'shell acknowledgement descriptor bound')
        master, slave = f.pty()
        env = dict(PATH='/usr/bin:/bin', HOME=directory, LANG='C', PS1='', PS2='',
                   HISTFILE='/dev/null', PROMPT_COMMAND='')
        # The selected login shell marks inherited auxiliary FDs close-on-exec.
        # Establish the private observation channel AFTER exec instead of changing
        # shell policy or pretending a lost observer is a dead background job.
        command = f'{shlex.quote(f.binary)} connect-job {shlex.quote(name)}'
        if case == 'bash_nohup':
            command = f'{shlex.quote(nohup)} ' + command
        line = ('set -m; shopt ' + ('-s' if case == 'bash_login_exit' else '-u') +
                ' huponexit; ' + command + f' </dev/null >{shlex.quote(str(output))} 2>&1 & ' +
                ('disown; ' if case == 'bash_disown' else '') +
                f'printf R >&{ack_write}; IFS= read -r fixture_exit; exit')
        require(len(line) < 2048, 'bounded shell setup command')
        # Supply setup through exact argv, not terminal typeahead before the
        # shell has initialized its terminal. Only send input after both a real
        # worker handshake and the shell's private acknowledgement.
        args = [f.binary, 'shell', str(ack_write), str(ack_write), bash,
                'login' if case == 'bash_login_exit' else 'ordinary', line]
        parent = f.spawn(args, [ack_write], slave, env)
        f.close(ack_write)
        try:
            readable(listener)
            control, _ = listener.accept()
            f.sockets.append(control)
            peer_pid, peer_uid, _ = struct.unpack('3i', control.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            ready = f.receive(control)
            require(ready['pid'] == peer_pid and peer_uid == os.getuid(), 'actual helper peer identity')
        except Exception:
            if output.exists():
                with output.open('rb') as stream:
                    f.records.append({'event': 'failure_job_output',
                                      'text': stream.read(4096).decode(errors='replace')})
            raise
        f.track(ready['pid'])
        require(ready['ppid'] == parent and ready['pgid'] != parent, 'actual shell background job')
        require(ready['hup_ignored'] == (case == 'bash_nohup'), 'inherited shell/nohup HUP disposition')
        readable(ack_read)
        require(os.read(ack_read, 1) == b'R', 'shell acknowledged job table/disown setup')
        f.close(ack_read)
        if case in ('bash_exit', 'bash_login_exit'):
            require(os.write(master, b'exit\n') == 5, 'explicit shell exit')
        else:
            f.close(master)
        shell_status = f.exited(parent)
        require(shell_status is not None, 'shell wait status')
        if case in ('bash_exit', 'bash_login_exit'):
            require(os.WIFEXITED(shell_status) and os.WEXITSTATUS(shell_status) == 0, 'ordinary shell exit')
            f.close(master)
        else:
            require(os.WIFSIGNALED(shell_status) and os.WTERMSIG(shell_status) == signal.SIGHUP,
                    'physical hangup killed actual shell')
        if case in ('bash_hangup', 'bash_login_exit'):
            status = f.exited(ready['pid'])
            if status is not None:
                require(os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGHUP, 'job HUP wait status')
            # If Bash reaped the job, do NOT manufacture a wait status from pidfd readiness.
        else:
            alive = f.request(control, 'P')
            require(alive['ppid'] == os.getpid(), 'surviving shell job adopted')
            require(alive['cgroup'] == ready['cgroup'], 'shell loss preserves cgroup membership')
            require(f.request(control, 'W')['written'] > 0, 'redirected shell-job output works')
            require(output.read_bytes() == b'WORK_LIFETIME_OUTPUT\n', 'real file output')
            f.quit(ready['pid'], control)
        f.empty()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--case', required=True, choices=CASES)
    parser.add_argument('--bash', default='/bin/bash')
    parser.add_argument('--nohup', default='/usr/bin/nohup')
    args = parser.parse_args()
    f = Fixture(args.binary)
    try:
        if args.case.startswith('bash_'):
            shell_case(f, args.case, args.bash, args.nohup)
        else:
            native_case(f, args.case)
    except Exception as error:
        f.diagnostics()
        print(json.dumps({'case': args.case, 'status': 'FAILED', 'error': str(error),
                          'observations': f.records, 'Android_qualified': False}), flush=True)
        raise
    finally:
        f.cleanup()
    print(json.dumps({'case': args.case, 'observations': f.records,
                      'scope': 'Linux host kernel and selected shell only; Android unqualified',
                      'complete_work_group_cleanup_proved': False}))


if __name__ == '__main__':
    main()
