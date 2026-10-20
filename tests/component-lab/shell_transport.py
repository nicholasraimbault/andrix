# SPDX-License-Identifier: Apache-2.0
"""The broker's transport to one guest through the host's adb server.

Three services, each with its own completion form:

- **shell**, protocol v2 in raw mode, `shell,v2,raw:<command>`. The daemon frames standard output,
  standard error and the exit status separately: a one byte packet ID and a four byte little endian
  length, then the payload. IDs 1 stdout, 2 stderr, 3 exit, whose payload is one byte. It sends
  one EXIT packet after the process ends and then closes the stream. A remote exit status is
  known only from exactly one well formed EXIT packet followed by a clean end of stream. Anything
  else, an end of stream before EXIT, a packet cut short, a second EXIT, an EXIT of another
  length, an unknown packet, a packet after EXIT, a stream above its bound or a timeout, leaves the
  status unknown. A transport or launch failure is reported as such, never as a remote status, so
  an adb error never becomes a quiet remote 1.
- **reboot**, `reboot:`. It has no shell protocol and no exit status. The server's OKAY says that
  the daemon accepted the request; the daemon then waits for the reboot and the stream ends when the
  guest goes down, or it writes a failure message. The new boot ID, read later, is what resolves a
  reboot. The acknowledgement is supplemental evidence only.
- **sync**, `sync:`, version 1 SEND of one file: SEND with "path,mode", DATA chunks of at most
  64 KiB, DONE with the modification time, then OKAY or FAIL with a message, then QUIT. A push is
  staging, and the broker verifies the pushed bytes with a separate digest read.

The smart socket host protocol: a request is four lowercase hexadecimal digits of length and the
payload; the reply is OKAY, or FAIL with four hexadecimal digits of length and a message. A
transport service first selects the device with `host:tport:serial:<serial>`, whose OKAY is
followed by an eight byte transport ID. Features come from `host-serial:<serial>:features`. The
broker requires `shell_v2` and never falls back to protocol 1 or a PTY.

These forms come from the pinned adb client sources and the daemon's shell service. The service
argument names `v2` and `raw` are the pinned client's constants, outside this package's inspected
scope, so a guest check must confirm the shell form before any mutation. Host evidence only."""
from dataclasses import dataclass
import socket
import struct
import time

SHELL_PREFIX = 'shell,v2,raw:'
REBOOT_SERVICE = 'reboot:'
SYNC_SERVICE = 'sync:'
FEATURE_SHELL2 = 'shell_v2'
ID_STDIN, ID_STDOUT, ID_STDERR, ID_EXIT, ID_CLOSE_STDIN, ID_WINDOW = 0, 1, 2, 3, 4, 5
PACKET_HEADER = 5
RESIDUAL_MAX = 4096
SYNC_DATA_MAX = 64 * 1024
MAX_REQUEST = 0xffff
MAX_FAIL_MESSAGE = 64 * 1024
REBOOT_MESSAGE_MAX = 4096
# The private input a constant command may be given on its standard input, in one STDIN packet.
PRIVATE_INPUT_MAX = 4096


class _Timeout(Exception):
    pass


class _SendFailed(Exception):
    """Transmission began and failed: the peer may hold the whole request."""

    def __init__(self, transport, detail):
        super().__init__(detail)
        self.transport = transport


class _Ended(Exception):
    """The stream ended before the bytes a step needed."""


class ShellV2Decoder:
    """Incremental decoder of the daemon's shell protocol v2 stream.

    `feed` takes bytes as they arrive, in any split. `end` is called at the end of the stream.
    Standard output and standard error are kept apart, each within its bound. The state is open,
    exited after one well formed EXIT packet, malformed, or overflow. Malformed and overflow are
    final: the caller stops reading and the exit status stays unknown.

    When the stream stops inside a stdout or stderr packet, `salvage` keeps the payload bytes
    already received in that packet's stream, within its bound, and names the stream in
    `partial_stream`. The bytes of a cut header, or of a cut EXIT packet, stay in `residual`. Salvage
    never completes anything: the status stays unknown."""

    def __init__(self, stdout_max, stderr_max):
        self.stdout, self.stderr = bytearray(), bytearray()
        self.limits = {ID_STDOUT: stdout_max, ID_STDERR: stderr_max}
        self.buffer = bytearray()
        self.state = 'open'
        self.exit_frame = None
        self.problem = None
        self.overflow = None
        self.partial = False
        self.partial_stream = None
        self.residual = b''
        self.residual_bytes = 0
        self._salvaged = False

    def _final(self, state, problem):
        self.state, self.problem = state, problem

    def feed(self, data):
        if self.state in ('malformed', 'overflow'):
            return
        self.buffer += data
        while len(self.buffer) >= PACKET_HEADER and self.state not in ('malformed', 'overflow'):
            ident = self.buffer[0]
            length = struct.unpack('<I', bytes(self.buffer[1:PACKET_HEADER]))[0]
            if self.state == 'exited':
                self._final('malformed', 'a second EXIT packet' if ident == ID_EXIT else 'a packet after EXIT')
                return
            if ident == ID_EXIT:
                if length != 1:
                    self._final('malformed', 'an EXIT packet of length %d' % length)
                    return
            elif ident in self.limits:
                stream = self.stdout if ident == ID_STDOUT else self.stderr
                if len(stream) + length > self.limits[ident]:
                    self.overflow = 'stdout' if ident == ID_STDOUT else 'stderr'
                    self._final('overflow', '%s above its bound of %d bytes' % (self.overflow, self.limits[ident]))
                    return
            else:
                self._final('malformed', 'an unknown packet ID %d' % ident)
                return
            if len(self.buffer) < PACKET_HEADER + length:
                return
            payload = bytes(self.buffer[PACKET_HEADER:PACKET_HEADER + length])
            del self.buffer[:PACKET_HEADER + length]
            if ident == ID_EXIT:
                self.exit_frame = payload[0]
                self.state = 'exited'
            elif ident == ID_STDOUT:
                self.stdout += payload
            else:
                self.stderr += payload

    def end(self):
        """The completion at a clean end of stream."""
        if self.state in ('malformed', 'overflow'):
            return self.state
        if self.buffer:
            self.partial = True
            if self.state == 'exited':
                self._final('malformed', 'bytes after EXIT')
                self.salvage()
                return self.state
            self.problem = 'the stream ended inside a packet'
            self.salvage()
            return 'eof-before-exit'
        if self.state == 'exited':
            return 'exited'
        self.problem = 'the stream ended before EXIT'
        return 'eof-before-exit'

    def salvage(self):
        """Keeps what the stream gave of a packet cut short, once: payload bytes of a stdout or
        stderr packet in their stream, every other undecoded byte as residual. Completion is
        unchanged."""
        if self._salvaged or not self.buffer:
            return
        self._salvaged = True
        self.partial = True
        data = bytes(self.buffer)
        del self.buffer[:]
        if self.state == 'open' and len(data) >= PACKET_HEADER and data[0] in self.limits:
            ident = data[0]
            payload = data[PACKET_HEADER:]
            stream = self.stdout if ident == ID_STDOUT else self.stderr
            # The packet's whole length passed its bound check before its payload was awaited, so its
            # received part fits. The check is repeated rather than assumed.
            if len(stream) + len(payload) <= self.limits[ident]:
                stream += payload
                self.partial_stream = 'stdout' if ident == ID_STDOUT else 'stderr'
                data = data[:PACKET_HEADER]
        self.residual_bytes = len(data)
        self.residual = data[:RESIDUAL_MAX]


@dataclass(frozen=True)
class ShellResult:
    """One shell command's outcome. `launch` is not-launched, unknown or launched. `transport` is
    ok or the failure that ended the call. `completion` is exited only with one well formed EXIT
    packet and a clean end of stream; `exit` is the remote status only then."""
    service: str
    launch: str
    transport: str
    completion: str
    exit_frame: object
    stdout: bytes
    stderr: bytes
    overflow: object
    partial_frame: bool
    fail_message: object
    error: object
    started_wall_ns: int
    ended_wall_ns: int
    duration_ns: int
    partial_stream: object = None
    residual: bytes = b''
    residual_bytes: int = 0

    @property
    def exit(self):
        return self.exit_frame if self.completion == 'exited' else None

    @property
    def completed(self):
        return self.completion == 'exited'

    def streams(self):
        return self.stdout, self.stderr

    def summary(self):
        """Every field except the streams, for the capture ledger."""
        return {'service': self.service, 'launch': self.launch, 'transport': self.transport,
                'completion': self.completion, 'exit': self.exit, 'exit_frame': self.exit_frame,
                'overflow': self.overflow, 'partial_frame': self.partial_frame, 'partial_stream': self.partial_stream,
                'residual_hex': self.residual.hex(), 'residual_bytes': self.residual_bytes,
                'fail_message': None if self.fail_message is None else self.fail_message.decode('ascii', 'replace'),
                'error': self.error, 'started_wall_ns': self.started_wall_ns, 'ended_wall_ns': self.ended_wall_ns,
                'duration_ns': self.duration_ns}


@dataclass(frozen=True)
class RebootResult:
    """The reboot service's acknowledgement. `acknowledgement` is accepted, refused or none; it
    has no exit status. `stream_end` says how the stream ended after an acceptance."""
    launch: str
    transport: str
    acknowledgement: str
    stream_end: str
    message: bytes
    fail_message: object
    error: object
    started_wall_ns: int
    ended_wall_ns: int
    duration_ns: int

    def streams(self):
        return self.message, b''

    def summary(self):
        return {'service': REBOOT_SERVICE, 'launch': self.launch, 'transport': self.transport,
                'acknowledgement': self.acknowledgement, 'stream_end': self.stream_end,
                'message': self.message.decode('ascii', 'replace'),
                'fail_message': None if self.fail_message is None else self.fail_message.decode('ascii', 'replace'),
                'error': self.error, 'started_wall_ns': self.started_wall_ns, 'ended_wall_ns': self.ended_wall_ns,
                'duration_ns': self.duration_ns}


@dataclass(frozen=True)
class PushResult:
    """One sync push. `status` is ok only on the daemon's OKAY after DONE."""
    path: str
    size: int
    launch: str
    transport: str
    status: str
    fail_message: object
    error: object
    started_wall_ns: int
    ended_wall_ns: int
    duration_ns: int

    def streams(self):
        return b'', b''

    def summary(self):
        return {'service': SYNC_SERVICE, 'path': self.path, 'size': self.size, 'launch': self.launch,
                'transport': self.transport, 'status': self.status,
                'fail_message': None if self.fail_message is None else self.fail_message.decode('ascii', 'replace'),
                'error': self.error, 'started_wall_ns': self.started_wall_ns, 'ended_wall_ns': self.ended_wall_ns,
                'duration_ns': self.duration_ns}


@dataclass(frozen=True)
class FeaturesResult:
    """The device's feature list through the server. `status` is ok, failed (FAIL), connect-failed,
    launch-deadline (nothing sent) or unknown."""
    status: str
    features: tuple
    fail_message: object
    error: object

    def streams(self):
        return ','.join(self.features).encode('ascii'), b''

    def summary(self):
        return {'service': 'host-serial:<serial>:features', 'status': self.status, 'features': list(self.features),
                'fail_message': None if self.fail_message is None else self.fail_message.decode('ascii', 'replace'),
                'error': self.error}


def tcp_connector(host, port):
    """A connector to an adb server's TCP socket."""
    def connect(timeout):
        return socket.create_connection((host, port), timeout=timeout)
    return connect


class AdbClient:
    """One device through an adb server. `connect(timeout)` returns a fresh connected socket.
    Every call has one deadline. Nothing is retried here: the broker decides."""

    def __init__(self, serial, connect, monotonic=time.monotonic_ns, wall=time.time_ns):
        if not serial or any(ord(c) < 0x21 or ord(c) > 0x7e for c in serial):
            raise ValueError('a device serial is printable ASCII without spaces')
        self.serial, self._connect, self._monotonic, self._wall = serial, connect, monotonic, wall

    # ------------------------------------------------ host protocol

    def _remaining(self, deadline):
        left = (deadline - self._monotonic()) / 1e9
        if left <= 0:
            raise _Timeout()
        return left

    def _send(self, sock, deadline, payload):
        """Sends one host request. Raises _Timeout when the deadline passed before transmission,
        and _SendFailed when transmission began and did not finish."""
        data = payload.encode('ascii')
        if len(data) > MAX_REQUEST:
            raise ValueError('a host request above its bound')
        sock.settimeout(self._remaining(deadline))
        try:
            sock.sendall(b'%04x' % len(data) + data)
        except socket.timeout as error:
            raise _SendFailed('timeout', 'the request was not sent whole within its bound') from error
        except OSError as error:
            raise _SendFailed('io-error', '%s: %s' % (type(error).__name__, error)) from error

    def _recv_exact(self, sock, deadline, count):
        out = bytearray()
        while len(out) < count:
            sock.settimeout(self._remaining(deadline))
            try:
                chunk = sock.recv(count - len(out))
            except socket.timeout as error:
                raise _Timeout() from error
            if not chunk:
                raise _Ended()
            out += chunk
        return bytes(out)

    def _status(self, sock, deadline):
        """('OKAY', None), ('FAIL', message) or raises ProtocolFault for any other status."""
        status = self._recv_exact(sock, deadline, 4)
        if status == b'OKAY':
            return 'OKAY', None
        if status != b'FAIL':
            raise _ProtocolFault('unknown status bytes %r' % status)
        size = self._recv_exact(sock, deadline, 4)
        try:
            length = int(size.decode('ascii'), 16)
        except ValueError as error:
            raise _ProtocolFault('a FAIL length that is not hexadecimal') from error
        if length > MAX_FAIL_MESSAGE:
            raise _ProtocolFault('a FAIL message above its bound')
        return 'FAIL', self._recv_exact(sock, deadline, length)

    def _open(self, service, deadline, may_send=None):
        """Connects, selects the device and opens one service. Returns (socket or None, transport
        failure or None, launch status, FAIL message or None, local error or None). The launch is
        launched only after the service's OKAY, unknown when the service request was sent and no
        status came back, and not-launched otherwise. may_send, when given, is asked once more right
        before the service request: a caller's launch deadline that passed while connecting or
        selecting the device sends nothing."""
        try:
            sock = self._connect(self._remaining(deadline))
        except _Timeout:
            return None, 'timeout', 'not-launched', None, 'connect timed out'
        except OSError as error:
            return None, 'connect-failed', 'not-launched', None, '%s: %s' % (type(error).__name__, error)
        try:
            self._send(sock, deadline, 'host:tport:serial:' + self.serial)
            status, message = self._status(sock, deadline)
            if status == 'FAIL':
                return sock, 'transport-failed', 'not-launched', message, None
            self._recv_exact(sock, deadline, 8)
        except _Timeout:
            return sock, 'timeout', 'not-launched', None, 'timed out before the service request'
        except _SendFailed as failed:
            return sock, failed.transport, 'not-launched', None, 'the device selection: %s' % failed
        except _Ended:
            return sock, 'io-error', 'not-launched', None, 'the server closed before the service request'
        except _ProtocolFault as fault:
            return sock, 'protocol-fault', 'not-launched', None, str(fault)
        except OSError as error:
            return sock, 'io-error', 'not-launched', None, '%s: %s' % (type(error).__name__, error)
        if may_send is not None and not may_send():
            return sock, 'launch-deadline', 'not-launched', None, 'the launch deadline passed before the service request'
        # Once the service request's transmission begins, the daemon may run the service, so a
        # failure from here on leaves the launch unknown. Only a deadline that passed before the
        # first byte is not launched.
        try:
            self._send(sock, deadline, service)
        except _Timeout:
            return sock, 'timeout', 'not-launched', None, 'timed out before the service request'
        except _SendFailed as failed:
            return sock, failed.transport, 'unknown', None, 'the service request: %s' % failed
        try:
            status, message = self._status(sock, deadline)
        except _Timeout:
            return sock, 'timeout', 'unknown', None, 'no status for the service'
        except _Ended:
            return sock, 'io-error', 'unknown', None, 'the stream ended before the service status'
        except _ProtocolFault as fault:
            return sock, 'protocol-fault', 'unknown', None, str(fault)
        except OSError as error:
            return sock, 'io-error', 'unknown', None, '%s: %s' % (type(error).__name__, error)
        if status == 'FAIL':
            return sock, 'service-failed', 'not-launched', message, None
        return sock, None, 'launched', None, None

    @staticmethod
    def _close(sock):
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass

    # ------------------------------------------------ services

    def features(self, timeout, may_send=None):
        """The device's features through the server. may_send, when given, is asked once more right
        before the request is sent: a deadline that has passed by then sends nothing."""
        deadline = self._monotonic() + int(timeout * 1e9)
        try:
            sock = self._connect(self._remaining(deadline))
        except (OSError, _Timeout) as error:
            return FeaturesResult('connect-failed', (), None, str(error) or type(error).__name__)
        try:
            if may_send is not None and not may_send():
                return FeaturesResult('launch-deadline', (), None, 'the launch deadline passed before the request')
            self._send(sock, deadline, 'host-serial:%s:features' % self.serial)
            status, message = self._status(sock, deadline)
            if status == 'FAIL':
                return FeaturesResult('failed', (), message, None)
            length = int(self._recv_exact(sock, deadline, 4).decode('ascii'), 16)
            text = self._recv_exact(sock, deadline, length).decode('ascii')
            return FeaturesResult('ok', tuple(sorted(x for x in text.split(',') if x)), None, None)
        except (_Timeout, _SendFailed, _Ended, _ProtocolFault, ValueError, OSError) as error:
            return FeaturesResult('unknown', (), None, str(error) or type(error).__name__)
        finally:
            self._close(sock)

    def shell(self, command, timeout, stdout_max, stderr_max, may_send=None, private=None):
        """One command through shell protocol v2, raw, with no input.

        With `private`, bytes, the command is a constant one given private input on its standard
        input: once the service is open, the input is sent whole in one STDIN packet, then
        CLOSE_STDIN, and the output is read as without it. The service request names only the
        constant command, and the input is never kept in the result. When the input cannot be sent
        whole, the call ends there with the transport failure, launched and with no status: the
        caller's input must be inert unless it arrives whole. The daemon's handling of STDIN and
        CLOSE_STDIN is in the adb module, outside this package's inspected scope, so a guest check
        must confirm this form before any private input relies on it."""
        if not command or any(ord(c) < 0x20 or ord(c) > 0x7e for c in command):
            raise ValueError('a shell command is printable ASCII')
        if private is not None:
            private = bytes(private)
            if not private or len(private) > PRIVATE_INPUT_MAX:
                raise ValueError('private input is 1 to %d bytes' % PRIVATE_INPUT_MAX)
        service = SHELL_PREFIX + command
        started_wall, started = self._wall(), self._monotonic()
        deadline = started + int(timeout * 1e9)
        decoder = ShellV2Decoder(stdout_max, stderr_max)
        sock, failure, launch, fail, error = self._open(service, deadline, may_send)
        transport, completion = 'ok', None
        if failure is not None:
            transport, completion = failure, 'not-started'
        elif private is not None and not self._input(sock, deadline, private):
            transport, completion, error = 'io-error', 'input-failed', 'the private input was not sent whole'
        else:
            try:
                while decoder.state not in ('malformed', 'overflow'):
                    sock.settimeout(self._remaining(deadline))
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout as timed_out:
                        raise _Timeout() from timed_out
                    if not chunk:
                        completion = decoder.end()
                        break
                    decoder.feed(chunk)
                else:
                    completion = decoder.state
            except _Timeout:
                transport, completion, error = 'timeout', 'timeout', 'the command did not complete within its bound'
            except OSError as failed:
                transport, completion, error = 'io-error', 'io-error', '%s: %s' % (type(failed).__name__, failed)
            if completion != 'exited':
                decoder.salvage()
            if completion == 'malformed':
                transport, error = 'protocol-fault', decoder.problem
            elif completion == 'overflow':
                error = decoder.problem
            elif completion == 'eof-before-exit':
                transport, error = 'closed', decoder.problem
        self._close(sock)
        ended = self._monotonic()
        return ShellResult(service, launch, transport, completion, decoder.exit_frame, bytes(decoder.stdout),
                           bytes(decoder.stderr), decoder.overflow, decoder.partial, fail, error, started_wall,
                           self._wall(), ended - started, decoder.partial_stream, decoder.residual,
                           decoder.residual_bytes)

    def _input(self, sock, deadline, data):
        """Sends one STDIN packet with the whole input, then CLOSE_STDIN: whether it was sent
        whole."""
        try:
            sock.settimeout(self._remaining(deadline))
            sock.sendall(struct.pack('<BI', ID_STDIN, len(data)) + data + struct.pack('<BI', ID_CLOSE_STDIN, 0))
        except (_Timeout, OSError):
            return False
        return True

    def reboot(self, timeout, may_send=None):
        started_wall, started = self._wall(), self._monotonic()
        deadline = started + int(timeout * 1e9)
        sock, failure, launch, fail, error = self._open(REBOOT_SERVICE, deadline, may_send)
        message = bytearray()
        if failure is not None:
            acknowledgement = 'refused' if failure == 'service-failed' else 'none'
            transport, stream_end = failure, 'not-started'
        else:
            transport, acknowledgement, stream_end = 'ok', 'accepted', None
            try:
                while True:
                    sock.settimeout(self._remaining(deadline))
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout as timed_out:
                        raise _Timeout() from timed_out
                    if not chunk:
                        stream_end = 'eof'
                        break
                    message += chunk
                    if len(message) > REBOOT_MESSAGE_MAX:
                        stream_end = 'overflow'
                        del message[REBOOT_MESSAGE_MAX:]
                        break
            except _Timeout:
                stream_end = 'timeout'
            except OSError as failed:
                stream_end, error = 'io-error', '%s: %s' % (type(failed).__name__, failed)
        self._close(sock)
        return RebootResult(launch, transport, acknowledgement, stream_end, bytes(message), fail, error,
                            started_wall, self._wall(), self._monotonic() - started)

    def push(self, data, path, mode, mtime, timeout, may_send=None):
        """Sends one file with sync SEND version 1. may_send, when given, is asked once more right
        before the sync service request, as for a shell command."""
        spec = '%s,%d' % (path, mode)
        if (not path.startswith('/') or ',' in path or len(spec) > 1024
                or any(ord(c) < 0x21 or ord(c) > 0x7e for c in path)):
            raise ValueError('a pushed path is absolute printable ASCII without commas or spaces')
        started_wall, started = self._wall(), self._monotonic()
        deadline = started + int(timeout * 1e9)
        sock, failure, launch, fail, error = self._open(SYNC_SERVICE, deadline, may_send)
        status = 'not-started'
        transport = failure or 'ok'
        if failure is None:
            try:
                parts = [b'SEND' + struct.pack('<I', len(spec)) + spec.encode('ascii')]
                parts += [b'DATA' + struct.pack('<I', len(data[at:at + SYNC_DATA_MAX])) + data[at:at + SYNC_DATA_MAX]
                          for at in range(0, len(data), SYNC_DATA_MAX)]
                parts.append(b'DONE' + struct.pack('<I', mtime & 0xffffffff))
                status = 'unknown'
                for part in parts:
                    sock.settimeout(self._remaining(deadline))
                    sock.sendall(part)
                head = self._recv_exact(sock, deadline, 8)
                ident, length = head[:4], struct.unpack('<I', head[4:])[0]
                if ident == b'OKAY' and length == 0:
                    status = 'ok'
                elif ident == b'FAIL' and length <= SYNC_DATA_MAX:
                    status, fail = 'failed', self._recv_exact(sock, deadline, length)
                else:
                    transport, error = 'protocol-fault', 'an unknown sync reply'
                if transport == 'ok':
                    try:
                        sock.sendall(b'QUIT' + struct.pack('<I', 0))
                    except OSError:
                        pass
            except (_Timeout, socket.timeout):
                transport, error = 'timeout', 'the push did not complete within its bound'
            except _Ended:
                transport, error = 'io-error', 'the stream ended before the sync reply'
            except OSError as failed:
                transport, error = 'io-error', '%s: %s' % (type(failed).__name__, failed)
        self._close(sock)
        return PushResult(path, len(data), launch, transport, status, fail, error, started_wall, self._wall(),
                          self._monotonic() - started)


class _ProtocolFault(Exception):
    pass
