# SPDX-License-Identifier: Apache-2.0
"""The adb transport against simulated byte streams: shell protocol v2 completion, the host
protocol's statuses, the reboot acknowledgement and the sync push. Host evidence only."""
import socket
import struct
import threading
import unittest

import labtest  # noqa: F401  (path setup)
import shell_transport as st


def packet(ident, payload):
    return bytes([ident]) + struct.pack('<I', len(payload)) + payload


def stream(*parts):
    return b''.join(parts)


OUT, ERR = st.ID_STDOUT, st.ID_STDERR
EXIT0 = packet(st.ID_EXIT, b'\x00')
WHOLE = stream(packet(OUT, b'Success\n'), packet(ERR, b'note\n'), packet(OUT, b'more\n'), EXIT0)


def decode(data, splits=(), stdout_max=1 << 20, stderr_max=1 << 20):
    decoder = st.ShellV2Decoder(stdout_max, stderr_max)
    at = 0
    for split in list(splits) + [len(data)]:
        decoder.feed(data[at:split])
        at = split
    return decoder, decoder.end()


class DecoderTests(unittest.TestCase):
    def test_a_whole_stream_keeps_its_streams_apart(self):
        decoder, completion = decode(WHOLE)
        self.assertEqual((completion, decoder.exit_frame), ('exited', 0))
        self.assertEqual((bytes(decoder.stdout), bytes(decoder.stderr)), (b'Success\nmore\n', b'note\n'))

    def test_every_split_of_the_stream_decodes_the_same(self):
        for first in range(len(WHOLE) + 1):
            for second in (first, min(len(WHOLE), first + 3), len(WHOLE)):
                decoder, completion = decode(WHOLE, (first, second))
                self.assertEqual((completion, decoder.exit_frame, bytes(decoder.stdout), bytes(decoder.stderr)),
                                 ('exited', 0, b'Success\nmore\n', b'note\n'), (first, second))

    def test_byte_by_byte(self):
        decoder, completion = decode(WHOLE, range(1, len(WHOLE)))
        self.assertEqual((completion, decoder.exit_frame), ('exited', 0))

    def test_an_end_before_exit_leaves_the_status_unknown(self):
        body = stream(packet(OUT, b'Success\n'))
        for cut in range(len(body) + 1):
            decoder, completion = decode(body[:cut])
            self.assertEqual(completion, 'eof-before-exit', cut)
            self.assertIsNone(decoder.exit_frame)
            self.assertEqual(decoder.partial, 0 < cut < len(body))
        decoder, completion = decode(stream(packet(OUT, b'x'), EXIT0[:3]))
        self.assertEqual((completion, decoder.partial), ('eof-before-exit', True))

    def test_a_second_or_malformed_exit_is_malformed(self):
        for data in (stream(EXIT0, EXIT0), stream(EXIT0, packet(st.ID_EXIT, b'\x01')),
                     packet(st.ID_EXIT, b''), packet(st.ID_EXIT, b'\x00\x00'), stream(EXIT0, packet(OUT, b'late')),
                     stream(EXIT0, b'\x01')):
            decoder, completion = decode(data)
            self.assertEqual(completion, 'malformed', data)

    def test_an_unknown_packet_is_malformed(self):
        for ident in (st.ID_STDIN, st.ID_CLOSE_STDIN, st.ID_WINDOW, 6, 255):
            decoder, completion = decode(stream(packet(ident, b'x'), EXIT0))
            self.assertEqual(completion, 'malformed', ident)

    def test_streams_above_their_bounds_overflow_without_waiting_for_the_payload(self):
        decoder, completion = decode(stream(packet(OUT, b'12345'), packet(OUT, b'678'), EXIT0), stdout_max=7)
        self.assertEqual((completion, decoder.overflow, bytes(decoder.stdout)), ('overflow', 'stdout', b'12345'))
        decoder = st.ShellV2Decoder(16, 16)
        decoder.feed(bytes([ERR]) + struct.pack('<I', 1 << 30))
        self.assertEqual((decoder.state, decoder.overflow, len(decoder.buffer)), ('overflow', 'stderr', 5))

    def test_received_partial_payload_is_kept_without_completion(self):
        for ident in (OUT, ERR):
            body = packet(ident, b'0123456789')
            for cut in range(st.PACKET_HEADER + 1, len(body)):
                decoder, completion = decode(stream(packet(OUT, b'whole\n'), body[:cut]))
                received = body[st.PACKET_HEADER:cut]
                self.assertEqual((completion, decoder.exit_frame, decoder.partial), ('eof-before-exit', None, True))
                expected = (b'whole\n' + received, b'') if ident == OUT else (b'whole\n', received)
                self.assertEqual((bytes(decoder.stdout), bytes(decoder.stderr)), expected, (ident, cut))
                self.assertEqual(decoder.partial_stream, 'stdout' if ident == OUT else 'stderr')
                self.assertEqual(decoder.residual, body[:st.PACKET_HEADER])
        # A cut header keeps its bytes as residual and adds nothing to either stream.
        for cut in range(1, st.PACKET_HEADER):
            decoder, completion = decode(stream(packet(OUT, b'a'), packet(OUT, b'b')[:cut]))
            self.assertEqual((completion, bytes(decoder.stdout), decoder.partial_stream), ('eof-before-exit', b'a', None))
            self.assertEqual(decoder.residual, packet(OUT, b'b')[:cut])
        # A cut EXIT is never a status.
        decoder, completion = decode(stream(packet(OUT, b'a'), EXIT0[:st.PACKET_HEADER]))
        self.assertEqual((completion, decoder.exit_frame, decoder.residual), ('eof-before-exit', None, EXIT0[:5]))
        # Salvage stays within the stream's bound and never repeats.
        decoder = st.ShellV2Decoder(8, 8)
        decoder.feed(packet(OUT, b'12345678')[:9])
        decoder.salvage()
        decoder.salvage()
        self.assertEqual((bytes(decoder.stdout), decoder.state), (b'1234', 'open'))

    def test_exit_statuses_are_kept_exactly(self):
        for status in (0, 1, 126, 127, 0x80 | 9, 255):
            decoder, completion = decode(stream(packet(ERR, b'error: x\n'), packet(st.ID_EXIT, bytes([status]))))
            self.assertEqual((completion, decoder.exit_frame), ('exited', status))


class FakeServer:
    """An adb server end for one connection at a time, running `script(sock)` in a thread."""

    def __init__(self, *scripts):
        self.scripts = list(scripts)
        self.threads, self.errors, self.received = [], [], []

    def connect(self, timeout):
        if not self.scripts:
            raise ConnectionRefusedError('no server')
        client, server = socket.socketpair()
        script = self.scripts.pop(0)

        def run():
            try:
                script(server, self)
            except Exception as error:  # Reported by the test.
                self.errors.append(error)
            finally:
                server.close()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.threads.append(thread)
        return client

    def join(self):
        for thread in self.threads:
            thread.join(5)


def exact(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError('closed')
        data += chunk
    return data


def request(sock, server):
    size = int(exact(sock, 4), 16)
    text = exact(sock, size).decode()
    server.received.append(text)
    return text


def transport_ok(sock, server):
    request(sock, server)
    sock.sendall(b'OKAY' + struct.pack('<Q', 7))


def shell_script(*parts, service_status=b'OKAY', after=None):
    def script(sock, server):
        transport_ok(sock, server)
        request(sock, server)
        sock.sendall(service_status)
        for part in parts:
            sock.sendall(part)
        if after:
            after(sock)
    return script


class ScriptedSocket:
    """A client socket with scripted replies. `fail_on` makes the send of a request whose payload
    starts with it fail after the bytes were accepted, as a peer that took the request and then broke."""

    def __init__(self, data, fail_on=None, failure=None, on_drained=None):
        self.data, self.sent = bytearray(data), []
        self.fail_on, self.failure, self.on_drained = fail_on, failure, on_drained

    def settimeout(self, value):
        pass

    def sendall(self, data):
        self.sent.append(bytes(data))
        if self.fail_on is not None and bytes(data[4:]).startswith(self.fail_on):
            raise self.failure

    def recv(self, count):
        out = bytes(self.data[:count])
        del self.data[:count]
        if not self.data and self.on_drained is not None:
            self.on_drained()
            self.on_drained = None
        return out

    def close(self):
        pass


def client(server, timeout_clock=None):
    return st.AdbClient('127.0.0.1:6520', server.connect)


class ShellTests(unittest.TestCase):
    def test_a_completed_command(self):
        server = FakeServer(shell_script(WHOLE))
        result = client(server).shell('pm list staged-sessions', 5, 1 << 20, 1 << 20)
        server.join()
        self.assertEqual(server.received, ['host:tport:serial:127.0.0.1:6520', 'shell,v2,raw:pm list staged-sessions'])
        self.assertEqual((result.launch, result.transport, result.completion, result.exit, result.completed),
                         ('launched', 'ok', 'exited', 0, True))
        self.assertEqual((result.stdout, result.stderr), (b'Success\nmore\n', b'note\n'))
        self.assertIsNone(result.error)

    def test_a_transport_failure_is_never_a_remote_status(self):
        def device_missing(sock, server):
            request(sock, server)
            sock.sendall(b'FAIL0010device not found')
        server = FakeServer(device_missing)
        result = client(server).shell('pidof system_server', 5, 1024, 1024)
        self.assertEqual((result.launch, result.transport, result.completion, result.exit, result.exit_frame),
                         ('not-launched', 'transport-failed', 'not-started', None, None))
        self.assertEqual((result.fail_message, result.stdout, result.stderr), (b'device not found', b'', b''))

    def test_a_refused_service_unknown_status_and_no_connection(self):
        server = FakeServer(shell_script(service_status=b'FAIL0006closed'))
        result = client(server).shell('id', 5, 1024, 1024)
        self.assertEqual((result.launch, result.transport, result.exit, result.fail_message),
                         ('not-launched', 'service-failed', None, b'closed'))

        def no_status(sock, server):
            transport_ok(sock, server)
            request(sock, server)
        server = FakeServer(no_status)
        result = client(server).shell('id', 5, 1024, 1024)
        self.assertEqual((result.launch, result.transport, result.completion, result.exit),
                         ('unknown', 'io-error', 'not-started', None))

        def garbage(sock, server):
            transport_ok(sock, server)
            request(sock, server)
            sock.sendall(b'OKAX')
        server = FakeServer(garbage)
        result = client(server).shell('id', 5, 1024, 1024)
        self.assertEqual((result.launch, result.transport, result.exit), ('unknown', 'protocol-fault', None))
        result = client(FakeServer()).shell('id', 5, 1024, 1024)
        self.assertEqual((result.launch, result.transport, result.exit), ('not-launched', 'connect-failed', None))

    def test_an_adb_error_message_with_a_closed_stream_is_not_exit_1(self):
        server = FakeServer(shell_script(packet(ERR, b'error: device offline\n')))
        result = client(server).shell('pidof com.android.systemui', 5, 1024, 1024)
        self.assertEqual((result.completion, result.transport, result.exit, result.completed),
                         ('eof-before-exit', 'closed', None, False))
        self.assertEqual(result.stderr, b'error: device offline\n')

    def test_a_timeout_after_launch(self):
        release = threading.Event()
        server = FakeServer(shell_script(packet(OUT, b'partial'), after=lambda sock: release.wait(5)))
        result = client(server).shell('dumpsys -t 25 package installs', 0.3, 1024, 1024)
        release.set()
        self.assertEqual((result.launch, result.transport, result.completion, result.exit),
                         ('launched', 'timeout', 'timeout', None))
        self.assertEqual(result.stdout, b'partial')

    def test_a_timeout_inside_a_packet_keeps_its_received_payload(self):
        release = threading.Event()
        cut = packet(ERR, b'denied: partial')[:12]
        server = FakeServer(shell_script(packet(OUT, b'head\n'), cut, after=lambda sock: release.wait(5)))
        result = client(server).shell('id', 0.3, 1024, 1024)
        release.set()
        self.assertEqual((result.completion, result.exit, result.completed), ('timeout', None, False))
        self.assertEqual((result.stdout, result.stderr), (b'head\n', b'denied:'))
        self.assertEqual((result.partial_frame, result.partial_stream), (True, 'stderr'))
        summary = result.summary()
        self.assertEqual((summary['partial_stream'], summary['residual_hex']), ('stderr', cut[:5].hex()))

    def test_a_service_send_failure_is_an_unknown_launch(self):
        for failure in (socket.timeout('timed out'), BrokenPipeError('broken pipe')):
            sock = ScriptedSocket(b'OKAY' + bytes(8), fail_on=b'shell,', failure=failure)
            result = st.AdbClient('sim', lambda timeout, s=sock: s).shell('id', 5, 100, 100)
            self.assertEqual((result.launch, result.exit, result.completed), ('unknown', None, False), failure)
            self.assertIn(result.transport, ('timeout', 'io-error'))
            self.assertTrue(sock.sent[-1][4:].startswith(b'shell,v2,raw:id'))
        # A deadline that passed before the service request was sent launches nothing.
        clock = {'now': 0}
        sock = ScriptedSocket(b'OKAY' + bytes(8), on_drained=lambda: clock.update(now=10 ** 12))
        client_ = st.AdbClient('sim', lambda timeout: sock, monotonic=lambda: clock['now'])
        result = client_.shell('id', 5, 100, 100)
        self.assertEqual((result.launch, result.transport, result.exit), ('not-launched', 'timeout', None))
        self.assertFalse(any(data[4:].startswith(b'shell,') for data in sock.sent))
        # The same holds for the reboot and sync services.
        for service, call in ((b'reboot:', lambda c: c.reboot(5)),
                              (b'sync:', lambda c: c.push(b'x', '/data/local/tmp/a/b', 0o644, 0, 5))):
            sock = ScriptedSocket(b'OKAY' + bytes(8), fail_on=service, failure=BrokenPipeError('broken pipe'))
            result = call(st.AdbClient('sim', lambda timeout, s=sock: s))
            self.assertEqual(result.launch, 'unknown', service)

    def test_a_launch_deadline_that_passes_during_setup_sends_nothing(self):
        # The caller's deadline passes while connecting and selecting the device: the service request
        # is never sent, so the launch is known not to have happened. An open deadline sends it.
        for service, call in ((b'shell,', lambda c, gate: c.shell('id', 5, 100, 100, may_send=gate)),
                              (b'reboot:', lambda c, gate: c.reboot(5, may_send=gate))):
            clock = {'now': 0}
            sock = ScriptedSocket(b'OKAY' + bytes(8), on_drained=lambda clock=clock: clock.update(now=2 * 10 ** 9))
            result = call(st.AdbClient('sim', lambda timeout, s=sock: s), lambda clock=clock: clock['now'] < 10 ** 9)
            self.assertEqual((result.launch, result.transport), ('not-launched', 'launch-deadline'), service)
            self.assertTrue(any(data[4:].startswith(b'host:tport:serial:') for data in sock.sent), service)
            self.assertFalse(any(data[4:].startswith(service) for data in sock.sent), service)
            sock = ScriptedSocket(b'OKAY' + bytes(8), fail_on=service, failure=BrokenPipeError('broken pipe'))
            result = call(st.AdbClient('sim', lambda timeout, s=sock: s), lambda: True)
            self.assertEqual(result.launch, 'unknown', service)
            self.assertTrue(sock.sent[-1][4:].startswith(service), service)

    def test_malformed_and_overflowing_streams(self):
        server = FakeServer(shell_script(EXIT0, EXIT0))
        result = client(server).shell('id', 5, 1024, 1024)
        self.assertEqual((result.completion, result.transport, result.exit, result.exit_frame),
                         ('malformed', 'protocol-fault', None, 0))
        server = FakeServer(shell_script(packet(OUT, b'x' * 300), EXIT0))
        result = client(server).shell('dumpsys user', 5, 256, 1024)
        self.assertEqual((result.completion, result.overflow, result.exit), ('overflow', 'stdout', None))

    def test_a_command_is_printable_ascii(self):
        server = FakeServer()
        for command in ('', 'id\n', 'echo \x00', 'caf\xe9'):
            with self.assertRaises(ValueError):
                client(server).shell(command, 5, 1, 1)


class OtherServiceTests(unittest.TestCase):
    def test_features(self):
        def features(sock, server):
            request(sock, server)
            body = b'shell_v2,cmd,stat_v2'
            sock.sendall(b'OKAY' + b'%04x' % len(body) + body)
        server = FakeServer(features)
        result = client(server).features(5)
        self.assertEqual(server.received, ['host-serial:127.0.0.1:6520:features'])
        self.assertEqual((result.status, result.features), ('ok', ('cmd', 'shell_v2', 'stat_v2')))

    def test_a_features_send_failure_is_unknown(self):
        sock = ScriptedSocket(b'', fail_on=b'host-serial:', failure=BrokenPipeError('broken pipe'))
        result = st.AdbClient('sim', lambda timeout: sock).features(5)
        self.assertEqual((result.status, result.features), ('unknown', ()))

    def test_the_reboot_acknowledgement_has_no_exit_status(self):
        server = FakeServer(shell_script())
        result = client(server).reboot(5)
        self.assertEqual(server.received[1], 'reboot:')
        self.assertEqual((result.launch, result.acknowledgement, result.stream_end, result.message),
                         ('launched', 'accepted', 'eof', b''))
        self.assertFalse(hasattr(result, 'exit'))
        self.assertNotIn('exit', result.summary())
        server = FakeServer(shell_script(b'reboot (reboot,adb) failed\n'))
        result = client(server).reboot(5)
        self.assertEqual((result.acknowledgement, result.stream_end, result.message),
                         ('accepted', 'eof', b'reboot (reboot,adb) failed\n'))
        server = FakeServer(shell_script(service_status=b'FAIL0006closed'))
        result = client(server).reboot(5)
        self.assertEqual((result.launch, result.acknowledgement, result.stream_end), ('not-launched', 'refused',
                                                                                      'not-started'))
        release = threading.Event()
        server = FakeServer(shell_script(after=lambda sock: release.wait(5)))
        result = client(server).reboot(0.3)
        release.set()
        self.assertEqual((result.acknowledgement, result.stream_end), ('accepted', 'timeout'))

    def test_a_sync_push_sends_the_exact_bytes_in_bounded_chunks(self):
        data = bytes(range(256)) * 600
        seen = {}

        def sync(sock, server, reply=b'OKAY' + struct.pack('<I', 0)):
            transport_ok(sock, server)
            request(sock, server)
            sock.sendall(b'OKAY')
            ident, size = exact(sock, 4), struct.unpack('<I', exact(sock, 4))[0]
            seen['send'] = (ident, exact(sock, size))
            chunks = []
            while True:
                ident, size = exact(sock, 4), struct.unpack('<I', exact(sock, 4))[0]
                if ident == b'DONE':
                    seen['mtime'] = size
                    break
                chunks.append((ident, size, exact(sock, size)))
            seen['chunks'] = chunks
            sock.sendall(reply)
            if reply.startswith(b'OKAY'):
                seen['quit'] = exact(sock, 8)
        server = FakeServer(sync)
        result = client(server).push(data, '/data/local/tmp/andrix-d5/p/base.apk', 0o644, 12345, 5)
        server.join()
        self.assertEqual((result.status, result.transport, result.launch), ('ok', 'ok', 'launched'))
        self.assertEqual(server.received[1], 'sync:')
        self.assertEqual(seen['send'], (b'SEND', b'/data/local/tmp/andrix-d5/p/base.apk,420'))
        self.assertTrue(all(ident == b'DATA' and size <= st.SYNC_DATA_MAX for ident, size, _ in seen['chunks']))
        self.assertEqual(b''.join(chunk for _, _, chunk in seen['chunks']), data)
        self.assertEqual((seen['mtime'], seen['quit']), (12345, b'QUIT' + struct.pack('<I', 0)))
        failing = FakeServer(lambda sock, server: sync(sock, server, b'FAIL' + struct.pack('<I', 9) + b'read-only'))
        result = client(failing).push(b'abc', '/data/local/tmp/andrix-d5/p/x', 0o644, 0, 5)
        self.assertEqual((result.status, result.fail_message), ('failed', b'read-only'))
        for path in ('relative/x', '/data/local/tmp/a,b', '/data/local/tmp/a b'):
            with self.assertRaises(ValueError):
                client(FakeServer()).push(b'x', path, 0o644, 0, 5)


if __name__ == '__main__':
    unittest.main()
