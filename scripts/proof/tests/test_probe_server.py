# SPDX-License-Identifier: Apache-2.0
"""Host-only socket/TLS/signal doubles: no network, devices or credential reads.

Run: python3 -B -m unittest discover -s scripts/proof/tests -p test_probe_server.py
Not certificate verification, a deployed endpoint, or Android/P4 evidence.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "probe_server", Path(__file__).resolve().parents[1] / "probe_server.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
CLI = ["--cert", "/explicit-fixture/fullchain.pem", "--private-key", "/explicit-fixture/private.key"]


def request(method=b"GET", target=b"/generate_204", version=b"HTTP/1.1", headers=None):
    if headers is None:
        headers = [b"Host: probe.andrix.org"]
    return (b" ".join((method, target, version)) + b"\r\n"
            + b"".join(line + b"\r\n" for line in headers) + b"\r\n")


class MemoryConnection:
    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.sent = []
        self.read_sizes = []
        self.timeouts = []
        self.closes = 0
        self.do_handshake = mock.Mock()

    def settimeout(self, seconds):
        assert 0 < seconds <= probe.CONNECTION_SECONDS
        self.timeouts.append(seconds)

    def recv(self, size):
        self.read_sizes.append(size)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closes += 1


class IsolatedTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        patch = lambda target, name, **kwargs: stack.enter_context(mock.patch.object(target, name, **kwargs))
        # Any accidentally unmocked I/O must fail, not touch an existing fixture.
        self.sockets = patch(probe.socket, "socket", side_effect=AssertionError("unexpected socket creation"))
        for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
            patch(probe.socket, name, side_effect=AssertionError("unexpected network/name lookup"))
        self.ssl_factory = patch(probe.ssl, "SSLContext", side_effect=AssertionError("unexpected TLS setup"))
        self.is_file = patch(probe.Path, "is_file", side_effect=AssertionError("unexpected file inspection"))
        self.signals = patch(probe.signal, "signal", return_value=mock.sentinel.previous_handler)
        self.select = patch(probe.select, "select", side_effect=AssertionError("unexpected select"))
        patch(probe.time, "monotonic", return_value=100.0)

    def allow_tls(self):
        self.is_file.side_effect = None
        self.is_file.return_value = True
        self.ssl_factory.side_effect = None
        context = self.ssl_factory.return_value = mock.Mock()
        return context

    def allow_listeners(self):
        first, second = mock.Mock(), mock.Mock()
        self.sockets.side_effect = [first, second]
        return first, second

    def run_main(self, args=()):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            result = probe.main(CLI + list(args))
        return result, output.getvalue(), error.getvalue()


class ResponseTests(IsolatedTests):
    def test_exact_get_is_empty_204_without_redirect_or_body_framing(self):
        for head in (request(), request(version=b"HTTP/1.0", headers=[]),
                     request(headers=[b"hOsT: probe.andrix.org:8080", b"Content-Length: 0", b"Connection: keep-alive"])):
            with self.subTest(head=head):
                self.assertEqual(probe.request_status(head), 204)
                connection = MemoryConnection([head[:9], head[9:]])
                probe.handle_connection(connection)
                self.assertEqual(connection.sent, [b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"])
                self.assertEqual(connection.closes, 1)
                connection.do_handshake.assert_not_called()

    def test_unrelated_paths_are_not_normalized_or_proxied(self):
        for target in (b"/", b"/generate_204/", b"/generate_204?x=1", b"/generate_204#x",
                       b"/%67enerate_204", b"//generate_204", b"/a/../generate_204",
                       b"/../../etc/passwd", b"https://probe.andrix.org/generate_204", b"*"):
            with self.subTest(target=target):
                self.assertEqual(probe.request_status(request(target=target)), 404)

    def test_other_methods_fail_closed_including_head(self):
        for method in (b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"TRACE", b"get", b"UNKNOWN"):
            with self.subTest(method=method):
                self.assertEqual(probe.request_status(request(method=method)), 405)
        self.assertIn(b"Allow: GET\r\n", probe.response_bytes(405))

    def test_bad_request_lines_and_versions_fail_closed(self):
        for head in (b"\r\n\r\n", b"GET /generate_204\r\n\r\n", request(version=b"HTTP/2.0"),
                     request(method=b"GET "), request(method=b"G\x00ET"), request(target=b"/generate_204\n"),
                     request(target=b""), request(target=b"/\xff"), request().replace(b"\r\n", b"\n")):
            with self.subTest(head=head):
                self.assertEqual(probe.request_status(head), 400)

    def test_missing_ambiguous_or_unsupported_headers_fail_closed(self):
        bad_headers = [[], [b"Host:"], [b"Host: bad host"], [b"Host: a", b"host: a"],
                       [b"Host: a", b"X: one", b"x: two"], [b"Host : a"], [b"Host: a", b" folded: value"],
                       [b"Host: a", b"No-Colon"], [b"Host: a", b": empty-name"], [b"Host: a\x00"],
                       [b"Host: a\x7f"], [b"Host: a", b"X: \xff"], [b"Host: a", b"Transfer-Encoding: chunked"],
                       [b"Host: a", b"Expect: 100-continue"], [b"Host: a", b"Upgrade: websocket"]]
        bad_headers += [[b"Host: a", b"Content-Length: " + value]
                        for value in (b"1", b"-1", b"00", b"0, 0", b"abc", b"")]
        for headers in bad_headers:
            with self.subTest(headers=headers):
                self.assertEqual(probe.request_status(request(headers=headers)), 400)

    def test_header_byte_and_count_limits(self):
        head = request(headers=[b"Host: a", b"X-Pad: "])
        head = head[:-4] + b"x" * (probe.MAX_HEADER_BYTES - len(head)) + b"\r\n\r\n"
        self.assertEqual(len(head), probe.MAX_HEADER_BYTES)
        self.assertEqual(probe.request_status(head), 204)
        self.assertEqual(probe.request_status(head[:-4] + b"x\r\n\r\n"), 431)
        headers = [b"Host: a"] + [b"X-%d: a" % n for n in range(probe.MAX_HEADERS - 1)]
        self.assertEqual(probe.request_status(request(headers=headers)), 204)
        self.assertEqual(probe.request_status(request(headers=headers + [b"Extra: a"])), 431)
        connection = MemoryConnection([head])
        probe.handle_connection(connection)
        self.assertEqual(connection.sent, [probe.response_bytes(204)])

    def test_all_error_responses_are_empty_and_never_redirect(self):
        for status in (400, 404, 405, 431):
            with self.subTest(status=status):
                head, body = probe.response_bytes(status).split(b"\r\n\r\n")
                self.assertTrue(head.startswith(b"HTTP/1.1 %d " % status))
                self.assertIn(b"Content-Length: 0", head)
                self.assertIn(b"Connection: close", head)
                self.assertNotIn(b"Location:", head)
                self.assertEqual(body, b"")


class ConnectionTests(IsolatedTests):
    def test_incomplete_or_failed_read_closes_without_logging(self):
        for chunks in ([], [b"GET /generate_204 HTTP/1.1\r\n"], [TimeoutError()],
                       [OSError("sensitive peer/request text")], [probe.ssl.SSLError("TLS peer text")]):
            with self.subTest(chunks=chunks):
                connection = MemoryConnection(chunks)
                output, error = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(error):
                    probe.handle_connection(connection)
                self.assertEqual(connection.sent, [])
                self.assertEqual(connection.closes, 1)
                self.assertEqual(output.getvalue() + error.getvalue(), "")

    def test_large_unterminated_header_reads_only_the_cap(self):
        connection = MemoryConnection([b"x" * (probe.MAX_HEADER_BYTES + 100)])
        probe.handle_connection(connection)
        self.assertEqual(connection.sent, [probe.response_bytes(431)])
        self.assertEqual(sum(connection.read_sizes), probe.MAX_HEADER_BYTES)
        self.assertLessEqual(max(connection.read_sizes), 1024)
        self.assertEqual(connection.chunks, [b"x" * 100])
        self.assertEqual(connection.closes, 1)

    def test_one_response_only_even_when_pipelined(self):
        connection = MemoryConnection([request() + request()])
        probe.handle_connection(connection)
        self.assertEqual(connection.sent, [probe.response_bytes(204)])
        self.assertEqual(connection.closes, 1)

    def test_upload_is_rejected_without_body_read_or_continue(self):
        connection = MemoryConnection([request(method=b"POST", headers=[b"Host: a", b"Content-Length: 999"]),
                                       b"never interpreted as a body"])
        probe.handle_connection(connection)
        self.assertEqual(connection.sent, [probe.response_bytes(400)])
        self.assertEqual(len(connection.read_sizes), 1)
        self.assertEqual(connection.closes, 1)

    def test_slow_trickle_cannot_reset_total_read_deadline(self):
        connection = MemoryConnection([b"G", b"E", b"T"])
        with mock.patch.object(probe.time, "monotonic", side_effect=[10, 10.5, 11, 14, 15]):
            probe.handle_connection(connection)
        self.assertEqual(connection.timeouts, [4.5, 4, 1])
        self.assertEqual(len(connection.read_sizes), 2)
        self.assertEqual(connection.sent, [])
        self.assertEqual(connection.closes, 1)

    def test_tls_wrap_is_deferred_and_both_socket_owners_close(self):
        raw, wrapped = MemoryConnection(), MemoryConnection([request()])
        context = mock.Mock()
        context.wrap_socket.return_value = wrapped
        with mock.patch.object(probe.time, "monotonic", return_value=10):
            probe.handle_connection(raw, context)
        context.wrap_socket.assert_called_once_with(raw, server_side=True, do_handshake_on_connect=False)
        wrapped.do_handshake.assert_called_once_with()
        self.assertEqual(raw.timeouts, [probe.CONNECTION_SECONDS])
        self.assertEqual(wrapped.sent, [probe.response_bytes(204)])
        self.assertEqual(raw.sent, [])
        self.assertEqual((raw.closes, wrapped.closes), (1, 1))

    def test_tls_handshake_read_and_write_share_one_deadline(self):
        raw, wrapped = MemoryConnection(), MemoryConnection([request()])
        context = mock.Mock(wrap_socket=mock.Mock(return_value=wrapped))
        with mock.patch.object(probe.time, "monotonic", side_effect=[10, 10.5, 11, 14.5, 15]):
            probe.handle_connection(raw, context)
        self.assertEqual(raw.timeouts, [4.5])
        self.assertEqual(wrapped.timeouts, [4, 0.5])
        self.assertEqual(wrapped.sent, [])  # No send after the total deadline.
        self.assertEqual((raw.closes, wrapped.closes), (1, 1))

    def test_tls_wrap_handshake_and_send_errors_close(self):
        for failure in ("wrap", "handshake", "send"):
            with self.subTest(failure=failure):
                raw, wrapped = MemoryConnection(), MemoryConnection([request()])
                context = mock.Mock(wrap_socket=mock.Mock(return_value=wrapped))
                error = probe.ssl.SSLError("sensitive TLS exception")
                if failure == "wrap":
                    context.wrap_socket.side_effect = error
                elif failure == "handshake":
                    wrapped.do_handshake.side_effect = error
                else:
                    wrapped.sendall = mock.Mock(side_effect=error)
                probe.handle_connection(raw, context)
                self.assertEqual(raw.closes, 1)
                self.assertEqual(wrapped.closes, 0 if failure == "wrap" else 1)
                self.assertEqual(raw.sent, [])


class SetupTests(IsolatedTests):
    def test_numeric_addresses_and_distinct_ports(self):
        self.assertEqual(probe.validate_network("127.0.0.1", "8080", "8443"), ("127.0.0.1", 8080, 8443))
        self.assertEqual(probe.validate_network("2001:db8::1", 80, 443), ("2001:db8::1", 80, 443))
        self.assertEqual(probe.validate_network("0.0.0.0", 80, 443), ("0.0.0.0", 80, 443))
        for bind, http, https in (("localhost", 80, 443), ("", 80, 443), ("::1%lo", 80, 443),
                                  ("127.0.0.1", 80, 80), ("::1", 0, 443), ("::1", 80, 65536),
                                  ("::1", -1, 443), ("::1", "bad", 443), ("::1", True, 443),
                                  ("::1", 80, 443.5)):
            with self.subTest(bind=bind, http=http, https=https), self.assertRaises(ValueError):
                with probe.open_listeners(bind, http, https, mock.sentinel.tls):
                    self.fail("invalid configuration opened listeners")
        self.sockets.assert_not_called()

    def test_file_paths_only_and_tls_policy_without_credentials(self):
        context = self.allow_tls()
        self.assertIs(probe.load_tls_context(CLI[1], CLI[3]), context)
        self.ssl_factory.assert_called_once_with(probe.ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(context.minimum_version, probe.ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode, probe.ssl.CERT_NONE)
        context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        context.load_cert_chain.assert_called_once_with(certfile=CLI[1], keyfile=CLI[3], password=probe._no_password)
        context.load_verify_locations.assert_not_called()
        context.load_default_certs.assert_not_called()
        with self.assertRaises(ValueError):
            context.load_cert_chain.call_args.kwargs["password"]()
        self.sockets.assert_not_called()

    def test_non_files_or_stdin_fail_before_tls_or_listeners(self):
        for values, results in (((CLI[1], CLI[3]), [False]), ((CLI[1], CLI[3]), [True, False]),
                                (("-", CLI[3]), []), ((CLI[1], "-"), [True]),
                                ((CLI[1], CLI[3]), [OSError("private path detail")])):
            with self.subTest(values=values, results=results):
                self.is_file.side_effect = results
                with self.assertRaises(ValueError):
                    probe.load_tls_context(*values)
        self.ssl_factory.assert_not_called()
        self.sockets.assert_not_called()

    def test_listeners_bind_both_protocols_and_close(self):
        first, second = self.allow_listeners()
        with probe.open_listeners("127.0.0.1", 8080, 8443, mock.sentinel.tls) as listeners:
            self.assertEqual(listeners, [(first, None), (second, mock.sentinel.tls)])
            for listener, port in ((first, 8080), (second, 8443)):
                listener.bind.assert_called_once_with(("127.0.0.1", port))
                listener.listen.assert_called_once_with(probe.BACKLOG)
                listener.setblocking.assert_called_once_with(False)
                listener.close.assert_not_called()
        self.assertEqual(self.sockets.call_args_list, [mock.call(probe.socket.AF_INET, probe.socket.SOCK_STREAM)] * 2)
        first.close.assert_called_once_with()
        second.close.assert_called_once_with()

    def test_ipv6_does_not_implicitly_expose_ipv4(self):
        first, second = self.allow_listeners()
        with probe.open_listeners("::1", 8080, 8443, mock.sentinel.tls):
            for listener in (first, second):
                listener.setsockopt.assert_any_call(probe.socket.IPPROTO_IPV6, probe.socket.IPV6_V6ONLY, 1)
        self.assertEqual(self.sockets.call_args_list, [mock.call(probe.socket.AF_INET6, probe.socket.SOCK_STREAM)] * 2)

    def test_https_never_falls_back_to_plaintext(self):
        with self.assertRaises(ValueError):
            with probe.open_listeners("127.0.0.1", 8080, 8443, None):
                self.fail("missing TLS context was accepted")
        self.sockets.assert_not_called()

    def test_startup_failure_at_either_listener_closes_every_created_socket(self):
        for index in (0, 1):
            for operation in ("setsockopt", "bind", "listen", "setblocking"):
                with self.subTest(index=index, operation=operation):
                    listeners = self.allow_listeners()
                    getattr(listeners[index], operation).side_effect = OSError("fixture failure")
                    with self.assertRaises(OSError):
                        with probe.open_listeners("127.0.0.1", 8080, 8443, mock.sentinel.tls):
                            self.fail("partial startup was accepted")
                    for created in listeners[:index + 1]:
                        created.close.assert_called_once_with()
                    for uncreated in listeners[index + 1:]:
                        uncreated.close.assert_not_called()

    def test_socket_creation_or_context_body_failure_rolls_back(self):
        first = mock.Mock()
        self.sockets.side_effect = [first, OSError("second socket failed")]
        with self.assertRaises(OSError):
            with probe.open_listeners("127.0.0.1", 8080, 8443, mock.sentinel.tls):
                self.fail("partial startup was accepted")
        first.close.assert_called_once_with()
        first, second = self.allow_listeners()
        with self.assertRaises(RuntimeError):
            with probe.open_listeners("127.0.0.1", 8080, 8443, mock.sentinel.tls):
                raise RuntimeError("body failed")
        first.close.assert_called_once_with()
        second.close.assert_called_once_with()


class LifecycleTests(IsolatedTests):
    def test_loop_dispatches_http_and_https_with_one_client_at_a_time(self):
        first, second = mock.Mock(), mock.Mock()
        a, b = MemoryConnection([request()]), MemoryConnection()
        wrapped = MemoryConnection([request()])
        context = mock.Mock(wrap_socket=mock.Mock(return_value=wrapped))
        first.accept.return_value, second.accept.return_value = (a, ("ignored", 1)), (b, ("ignored", 2))
        self.select.side_effect = [([first, second], [], [])]
        probe.serve([(first, None), (second, context)], lambda: wrapped.closes > 0)
        self.assertEqual(a.sent, wrapped.sent)
        self.assertEqual(a.sent, [probe.response_bytes(204)])
        self.assertEqual((a.closes, b.closes, wrapped.closes), (1, 1, 1))
        self.select.assert_called_once_with([first, second], [], [], probe.POLL_SECONDS)

    def test_accept_race_is_harmless_and_stop_after_poll_prevents_accept(self):
        for error in (BlockingIOError(), ConnectionAbortedError()):
            with self.subTest(error=error):
                listener = mock.Mock()
                listener.accept.side_effect = error
                self.select.side_effect = [([listener], [], [])]
                probe.serve([(listener, None)], lambda: listener.accept.call_count > 0)
                listener.accept.assert_called_once_with()
                listener.accept.reset_mock()
                stopped = iter([False, True])
                self.select.side_effect = [([listener], [], [])]
                probe.serve([(listener, None)], lambda: next(stopped))
                listener.accept.assert_not_called()

    def test_bad_cli_is_redacted_and_precedes_file_access(self):
        for args in ([], CLI + ["--http-port", "private-argument-text"], CLI + ["--bind", "probe.andrix.org"],
                     CLI + ["--http-port", "8443"], CLI + ["--unknown", "private-argument-text"]):
            with self.subTest(args=args):
                output, error = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(error), self.assertRaises(SystemExit) as caught:
                    probe.main(args)
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("private-argument-text", error.getvalue())
        self.is_file.assert_not_called()
        self.ssl_factory.assert_not_called()
        self.sockets.assert_not_called()
        self.signals.assert_not_called()

    def test_tls_setup_failure_has_no_readiness_or_exception_details(self):
        context = self.allow_tls()
        context.load_cert_chain.side_effect = probe.ssl.SSLError("sensitive key error " + CLI[3])
        result, output, error = self.run_main()
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        self.assertIn("TLS setup", error)
        self.assertNotIn("sensitive", error)
        self.assertNotIn(CLI[3], error)
        self.sockets.assert_not_called()
        self.assertEqual(self.signals.call_count, 4)  # Install and restore both.

    def test_startup_and_serving_errors_close_listeners_and_redact_details(self):
        self.allow_tls()
        for stage in ("listener startup", "serving"):
            with self.subTest(stage=stage):
                first, second = self.allow_listeners()
                if stage == "listener startup":
                    second.bind.side_effect = OSError("sensitive exception")
                else:
                    self.select.side_effect = OSError("sensitive exception")
                result, output, error = self.run_main()
                self.assertEqual(result, 1)
                self.assertEqual(bool(output), stage == "serving")
                self.assertEqual(error, "probe_server: %s failed\n" % stage)
                first.close.assert_called_once_with()
                second.close.assert_called_once_with()

    def test_sigint_and_sigterm_close_both_and_restore_handlers(self):
        self.allow_tls()
        for signum, args, address in ((probe.signal.SIGINT, [], "127.0.0.1"),
                                      (probe.signal.SIGTERM, ["--bind", "::1"], "[::1]")):
            with self.subTest(signum=signum):
                first, second = self.allow_listeners()
                self.signals.reset_mock()

                def poll(*unused):
                    # Deliver only to the captured Python handler, never the OS.
                    self.select.side_effect = AssertionError("service polled after stop")
                    self.signals.call_args_list[0].args[1](signum, None)
                    return [], [], []

                self.select.side_effect = poll
                result, output, error = self.run_main(args)
                self.assertEqual((result, error), (0, ""))
                self.assertIn("http://%s:8080/generate_204" % address, output)
                self.assertIn("https://%s:8443/generate_204" % address, output)
                self.assertIn("Android/client TLS validation unproved", output)
                self.assertNotIn(CLI[1], output)
                self.assertNotIn(CLI[3], output)
                first.close.assert_called_once_with()
                second.close.assert_called_once_with()
                self.assertEqual(self.signals.call_args_list[-2:],
                                 [mock.call(sig, mock.sentinel.previous_handler)
                                  for sig in (probe.signal.SIGINT, probe.signal.SIGTERM)])

    def test_signal_during_startup_never_reports_readiness(self):
        context = self.allow_tls()
        for stage in ("TLS", "listener"):
            with self.subTest(stage=stage):
                self.signals.reset_mock()
                self.sockets.reset_mock()

                def stop(*args, **kwargs):
                    self.signals.call_args_list[0].args[1](probe.signal.SIGTERM, None)

                context.load_cert_chain.side_effect = stop if stage == "TLS" else None
                first, second = self.allow_listeners()
                if stage == "listener":
                    second.listen.side_effect = stop
                self.assertEqual(self.run_main(), (0, "", ""))
                if stage == "TLS":
                    self.sockets.assert_not_called()
                else:
                    first.close.assert_called_once_with()
                    second.close.assert_called_once_with()
                self.select.assert_not_called()


if __name__ == "__main__":
    unittest.main()
