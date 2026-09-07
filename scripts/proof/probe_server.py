#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""HTTP(S) 204 listeners for a private host fixture, not Android readiness."""
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import select
import signal
import socket
import ssl
import sys
import time


MAX_HEADER_BYTES = 8192  # Includes request line and terminating CRLFs.
MAX_HEADERS = 64
CONNECTION_SECONDS = 5.0  # One total deadline: handshake, headers AND response.
BACKLOG = 8  # Kernel-clamped pending queue per listener; only one active client.
POLL_SECONDS = 0.2
TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
REASONS = {200: "OK", 204: "No Content", 400: "Bad Request", 404: "Not Found",
           405: "Method Not Allowed", 431: "Request Header Fields Too Large",
           503: "Service Unavailable"}
CT_FILES = ("log_list.pub", "v2/log_list.json", "v2/log_list.sig",
            "v3/log_list.ctfb", "v3/log_list.sig")
MAX_CT_FILE_BYTES = 1024 * 1024


def load_ct_assets(directory):
    """Load only five staged public CT files with an exact digest manifest.

    Verify their signatures against the built Android allowlist before staging.
    Android independently retains that signature/allowlist verification. This
    service never fetches data from upstream or changes client trust.
    """
    root = Path(directory).resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("invalid CT bundle manifest path")
    with manifest_path.open("rb") as stream:
        encoded = stream.read(16385)
    if len(encoded) > 16384:
        raise ValueError("oversized CT bundle manifest")
    manifest = json.loads(encoded)
    if (not isinstance(manifest, dict) or manifest.get("schema") != 1
            or not isinstance(manifest.get("files"), dict)
            or set(manifest["files"]) != set(CT_FILES)):
        raise ValueError("unexpected CT bundle manifest")
    now_ms = int(time.time() * 1000)
    timestamp, expiry = manifest.get("log_list_timestamp_ms"), manifest.get("valid_until_ms")
    if (type(timestamp) is not int or type(expiry) is not int
            or expiry != timestamp + 70 * 24 * 60 * 60 * 1000
            or not timestamp <= now_ms <= expiry):
        raise ValueError("CT snapshot expired or future-dated")
    assets = {}
    for name in CT_FILES:
        path = root / name
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError("invalid CT data path")
        with path.open("rb") as stream:
            data = stream.read(MAX_CT_FILE_BYTES + 1)
        if not 0 < len(data) <= MAX_CT_FILE_BYTES:
            raise ValueError("invalid CT data size")
        if hashlib.sha256(data).hexdigest() != manifest["files"][name]:
            raise ValueError("CT data digest mismatch")
        assets[("/certificate_transparency/" + name).encode("ascii")] = data
    return assets


def load_security_assets(directory):
    # Keep the base/CT service standalone when this optional feature is unused.
    # Support direct script launch as well as package/import-based host tests.
    if __package__:
        from .security_data import load_assets
    else:
        try:
            from security_data import load_assets
        except ModuleNotFoundError as error:
            if error.name != "security_data":
                raise
            from scripts.proof.security_data import load_assets
    return load_assets(directory)


def request_status(head, extra_paths=()):
    """Classify a bounded HTTP/1.x header block; never interpret a URL or body."""
    if len(head) > MAX_HEADER_BYTES:
        return 431
    if not head.endswith(b"\r\n\r\n"):
        return 400
    lines = head[:-4].split(b"\r\n")
    if len(lines) - 1 > MAX_HEADERS:
        return 431
    parts = lines[0].split(b" ")
    if len(parts) != 3:
        return 400
    method, target, version = parts
    if (not TOKEN.fullmatch(method) or version not in (b"HTTP/1.0", b"HTTP/1.1")
            or not target or any(byte < 33 or byte > 126 for byte in target)):
        return 400
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if (not colon or not TOKEN.fullmatch(name)
                or any(byte != 9 and (byte < 32 or byte > 126) for byte in value)):
            return 400
        name = name.lower()
        if name in headers:  # No duplicate fields or folded/ambiguous framing.
            return 400
        headers[name] = value.strip(b" \t")
    host = headers.get(b"host")
    if ((version == b"HTTP/1.1" and host is None)
            or (host is not None and (not host or b" " in host or b"\t" in host))):
        return 400
    if (any(name in headers for name in (b"transfer-encoding", b"expect", b"upgrade"))
            or headers.get(b"content-length", b"0") != b"0"):
        return 400
    if method != b"GET":
        return 405
    if target == b"/generate_204":
        return 204
    return 200 if target in extra_paths else 404


def response_bytes(status, payload=b""):
    lines = ["HTTP/1.1 %d %s" % (status, REASONS[status]), "Connection: close"]
    # HTTP forbids Content-Length on 204, even when zero. All errors are empty too.
    if status != 204:
        lines.append("Content-Length: %d" % len(payload))
    if status == 200:
        lines.extend(["Content-Type: application/octet-stream", "Cache-Control: no-store"])
    if status == 503:
        lines.append("Cache-Control: no-store")
    if status == 405:
        lines.append("Allow: GET")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + payload


class _HeaderTooLarge(Exception):
    pass


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _read_head(connection, deadline):
    data = bytearray()
    while True:
        end = data.find(b"\r\n\r\n")
        if end >= 0:
            return bytes(data[:end + 4])
        if len(data) == MAX_HEADER_BYTES:
            raise _HeaderTooLarge
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(min(1024, MAX_HEADER_BYTES - len(data)))
        if not chunk:
            return None
        data.extend(chunk)


def handle_connection(connection, tls_context=None, assets=None, security_assets=None):
    """Own and close one accepted socket; optional TLS is applied before HTTP.

    Kept separate from listeners for credential-free, in-memory host tests.
    Timeout, EOF and TLS/socket failures close silently, never log requests.
    """
    deadline = time.monotonic() + CONNECTION_SECONDS
    assets = assets if tls_context is not None and assets else {}
    security_assets = security_assets if tls_context is not None else None
    security_paths = security_assets.paths if security_assets is not None else ()
    payload = b""
    security_target = None
    try:
        with ExitStack() as cleanup:
            cleanup.callback(connection.close)
            connection.settimeout(_remaining(deadline))
            if tls_context is not None:
                connection = tls_context.wrap_socket(
                    connection, server_side=True, do_handshake_on_connect=False)
                cleanup.callback(connection.close)
                connection.settimeout(_remaining(deadline))
                connection.do_handshake()
            try:
                head = _read_head(connection, deadline)
                if head is None:
                    return
                status = request_status(head, tuple(assets) + security_paths)
                if status == 200:
                    target = head.split(b" ", 2)[1]
                    if target in security_paths:
                        security_target = target
                    else:
                        payload = assets[target]
            except _HeaderTooLarge:
                status = 431
            connection.settimeout(_remaining(deadline))
            if security_target is not None:
                # Check after handshake/header reads, immediately before response
                # selection. Never turn stale data into an empty successful list.
                try:
                    payload = security_assets.payload(security_target)
                except ValueError:
                    status, payload = 503, b""
            connection.sendall(response_bytes(status, payload))
    except OSError:  # Includes SSL errors and total-deadline/socket timeouts.
        pass


def validate_network(bind, http_port, https_port):
    """Numeric addresses only: no hostname resolution or implicit external bind."""
    try:
        if not isinstance(bind, str) or "%" in bind:
            raise ValueError
        address = ipaddress.ip_address(bind)
    except ValueError:
        raise ValueError("--bind must be a numeric IPv4/IPv6 address without a scope ID") from None
    ports = []
    for label, value in (("--http-port", http_port), ("--https-port", https_port)):
        # Do not coerce booleans/floats or accept arbitrary argument text as a port.
        if not re.fullmatch(r"[0-9]{1,5}", str(value)):
            raise ValueError(label + " must be an integer in 1..65535")
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError(label + " must be an integer in 1..65535")
        ports.append(port)
    if ports[0] == ports[1]:
        raise ValueError("HTTP and HTTPS ports must be distinct")
    return str(address), ports[0], ports[1]


def _no_password():
    # Without a callback OpenSSL may prompt on the terminal for an encrypted key.
    raise ValueError("encrypted keys are unsupported; use an operator-protected key FILE")


def load_tls_context(cert_file, key_file):
    """Load only explicitly supplied regular FILE paths, never stdin or key text."""
    paths = []
    for value in (cert_file, key_file):
        try:
            path = Path(value)
            valid = str(path) != "-" and path.is_file()
        except (OSError, TypeError, ValueError):
            valid = False
        if not valid:
            raise ValueError("certificate and private key must name existing regular FILEs")
        paths.append(str(path))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_NONE  # No client certificates; not client trust policy.
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(certfile=paths[0], keyfile=paths[1], password=_no_password)
    return context


@contextmanager
def open_listeners(bind, http_port, https_port, tls_context):
    """Own both listeners, including rollback if either fails to bind/listen."""
    bind, http_port, https_port = validate_network(bind, http_port, https_port)
    if tls_context is None:
        raise ValueError("HTTPS requires a TLS context")
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    with ExitStack() as cleanup:
        listeners = []
        for port, context in ((http_port, None), (https_port, tls_context)):
            listener = socket.socket(family, socket.SOCK_STREAM)
            cleanup.callback(listener.close)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((bind, port))
            listener.listen(BACKLOG)
            listener.setblocking(False)
            listeners.append((listener, context))
        yield listeners


def serve(listeners, stopping, assets=None, security_assets=None):
    """Serial, bounded service; no worker threads, keep-alive or outbound sockets."""
    contexts = dict(listeners)
    while not stopping():
        ready, _, _ = select.select(list(contexts), [], [], POLL_SECONDS)
        for listener in ready:
            if stopping():
                return
            try:
                connection, _ = listener.accept()
            except (BlockingIOError, ConnectionAbortedError):
                continue
            if security_assets is not None:
                handle_connection(connection, contexts[listener], assets, security_assets)
            elif assets:
                handle_connection(connection, contexts[listener], assets)
            else:
                handle_connection(connection, contexts[listener])


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes arbitrary argv, potentially accidental key text.
        self.print_usage(sys.stderr)
        self.exit(2, "probe_server: invalid arguments; use --help (cert/key options take FILE paths)\n")


def main(argv=None):
    parser = _ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Numeric local IP (default: 127.0.0.1); external exposure is explicit.")
    parser.add_argument("--http-port", default="8080", help="HTTP port (default: 8080).")
    parser.add_argument("--https-port", default="8443", help="Distinct HTTPS port (default: 8443).")
    parser.add_argument("--cert", required=True, metavar="FILE", help="PEM certificate/fullchain FILE.")
    parser.add_argument("--private-key", required=True, metavar="FILE", help="Unencrypted PEM key FILE.")
    parser.add_argument("--ct-data-dir", metavar="DIRECTORY",
                        help="Optional preverified signed CT snapshot and manifest; HTTPS only.")
    parser.add_argument("--security-data-dir", metavar="DIRECTORY",
                        help="Optional bounded public security snapshots and explicit owner catalog; HTTPS only.")
    args = parser.parse_args(argv)
    try:
        bind, http_port, https_port = validate_network(args.bind, args.http_port, args.https_port)
    except ValueError as error:
        parser.exit(2, "probe_server: %s\n" % error)  # Only fixed validation messages.

    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True  # Do not interrupt descriptor ownership/cleanup during startup.

    previous = {}
    stage = "signal setup"
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, stop)
        stage = "TLS setup (check certificate/fullchain and matching unencrypted key FILEs)"
        context = load_tls_context(args.cert, args.private_key)
        stage = "CT snapshot validation"
        assets = load_ct_assets(args.ct_data_dir) if args.ct_data_dir else None
        stage = "security snapshot validation"
        security_assets = load_security_assets(args.security_data_dir) if args.security_data_dir else None
        if stopping:
            return 0
        stage = "listener startup"
        with open_listeners(bind, http_port, https_port, context) as listeners:
            if not stopping:
                host = "[" + bind + "]" if ":" in bind else bind
                print("Listening (host service only; Android/client TLS validation unproved):\n"
                      "  http://%s:%d/generate_204\n  https://%s:%d/generate_204"
                      % (host, http_port, host, https_port), flush=True)
                stage = "serving"
                if security_assets is not None:
                    serve(listeners, lambda: stopping, assets, security_assets)
                elif assets:
                    serve(listeners, lambda: stopping, assets)
                else:
                    serve(listeners, lambda: stopping)
        return 0
    except (ImportError, OSError, ValueError):
        # Includes a missing optional security_data helper in a runtime copy.
        # No exception text, credential paths, request data or peer addresses.
        print("probe_server: %s failed" % stage, file=sys.stderr)
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
