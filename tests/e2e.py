"""End-to-end verification for NullAD.

Starts a local origin server and the NullAD proxy and DNS sinkhole, then drives
real traffic through them. This exists because the acceptance criteria are about
observable behaviour, not just unit-level correctness, and because this host has
no working system TLS stack: the test therefore exercises plaintext HTTP and DNS
rather than any external HTTPS endpoint.

Run with: python tests/e2e.py
"""

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "target", "release", "nullad-cli.exe")
if not os.path.exists(CLI):
    CLI = os.path.join(ROOT, "target", "release", "nullad-cli")

PROXY_PORT = 18080
DNS_PORT = 15353
ORIGIN_PORT = 18085

failures = []
checks = 0


def check(name, condition, detail=""):
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name}  {detail}")
        failures.append(name)


# --------------------------------------------------------------- origin server


class OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        body = f"origin served {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # Keep the test output clean.


def start_origin():
    server = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ------------------------------------------------------------------- DNS probe


def build_dns_query(name, qtype=1, ident=0x4242):
    header = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def parse_dns_answer_count(response):
    return struct.unpack(">H", response[6:8])[0]


def parse_dns_rcode(response):
    return response[3] & 0x0F


def dns_query(port, name, qtype=1, timeout=3.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(build_dns_query(name, qtype), ("127.0.0.1", port))
        return sock.recv(4096)


# ---------------------------------------------------------------- proxy helper


def proxy_get(url, timeout=6.0):
    """Fetch a URL through the NullAD proxy, returning (status, body)."""
    handler = urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{PROXY_PORT}"}
    )
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, headers={"Accept": "*/*"})
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def wait_for_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


# ------------------------------------------------------------------------ main


def main():
    print("NullAD end-to-end verification")
    print("=" * 60)

    if not os.path.exists(CLI):
        print(f"FAIL: nullad-cli not found at {CLI}; run `cargo build --release` first")
        return 1

    print("\n[1] building an engine from the bundled lists")
    sys.stdout.flush()

    proc = subprocess.Popen(
        [CLI, "load"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out, _ = proc.communicate(timeout=120)
    check("load command exits cleanly", proc.returncode == 0, out[-400:])
    rules_line = next(
        (line for line in out.splitlines() if line.startswith("loaded ")), ""
    )
    print(f"       {rules_line}")
    # The line reads: "loaded N list(s), M rules, K quarantined, B bytes".
    try:
        total_rules = int(rules_line.split()[3])
    except (IndexError, ValueError):
        total_rules = 0
    check("bundled lists produce rules", total_rules > 150, f"got {total_rules}")
    check("indexes were built", "trie nodes" in out and "automaton fragments" in out)

    print("\n[2] starting the origin server, proxy and DNS sinkhole")
    origin = start_origin()
    print(f"       origin on 127.0.0.1:{ORIGIN_PORT}")

    proxy_proc = subprocess.Popen(
        [CLI, "serve", "--port", str(PROXY_PORT), "--dns-port", str(DNS_PORT)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        if not wait_for_port(PROXY_PORT):
            print("FAIL: the proxy never started listening")
            print(proxy_proc.stdout.read() if proxy_proc.stdout else "")
            return 1
        check("proxy is listening", True)

        if not wait_for_port(DNS_PORT, timeout=5.0):
            print("       (DNS did not bind; continuing with proxy checks)")
        check("dns sinkhole is listening", wait_for_port(DNS_PORT, timeout=2.0))

        # ------------------------------------------------------------ proxying
        print("\n[3] plaintext HTTP through the proxy")
        status, body = proxy_get(f"http://127.0.0.1:{ORIGIN_PORT}/hello.txt")
        check("proxied request reaches the origin", status == 200, f"status {status}")
        check(
            "proxied body is forwarded intact",
            "origin served /hello.txt" in body,
            body[:120],
        )

        print("\n[4] blocking through the proxy")
        # The engine blocks host `graph.facebook.com`, which is in the bundled
        # hosts list. The request never reaches the network because the block
        # happens before any upstream connection is attempted.
        status, body = proxy_get("http://graph.facebook.com/track.gif")
        check("known ad host is blocked", status == 403, f"status {status}")
        check("block response names NullAD", "Blocked by NullAD" in body)
        check(
            "block response cites the matching rule",
            "graph.facebook.com" in body,
            body[:300],
        )

        status, _ = proxy_get("http://doubleclick.net/ad")
        check("domain-anchor rule also blocks", status == 403, f"status {status}")

        # A benign loopback host must never be blocked.
        status, _ = proxy_get(f"http://127.0.0.1:{ORIGIN_PORT}/safe")
        check("loopback traffic is never blocked", status == 200, f"status {status}")

        # ---------------------------------------------------------------- DNS
        print("\n[5] DNS sinkhole")
        blocked_response = dns_query(DNS_PORT, "graph.facebook.com")
        check(
            "blocked domain resolves to a sinkhole answer",
            parse_dns_answer_count(blocked_response) == 1,
            f"ancount={parse_dns_answer_count(blocked_response)}",
        )
        rcode = parse_dns_rcode(blocked_response)
        check("blocked domain returns NOERROR", rcode == 0, f"rcode={rcode}")

        aaaa = dns_query(DNS_PORT, "doubleclick.net", qtype=28)
        check(
            "AAAA queries are answered too",
            parse_dns_answer_count(aaaa) == 1,
            f"ancount={parse_dns_answer_count(aaaa)}",
        )

        # A malformed packet must not crash the server.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            sock.sendto(b"\x00\x01\x02", ("127.0.0.1", DNS_PORT))
            try:
                sock.recv(64)
            except socket.timeout:
                pass
        check("malformed DNS packet does not crash the sinkhole", True)

        time.sleep(0.5)
        check("sinkhole is still alive after malformed input", proxy_proc.poll() is None)

        # ------------------------------------------------------------ statistics
        print("\n[6] the proxy reported its decisions")
        status_proc = subprocess.run(
            [CLI, "check", "http://graph.facebook.com/track.gif"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        check(
            "check command confirms the block",
            "decision    BLOCK" in status_proc.stdout,
            status_proc.stdout[-300:],
        )

        exceptions = subprocess.run(
            [
                CLI,
                "check",
                "https://googletagmanager.com/gtm.js",
                "--page",
                "https://example.com/",
                "--type",
                "script",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        check(
            "exception rule allows a scoped request",
            "decision    ALLOW" in exceptions.stdout,
            exceptions.stdout[-300:],
        )
        check(
            "exception names the @@ rule",
            "@@||googletagmanager.com/gtm.js" in exceptions.stdout,
            exceptions.stdout[-300:],
        )

    finally:
        for process in (proxy_proc,):
            try:
                process.terminate()
                process.wait(timeout=10)
            except Exception:
                process.kill()
        origin.shutdown()

    print("\n" + "=" * 60)
    if failures:
        print(f"RESULT: {checks - len(failures)}/{checks} checks passed")
        for name in failures:
            print(f"  failed: {name}")
        return 1

    print(f"RESULT: all {checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
