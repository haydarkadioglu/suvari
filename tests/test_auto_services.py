"""Read-only protocol checks against loopback fake services.

Every fake server records everything it receives so the tests can prove that
no write/state-changing command was ever sent.
"""

import json
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from suvari.auto import services
from suvari.auto.services import (
    UnsafeCommand, assert_read_only, bson_decode, bson_encode, run_check,
)

WRITE_VERBS = (b"CONFIG", b"FLUSHALL", b"FLUSHDB", b"SET ", b"DEL ", b"SLAVEOF",
               b"REPLICAOF", b"SHUTDOWN", b"FLUSH_ALL", b"DELETE", b"STOR", b"RETR",
               b"LIST", b"INFO")


class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def tcp_server(fn):
    received: list[bytes] = []

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                fn(self.request, received)
            except OSError:
                pass

    srv = _TCP(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], received


def http_server(routes: dict):
    """routes: path -> (status, json-able body). Records (method, path)."""
    seen: list[tuple[str, str]] = []

    class H(BaseHTTPRequestHandler):
        def _any(self):
            seen.append((self.command, self.path))
            status, body = routes.get(self.path.split("?")[0], (404, {"error": "nope"}))
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_HEAD = do_PUT = do_POST = do_DELETE = _any

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], seen


@pytest.fixture()
def servers():
    started = []

    def track(res):
        started.append(res[0])
        return res

    yield track
    for s in started:
        s.shutdown()
        s.server_close()


def _assert_no_writes(received: list[bytes]):
    blob = b"".join(received).upper()
    for verb in WRITE_VERBS:
        assert verb not in blob, f"{verb!r} was sent: {blob[:200]!r}"


# ── redis ────────────────────────────────────────────────────────────────

def _fake_redis(reply: bytes):
    def fn(sock, rec):
        while True:
            data = sock.recv(1024)
            if not data:
                return
            rec.append(data)
            sock.sendall(reply if b"PING" in data else b"-ERR unknown command\r\n")
    return fn


def test_redis_pong_is_unauthenticated_access(servers):
    _, port, rec = servers(tcp_server(_fake_redis(b"+PONG\r\n")))
    r = run_check("redis-noauth", "127.0.0.1", port)
    assert r.status == "positive" and r.severity == "HIGH" and r.safe
    assert "without authentication" in r.detail
    assert r.sent == ["PING"]
    assert rec == [b"*1\r\n$4\r\nPING\r\n"]
    _assert_no_writes(rec)


def test_redis_noauth_reply_is_negative(servers):
    _, port, rec = servers(tcp_server(_fake_redis(b"-NOAUTH Authentication required.\r\n")))
    r = run_check("redis-noauth", "127.0.0.1", port)
    assert r.status == "negative" and r.severity == "INFO"
    _assert_no_writes(rec)


# ── memcached ────────────────────────────────────────────────────────────

def test_memcached_stats_is_unauthenticated_access(servers):
    def fn(sock, rec):
        data = sock.recv(1024)
        rec.append(data)
        sock.sendall(b"STAT pid 42\r\nSTAT version 1.6.21\r\nSTAT curr_items 7\r\nEND\r\n")

    _, port, rec = servers(tcp_server(fn))
    r = run_check("memcached-noauth", "127.0.0.1", port)
    assert r.status == "positive"
    assert "version=1.6.21" in r.evidence and "curr_items=7" in r.evidence
    assert rec == [b"stats\r\n"]
    _assert_no_writes(rec)


# ── elastic ──────────────────────────────────────────────────────────────

def test_elastic_open_cluster(servers):
    _, port, seen = servers(http_server({
        "/": (200, {"name": "n1", "cluster_name": "prod", "version": {"number": "7.17.9"},
                    "tagline": "You Know, for Search"}),
        "/_cat/indices": (200, [{"index": "users"}, {"index": "orders"}]),
    }))
    r = run_check("elastic-noauth", "127.0.0.1", port)
    assert r.status == "positive" and r.severity == "HIGH"
    assert "2 indices" in r.evidence and "users" not in r.evidence  # names not recorded
    assert {m for m, _ in seen} == {"GET"}
    assert [p.split("?")[0] for _, p in seen] == ["/", "/_cat/indices"]


def test_elastic_auth_required(servers):
    _, port, seen = servers(http_server({"/": (401, {"error": "security_exception"})}))
    r = run_check("elastic-noauth", "127.0.0.1", port)
    assert r.status == "negative"
    assert seen == [("GET", "/")]


# ── docker api ───────────────────────────────────────────────────────────

def test_docker_api_exposed(servers):
    _, port, seen = servers(http_server({
        "/version": (200, {"Version": "24.0.7", "ApiVersion": "1.43", "Os": "linux"}),
        "/containers/json": (200, [{"Id": "abc"}, {"Id": "def"}, {"Id": "ghi"}]),
    }))
    r = run_check("docker-api-noauth", "127.0.0.1", port)
    assert r.status == "positive" and r.severity == "CRITICAL"
    assert "3 running containers" in r.evidence and "abc" not in r.evidence
    assert seen == [("GET", "/version"), ("GET", "/containers/json")]


# ── mongodb ──────────────────────────────────────────────────────────────

def _mongo_reply_op_reply(doc: dict) -> bytes:
    body = struct.pack("<iqii", 0, 0, 0, 1) + bson_encode(doc)
    return struct.pack("<iiii", 16 + len(body), 1, 1, 1) + body


def _mongo_reply_op_msg(doc: dict) -> bytes:
    body = struct.pack("<I", 0) + b"\x00" + bson_encode(doc)
    return struct.pack("<iiii", 16 + len(body), 1, 2, 2013) + body


def _read_msg(sock) -> bytes:
    head = b""
    while len(head) < 4:
        head += sock.recv(4 - len(head))
    (n,) = struct.unpack("<i", head)
    rest = b""
    while len(rest) < n - 4:
        rest += sock.recv(n - 4 - len(rest))
    return head + rest


def test_mongodb_lists_databases_without_auth(servers):
    def fn(sock, rec):
        q = _read_msg(sock)
        rec.append(q)
        assert struct.unpack("<i", q[12:16])[0] == 2004  # OP_QUERY isMaster
        sock.sendall(_mongo_reply_op_reply({"ismaster": True, "maxWireVersion": 17, "ok": 1.0}))
        m = _read_msg(sock)
        rec.append(m)
        cmd = bson_decode(m[21:])
        assert cmd == {"listDatabases": 1, "nameOnly": True, "$db": "admin"}
        sock.sendall(_mongo_reply_op_msg({"databases": [{"name": "a"}, {"name": "b"}],
                                          "ok": 1.0}))

    _, port, rec = servers(tcp_server(fn))
    r = run_check("mongodb-noauth", "127.0.0.1", port)
    assert r.status == "positive" and r.severity == "CRITICAL", r.detail
    assert "2 databases" in r.detail
    assert r.sent == ["isMaster", "listDatabases nameOnly"]


def test_mongodb_auth_required(servers):
    def fn(sock, rec):
        rec.append(_read_msg(sock))
        sock.sendall(_mongo_reply_op_reply({"ismaster": True, "maxWireVersion": 17, "ok": 1.0}))
        rec.append(_read_msg(sock))
        sock.sendall(_mongo_reply_op_msg({"ok": 0.0, "code": 13,
                                          "errmsg": "command listDatabases requires authentication"}))

    _, port, _ = servers(tcp_server(fn))
    assert run_check("mongodb-noauth", "127.0.0.1", port).status == "negative"


def test_bson_roundtrip():
    doc = {"a": 1, "b": "x", "c": True, "d": 1.5, "e": {"f": None}, "g": 2**40,
           "h": [1, "two", {"three": 3}]}
    assert bson_decode(bson_encode(doc)) == doc


# ── ftp / smtp / vnc / ssh / dns ─────────────────────────────────────────

def test_ftp_anonymous_login_only_no_listing(servers):
    def fn(sock, rec):
        sock.sendall(b"220 (vsFTPd 3.0.5)\r\n")
        while True:
            data = sock.recv(1024)
            if not data:
                return
            rec.append(data)
            if data.startswith(b"USER"):
                sock.sendall(b"331 Please specify the password.\r\n")
            elif data.startswith(b"PASS"):
                sock.sendall(b"230 Login successful.\r\n")
            elif data.startswith(b"QUIT"):
                sock.sendall(b"221 Goodbye.\r\n")
                return

    _, port, rec = servers(tcp_server(fn))
    r = run_check("ftp-anonymous", "127.0.0.1", port)
    assert r.status == "positive"
    assert [x.split()[0] for x in rec] == [b"USER", b"PASS", b"QUIT"]
    _assert_no_writes(rec)


def test_smtp_without_starttls(servers):
    def fn(sock, rec):
        sock.sendall(b"220 mx.example.com ESMTP Postfix\r\n")
        data = sock.recv(1024)
        rec.append(data)
        sock.sendall(b"250-mx.example.com\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
        rec.append(sock.recv(1024))
        sock.sendall(b"221 Bye\r\n")

    _, port, rec = servers(tcp_server(fn))
    r = run_check("smtp-starttls", "127.0.0.1", port)
    assert r.status == "positive" and r.severity == "MEDIUM"
    assert "cleartext" in r.detail
    # banner + EHLO only — no relay test (no MAIL FROM / RCPT TO)
    blob = b"".join(rec).upper()
    assert b"MAIL FROM" not in blob and b"RCPT" not in blob


def test_vnc_security_type_none(servers):
    def fn(sock, rec):
        sock.sendall(b"RFB 003.008\n")
        rec.append(sock.recv(12))
        sock.sendall(bytes([2, 1, 2]))   # None, VNC auth
        try:
            rec.append(sock.recv(16))     # client must not choose a type
        except OSError:
            pass

    _, port, rec = servers(tcp_server(fn))
    r = run_check("vnc-noauth", "127.0.0.1", port)
    assert r.status == "positive" and "[1, 2]" in r.evidence
    assert rec[0] == b"RFB 003.008\n" and rec[1:] in ([], [b""])


def _kexinit(kex, hostkey, cipher, mac) -> bytes:
    lists = [kex, hostkey, cipher, cipher, mac, mac, "none", "none", "", ""]
    payload = bytes([20]) + b"\x00" * 16
    for n in lists:
        payload += struct.pack(">I", len(n)) + n.encode()
    payload += b"\x00" + struct.pack(">I", 0)
    pad = 8 - (len(payload) + 5) % 8 + 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def test_ssh_weak_algorithms_from_server_kexinit(servers):
    def fn(sock, rec):
        sock.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
        rec.append(sock.recv(256))
        sock.sendall(_kexinit("curve25519-sha256,diffie-hellman-group1-sha1",
                              "ssh-ed25519,ssh-rsa", "aes128-ctr,aes128-cbc", "hmac-sha2-256"))

    _, port, rec = servers(tcp_server(fn))
    r = run_check("ssh-weak-algos", "127.0.0.1", port)
    assert r.status == "positive" and r.severity == "MEDIUM"
    assert "kex:diffie-hellman-group1-sha1" in r.detail and "hostkey:ssh-rsa" in r.detail
    assert "cipher:aes128-cbc" in r.detail
    assert rec == [b"SSH-2.0-Suvari_Probe\r\n"]


def test_dns_axfr_allowed(servers):
    def fn(sock, rec):
        head = sock.recv(2)
        (n,) = struct.unpack(">H", head)
        q = sock.recv(n)
        rec.append(q)
        assert struct.unpack(">H", q[-4:-2])[0] == 252  # AXFR
        msg = q[:2] + struct.pack(">HHHHH", 0x8400, 1, 5, 0, 0) + q[12:]
        sock.sendall(struct.pack(">H", len(msg)) + msg)

    _, port, _ = servers(tcp_server(fn))
    r = run_check("dns-axfr", "127.0.0.1", port, meta={"zones": ["example.com"]})
    assert r.status == "positive" and "example.com" in r.detail
    r = run_check("dns-axfr", "127.0.0.1", port, meta={"zones": []})
    assert r.status == "inconclusive"


def test_closed_port_is_error_not_finding():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    r = run_check("redis-noauth", "127.0.0.1", port)
    assert r.status == "error" and not r.positive


# ── read-only guard ──────────────────────────────────────────────────────

@pytest.mark.parametrize("proto,payload", [
    ("redis", b"*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n"),
    ("redis", b"FLUSHALL\r\n"),
    ("redis", b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"),
    ("memcached", b"flush_all\r\n"),
    ("memcached", b"set k 0 0 1\r\n"),
    ("ftp", b"STOR x\r\n"),
    ("ftp", b"LIST\r\n"),
    ("http", b"PUT /x HTTP/1.1\r\n"),
    ("http", b"DELETE /_all HTTP/1.1\r\n"),
])
def test_read_only_guard_refuses_writes(proto, payload):
    with pytest.raises(UnsafeCommand):
        assert_read_only(proto, payload)


def test_read_only_guard_allows_probes():
    for proto, payload in (("redis", b"*1\r\n$4\r\nPING\r\n"), ("memcached", b"stats\r\n"),
                           ("ftp", b"USER anonymous\r\n"), ("http", b"GET / HTTP/1.0\r\n")):
        assert_read_only(proto, payload)


def test_every_check_has_a_recommendation_and_severity():
    for key in services.CHECKS:
        assert key in services.CHECK_SEVERITY
        if key != "svc-identify":
            assert key in services.RECOMMENDATIONS
