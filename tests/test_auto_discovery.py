"""Port discovery and service identification against loopback fake services.

No network beyond 127.0.0.1: three fake services (SSH banner, Redis, HTTP) on
ephemeral ports, plus one port that is known to be closed.
"""

import json
import socket
import socketserver
import threading

import pytest

from suvari.auto import discovery
from suvari.auto.discovery import (
    HostProfile, OpenPort, discover, identify, parse_ports, tcp_scan,
)
from suvari.auto.jobs import JobManager, JobRunner


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve(handler_fn):
    """Start a loopback TCP server; ``handler_fn(sock, received_list)``."""
    received: list[bytes] = []

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                handler_fn(self.request, received)
            except OSError:
                pass

    srv = _Server(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], received


def _ssh(sock, rec):
    sock.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
    try:
        rec.append(sock.recv(256))
    except OSError:
        pass


def _redis(sock, rec):
    while True:
        data = sock.recv(1024)
        if not data:
            return
        rec.append(data)
        if b"PING" in data.upper():
            sock.sendall(b"+PONG\r\n")
        else:
            sock.sendall(b"-ERR unknown command\r\n")


def _http(sock, rec):
    data = sock.recv(2048)
    rec.append(data)
    body = b"<html>hello</html>"
    sock.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: "
                 + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


@pytest.fixture()
def three_services():
    servers = [_serve(_ssh), _serve(_redis), _serve(_http)]
    yield {name: (port, rec) for name, (_, port, rec) in zip(("ssh", "redis", "http"), servers)}
    for srv, _, _ in servers:
        srv.shutdown()
        srv.server_close()


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_tcp_scan_finds_open_and_skips_closed(three_services):
    open_ports = sorted(p for p, _ in three_services.values())
    closed = _closed_port()
    found = tcp_scan("127.0.0.1", open_ports + [closed], timeout=1.0)
    assert found == open_ports
    assert closed not in found


def test_scan_honours_scope_and_budget(three_services):
    ports = sorted(p for p, _ in three_services.values())
    allowed = {ports[0]}
    assert tcp_scan("127.0.0.1", ports, allow=lambda p: p in allowed) == [ports[0]]
    calls = []

    def acquire():
        calls.append(1)
        return False  # budget exhausted: nothing may be sent

    assert tcp_scan("127.0.0.1", ports, acquire=acquire, concurrency=1) == []


def test_discover_identifies_ssh_redis_http(three_services):
    ports = {name: p for name, (p, _) in three_services.items()}
    closed = _closed_port()
    prof = discover("127.0.0.1", "127.0.0.1", list(ports.values()) + [closed],
                    keyscan=False)
    by_port = {p.port: p for p in prof.open_ports}
    assert set(by_port) == set(ports.values())
    assert closed not in by_port

    ssh = by_port[ports["ssh"]]
    assert ssh.service == "ssh" and ssh.product == "OpenSSH" and ssh.version == "8.9p1"
    assert by_port[ports["redis"]].service == "redis"
    http = by_port[ports["http"]]
    assert http.service == "http" and http.product == "nginx" and http.version == "1.24.0"
    assert "22" not in prof.summary() and f"{ports['ssh']}/tcp ssh OpenSSH 8.9p1" in prof.summary()

    # nothing state-changing was sent to the fake redis
    sent = b"".join(three_services["redis"][1]).upper()
    for verb in (b"CONFIG", b"FLUSHALL", b"SET ", b"INFO"):
        assert verb not in sent


def test_profile_roundtrip():
    prof = HostProfile("h", "10.0.0.1", [OpenPort(22, service="ssh", product="OpenSSH",
                                                  version="9.6")], scanned=100)
    again = HostProfile.from_dict(json.loads(json.dumps(prof.to_dict())))
    assert again == prof
    assert again.summary() == "22/tcp ssh OpenSSH 9.6"


@pytest.mark.parametrize("port,banner,tls,service,product", [
    (2222, "SSH-2.0-OpenSSH_9.6p1 Ubuntu", False, "ssh", "OpenSSH"),
    (21, "220 (vsFTPd 3.0.5)\r\n", False, "ftp", "vsFTPd"),
    (25, "220 mail.example.com ESMTP Postfix\r\n", False, "smtp", "Postfix"),
    (110, "+OK Dovecot ready.\r\n", False, "pop3", ""),
    (143, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", False, "imap", ""),
    (5901, "RFB 003.008\n", False, "vnc", ""),
    (12345, "VERSION 1.6.21\r\n", False, "memcached", "memcached"),
    (6379, "-NOAUTH Authentication required.\r\n", False, "redis", ""),
    (3306, "J\\x00\\x00\\x00\n8.0.36\\x00", False, "mysql", "MySQL"),
    (5432, "S", False, "postgres", ""),
    (9200, 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n'
           '{"cluster_name":"x","version":{"number":"8.11.1"}}', False, "elastic",
     "Elasticsearch"),
    (2375, 'HTTP/1.1 200 OK\r\nServer: Docker/24.0.7 (linux)\r\n\r\n{"ApiVersion":"1.43",'
           '"Version":"24.0.7"}', False, "docker-api", "Docker"),
    (8443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n\r\n", True, "https", "Apache"),
    (40000, "", False, "unknown", ""),
    (445, "", False, "smb", ""),
])
def test_identify_table(port, banner, tls, service, product):
    op = identify("h", port, banner, tls)
    assert op.service == service
    assert op.product == product


def test_parse_ports():
    assert parse_ports(None) == list(discovery.TOP_PORTS)
    assert len(parse_ports("top100")) == 100
    assert parse_ports("1-1024")[:2] == [1, 2] and len(parse_ports("1-1024")) == 1024
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert len(parse_ports("all")) == 65535
    for bad in ("0", "70000", "a-b", "10-5", ""):
        with pytest.raises(ValueError):
            parse_ports(bad) if bad else parse_ports(",")


def _no_dns(host):
    raise AssertionError(f"DNS must not be queried for {host!r}")


def test_job_host_target_runs_service_checks_and_spawns_web_target(
        tmp_path, three_services, make_server):
    """A bare IP target with discovery: profile -> redis finding + one web target."""
    _, http_url = make_server()
    http_port = int(http_url.rsplit(":", 1)[1].strip("/"))
    ports = [three_services["ssh"][0], three_services["redis"][0], http_port]
    mgr = JobManager(tmp_path)
    job = mgr.create(["127.0.0.1"], rate_per_min=60000, duration=120, max_steps=6,
                     dry_run=True, resolver=_no_dns,
                     discovery={"enabled": True, "ports": ",".join(map(str, ports))})
    assert [t.kind for t in job.targets] == ["host"]

    result = JobRunner(job, mgr, resolver=_no_dns, handle_signals=False).run()
    assert result["status"] == "done"
    kinds = {t["url"]: t["kind"] for t in result["targets"]}
    assert kinds["127.0.0.1"] == "host"
    assert kinds[f"http://127.0.0.1:{http_port}/"] == "web"
    assert len(kinds) == 2

    jdir = tmp_path / job.id
    st = json.loads((jdir / "targets" / "127.0.0.1.state.json").read_text())
    services = {p["port"]: p["service"] for p in st["host"]["profile"]["open_ports"]}
    assert services[three_services["redis"][0]] == "redis"
    assert services[three_services["ssh"][0]] == "ssh"
    checks = {c["check"]: c for c in st["host"]["checks"]}
    assert checks["redis-noauth"]["status"] == "positive"
    assert any(f["check"] == "redis-noauth" and f["source"] == "service"
               for f in st["findings"])
    # requests counter includes the port-scan connects
    assert result["counters"]["requests"] >= len(ports)

    report = (jdir / job.report).read_text()
    assert "## Target: 127.0.0.1 (host)" in report
    assert "### Host profile" in report and "### Service findings" in report
    assert "redis-noauth | **ISSUE**" in report
    assert "Service findings: 1" in report


def test_job_without_discovery_keeps_bare_ip_as_web_target(tmp_path):
    mgr = JobManager(tmp_path)
    job = mgr.create(["127.0.0.1"], resolver=_no_dns)
    assert job.targets[0].kind == "web" and job.targets[0].url == "http://127.0.0.1/"
    job2 = mgr.create(["127.0.0.1:6379", "https://example.com/"], resolver=_no_dns,
                      discovery={"enabled": True})
    assert [(t.kind, t.ports) for t in job2.targets] == [("host", "6379"), ("web", "")]


class _PromptLLM:
    def __init__(self, reply):
        self.reply = reply
        self.prompts = []

    def chat(self, messages, **kw):
        self.prompts.append(messages[-1]["content"])
        return json.dumps(self.reply)


def test_planner_prompt_carries_host_profile_and_guards_ports(tmp_path):
    from suvari.auto.planner import Planner
    from suvari.auto.state import ScanState

    prof = HostProfile("127.0.0.1", "127.0.0.1", [
        OpenPort(22, service="ssh", product="OpenSSH", version="8.9"),
        OpenPort(443, service="https", tls=True, product="nginx", version="1.24"),
        OpenPort(6379, service="redis"),
        OpenPort(40000, service="unknown"),
    ]).to_dict()
    llm = _PromptLLM({"hypotheses": [
        {"title": "memcached?", "vector": "memcached-noauth", "target": "127.0.0.1:40000",
         "prior": 0.4, "rationale": "odd port"},
        {"title": "off-port", "vector": "redis-noauth", "target": "127.0.0.1:1234",
         "prior": 0.9, "rationale": "not open"},
        {"title": "other host", "vector": "redis-noauth", "target": "10.9.9.9:6379",
         "prior": 0.9, "rationale": "elsewhere"},
    ]})
    blocked = []
    planner = Planner("http://127.0.0.1/", llm=llm, host_profile=prof, service_mode=True,
                      on_blocked=lambda u, r: blocked.append(u))
    st = ScanState(tmp_path, "127.0.0.1", ["127.0.0.1"])
    planner.bootstrap(st)

    assert ("Host profile (127.0.0.1): 22/tcp ssh OpenSSH 8.9, 443/tcp https nginx 1.24, "
            "6379/tcp redis, 40000/tcp unknown") in llm.prompts[0]
    hyps = {(h.vector, h.target): h for h in st.hypotheses.values()}
    assert hyps[("ssh-weak-algos", "127.0.0.1:22")].prior == 0.5
    assert ("tls-config", "127.0.0.1:443") in hyps
    assert hyps[("redis-noauth", "127.0.0.1:6379")].prior == 0.5
    assert hyps[("svc-identify", "127.0.0.1:40000")].prior == 0.3     # unknown service
    assert ("memcached-noauth", "127.0.0.1:40000") in hyps            # llm-proposed, open port
    assert sorted(blocked) == ["10.9.9.9:6379", "127.0.0.1:1234"]
    assert all(h.max_attempts == 1 for h in st.hypotheses.values())
    # no web vectors in service mode
    assert not any(h.vector == "git-exposure" for h in st.hypotheses.values())
