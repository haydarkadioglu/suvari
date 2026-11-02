"""
Port and service discovery for host targets (no nmap required).

``tcp_scan`` finds open TCP ports with plain ``connect()`` calls, ``banner_grab``
reads what a service volunteers and — only when it stays silent — sends one
protocol-appropriate, read-only probe, and ``identify`` maps port + banner to a
service name. ``discover`` ties them together into a :class:`HostProfile`.

Every connection is gated by an optional ``allow(port)`` callback (scope) and an
optional ``acquire()`` callback (the job's global rate limiter / request
budget), so a port scan counts against ``--rate`` and ``--max-requests`` like
any HTTP probe.

Probes sent by this module are all harmless reads: an HTTP ``GET /``, a Redis
``PING``, a memcached ``version``, a MongoDB ``isMaster``, a PostgreSQL
``SSLRequest``, an RDP X.224 connection request, a DNS ``version.bind`` query,
an NTP client request and an SNMPv3 engine-discovery request (no community
string, no credentials).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Optional

log = logging.getLogger("suvari.auto.discovery")

# The 100 TCP ports most worth looking at on an internet- or LAN-facing host.
TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 514, 515, 587, 631, 636, 873, 993, 995, 1080, 1194, 1433, 1521,
    1723, 1883, 2049, 2181, 2375, 2376, 2379, 3000, 3128, 3268, 3306, 3389,
    3690, 4369, 4443, 4848, 5000, 5001, 5060, 5432, 5601, 5672, 5900, 5901,
    5984, 5985, 5986, 6000, 6379, 6443, 6666, 7001, 7077, 7474, 8000, 8008,
    8009, 8080, 8081, 8086, 8088, 8089, 8091, 8161, 8443, 8500, 8834, 8880,
    8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000,
    10250, 11211, 15672, 27017, 27018, 28017, 50000, 50070, 61616, 64738,
)
assert len(TOP_PORTS) == 100 and len(set(TOP_PORTS)) == 100

UDP_PORTS: tuple[int, ...] = (53, 123, 161)

# Port -> most likely service, used when the banner alone is not conclusive.
PORT_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 123: "ntp", 135: "msrpc", 139: "smb", 143: "imap", 161: "snmp",
    443: "https", 445: "smb", 465: "smtp", 587: "smtp", 993: "imap", 995: "pop3",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker-api",
    2376: "docker-api", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5601: "http", 5672: "amqp", 5900: "vnc", 5901: "vnc", 6379: "redis",
    8080: "http", 8443: "https", 9200: "elastic", 9300: "elastic",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb",
}

# Ports that speak TLS from the first byte.
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 4443, 5986, 6443, 8443, 9443, 10250}

BANNER_BYTES = 512
BANNER_TIMEOUT = 2.0
HTTP_SERVICES = {"http", "https", "elastic", "docker-api"}


# ── model ────────────────────────────────────────────────────────────────

@dataclass
class OpenPort:
    port: int
    proto: str = "tcp"
    service: str = "unknown"
    banner: str = ""
    tls: bool = False
    product: str = ""
    version: str = ""
    process: str = ""     # owning process, only when the host is this machine

    def label(self) -> str:
        prod = " ".join(x for x in (self.product, self.version) if x)
        return f"{self.port}/{self.proto} {self.service}" + (f" {prod}" if prod else "")

    @property
    def is_http(self) -> bool:
        return self.service in ("http", "https")


@dataclass
class HostProfile:
    host: str
    resolved_ip: str
    open_ports: list[OpenPort] = field(default_factory=list)
    ssh_hostkey: Optional[str] = None
    scanned: int = 0
    udp_scanned: int = 0
    duration: float = 0.0
    skipped: int = 0            # ports refused by scope or budget

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "HostProfile":
        d = dict(d)
        d["open_ports"] = [OpenPort(**p) for p in d.get("open_ports", [])]
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in allowed})

    def summary(self) -> str:
        """``22/tcp ssh OpenSSH 8.9p1, 443/tcp https nginx 1.24.0`` for prompts."""
        if not self.open_ports:
            return "no open ports found"
        return ", ".join(p.label() for p in self.open_ports)


# ── port specs ───────────────────────────────────────────────────────────

def parse_ports(spec: Optional[str]) -> list[int]:
    """``top100`` (default), ``all``, ``22``, ``1-1024``, ``22,80,8000-8100``."""
    s = (spec or "top100").strip().lower()
    if s in ("top100", "top", "default"):
        return list(TOP_PORTS)
    if s == "all":
        return list(range(1, 65536))
    out: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if part in ("top100", "top"):
            out.update(TOP_PORTS)
            continue
        lo_s, sep, hi_s = part.partition("-")
        if not lo_s.isdigit() or (sep and not hi_s.isdigit()):
            raise ValueError(f"invalid port spec: {part!r}")
        lo, hi = int(lo_s), int(hi_s) if sep else int(lo_s)
        if not (0 < lo <= hi < 65536):
            raise ValueError(f"port out of range: {part!r}")
        out.update(range(lo, hi + 1))
    if not out:
        raise ValueError(f"empty port spec: {spec!r}")
    return sorted(out)


# ── TCP connect scan ─────────────────────────────────────────────────────

def _family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def tcp_scan(host: str, ports: Iterable[int], timeout: float = 1.0,
             concurrency: int = 64,
             allow: Optional[Callable[[int], bool]] = None,
             acquire: Optional[Callable[[], bool]] = None) -> list[int]:
    """Return the sorted list of ports on ``host`` that accept a TCP connect.

    ``allow(port)`` is consulted before each connect (scope); ``acquire()``
    paces it (rate limiter) and returning False stops the scan. Nothing is
    written to an accepted socket — it is closed immediately.
    """
    ports = list(dict.fromkeys(ports))
    stopped = False

    def probe(port: int) -> Optional[int]:
        nonlocal stopped
        if stopped or (allow is not None and not allow(port)):
            return None
        if acquire is not None and not acquire():
            stopped = True
            return None
        try:
            with socket.socket(_family(host), socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return port
        except OSError:
            pass
        return None

    workers = max(1, min(concurrency, len(ports) or 1))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="portscan") as pool:
        found = [p for p in pool.map(probe, ports) if p is not None]
    return sorted(found)


# ── banner grabbing ──────────────────────────────────────────────────────

def _http_get(host: str, path: str = "/") -> bytes:
    h = f"[{host}]" if ":" in host else host
    return (f"GET {path} HTTP/1.0\r\nHost: {h}\r\nUser-Agent: suvari\r\n"
            f"Accept: */*\r\nConnection: close\r\n\r\n").encode()


def mongo_ismaster_query() -> bytes:
    """OP_QUERY ``{isMaster: 1}`` on ``admin.$cmd`` — the handshake every driver sends."""
    from .services import bson_encode
    doc = bson_encode({"isMaster": 1})
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + doc
    return struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body


_RDP_X224 = bytes.fromhex("030000130ee000000000000100080003000000")
_PG_SSLREQUEST = struct.pack(">ii", 8, 80877103)


def dns_query(name: str, qtype: int = 16, qclass: int = 1, tcp: bool = False,
              txid: int = 0x5356) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".") if p)
    msg = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + b"\x00" \
        + struct.pack(">HH", qtype, qclass)
    return struct.pack(">H", len(msg)) + msg if tcp else msg


def _probe_for(port: int, host: str) -> Optional[bytes]:
    """The one read-only probe sent to a port that did not speak first."""
    hint = PORT_HINTS.get(port)
    if hint == "redis":
        return b"*1\r\n$4\r\nPING\r\n"
    if hint == "memcached":
        return b"version\r\n"
    if hint == "mongodb":
        return mongo_ismaster_query()
    if hint == "postgres":
        return _PG_SSLREQUEST
    if hint == "rdp":
        return _RDP_X224
    if hint == "dns":
        return dns_query("version.bind", 16, 3, tcp=True)
    if hint in ("smb", "msrpc", "mysql", "mssql", "oracle", "nfs", "vnc"):
        return None  # binary protocols we only identify by port
    if hint == "docker-api":
        return _http_get(host, "/version")
    return _http_get(host)


def _recv(sock: socket.socket, limit: int = BANNER_BYTES,
          timeout: float = BANNER_TIMEOUT) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    deadline = time.monotonic() + timeout
    while len(buf) < limit:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            chunk = sock.recv(limit - len(buf))
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if buf.startswith(b"HTTP/") and b"\r\n\r\n" not in buf:
            continue
        if not buf.startswith(b"HTTP/"):
            # line-oriented banners: one read is enough once a line ended
            if buf.endswith(b"\n") or len(buf) >= 64:
                break
    return buf[:limit]


def _tls_wrap(sock: socket.socket, host: str) -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sni = None if re.fullmatch(r"[\d.:]+", host) else host
    return ctx.wrap_socket(sock, server_hostname=sni)


def _looks_tls(data: bytes) -> bool:
    # TLS alert / handshake record header
    return len(data) >= 3 and data[0] in (0x15, 0x16) and data[1] == 0x03


def banner_grab(host: str, port: int, timeout: float = BANNER_TIMEOUT,
                acquire: Optional[Callable[[], bool]] = None) -> tuple[str, bool]:
    """Return ``(banner, tls)`` for an open port.

    Order: TLS ports get a TLS handshake + HTTP ``GET /``; otherwise read up to
    512 bytes passively for ``timeout`` seconds, and only if the service stays
    silent send one protocol probe. A plaintext probe answered by a TLS alert
    (or a closed socket on an unknown port) is retried once over TLS.
    """
    def connect() -> socket.socket:
        if acquire is not None and not acquire():
            raise ConnectionAbortedError("request budget exhausted (not sent)")
        return socket.create_connection((host, port), timeout=timeout)

    if port in TLS_PORTS:
        data = _tls_banner(connect, host, port, timeout)
        if data is not None:
            return data, True

    try:
        with connect() as s:
            data = _recv(s, timeout=timeout)
            if not data:
                probe = _probe_for(port, host)
                if probe is not None:
                    s.sendall(probe)
                    data = _recv(s, timeout=timeout)
    except ConnectionAbortedError:
        return "", False
    except OSError as e:
        log.debug("banner %s:%s: %s", host, port, e)
        data = b""

    if (_looks_tls(data) or (not data and port not in PORT_HINTS)) \
            and port not in TLS_PORTS:
        tls = _tls_banner(connect, host, port, timeout)
        if tls is not None:
            return tls, True
    return _printable(data), False


def _tls_banner(connect, host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with connect() as raw:
            with _tls_wrap(raw, host) as s:
                s.sendall(_http_get(host, "/version" if port == 2376 else "/"))
                return _printable(_recv(s, timeout=timeout))
    except (OSError, ssl.SSLError, ConnectionAbortedError):
        return None


def _printable(data: bytes) -> str:
    """Bytes -> a printable banner (non-printables escaped, capped)."""
    out = []
    for b in data[:BANNER_BYTES]:
        if 32 <= b < 127 or b in (9, 10, 13):
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


# ── identification ───────────────────────────────────────────────────────

_FTP_RE = re.compile(r"ftp|filezilla|vsftpd|proftpd|pure-ftpd", re.I)
_SMTP_RE = re.compile(r"smtp|esmtp|postfix|exim|sendmail|mail", re.I)


def identify(host: str, port: int, banner: str, tls: bool = False) -> OpenPort:
    """Guess the service on ``port`` from its banner, falling back to the port."""
    b = banner or ""
    low = b.lower()
    op = OpenPort(port=port, banner=b[:BANNER_BYTES], tls=tls)
    hint = PORT_HINTS.get(port, "unknown")

    if b.startswith("SSH-"):
        op.service = "ssh"
        m = re.match(r"SSH-[\d.]+-([A-Za-z]+)[_-]?([\w.]*)", b)
        if m:
            op.product, op.version = m.group(1), m.group(2)
    elif b.startswith("HTTP/"):
        server = re.search(r"(?im)^server:\s*([^\r\n]+)", b)
        sv = server.group(1).strip() if server else ""
        if '"cluster_name"' in b or "you know, for search" in low or \
                "x-elastic-product" in low:
            op.service = "elastic"
            m = re.search(r'"number"\s*:\s*"([\d.]+)"', b)
            op.product, op.version = "Elasticsearch", (m.group(1) if m else "")
        elif '"apiversion"' in low or "docker/" in low:
            op.service = "docker-api"
            m = re.search(r'"Version"\s*:\s*"([^"]+)"', b)
            op.product, op.version = "Docker", (m.group(1) if m else "")
        else:
            op.service = "https" if tls else "http"
            if not sv:
                pb = re.search(r"(?im)^x-powered-by:\s*([^\r\n]+)", b)
                sv = pb.group(1).strip() if pb else ""
            if sv:
                m = re.match(r"([^/\s]+)(?:/(\S+))?", sv)
                op.product = m.group(1) if m else sv
                op.version = (m.group(2) or "") if m else ""
    elif b.startswith(("+PONG", "-NOAUTH", "-DENIED", "-ERR")) or \
            (hint == "redis" and b.startswith(("+", "-"))):
        op.service = "redis"
    elif b.startswith("VERSION ") or b.startswith("STAT "):
        op.service = "memcached"
        m = re.match(r"VERSION (\S+)", b)
        op.product, op.version = "memcached", (m.group(1) if m else "")
    elif b.startswith("RFB "):
        op.service = "vnc"
        op.version = b[4:11].strip()
    elif b.startswith("220"):
        if _FTP_RE.search(b) and not _SMTP_RE.search(b.replace("FTP", "")):
            op.service = "ftp"
        elif _SMTP_RE.search(b) or hint == "smtp":
            op.service = "smtp"
        else:
            op.service = "ftp" if hint != "smtp" else "smtp"
        m = re.search(r"(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Postfix|Exim|Sendmail)"
                      r"[ /]?([\d.]+[a-z]?)?", b, re.I)
        if m:
            op.product, op.version = m.group(1), m.group(2) or ""
    elif b.startswith("+OK"):
        op.service = "pop3"
    elif b.startswith("* OK") or "imap" in low[:80]:
        op.service = "imap"
    elif "ismaster" in low or "iswritableprimary" in low or "maxwireversion" in low:
        op.service = "mongodb"
    elif _is_mysql(b):
        op.service = "mysql"
        m = re.search(r"\\x00\n(\d[\w.\-]*)", b)
        if m:
            op.version = m.group(1)
            op.product = "MariaDB" if "mariadb" in low else "MySQL"
    elif hint == "postgres" and b in ("S", "N", "E"):
        op.service = "postgres"
    elif b.startswith("\\x03\\x00") and hint in ("rdp", "unknown"):
        op.service = "rdp"
    elif hint == "dns" and b.startswith("\\x00"):
        op.service = "dns"
    elif tls:
        op.service = "https" if hint in ("https", "unknown", "http") else hint
    else:
        op.service = hint
    if tls and op.service == "http":
        op.service = "https"
    return op


def _is_mysql(b: str) -> bool:
    # handshake v10: 3-byte length, seq 0 (escaped \x00), protocol 0x0a
    # (kept as a literal newline by _printable), then the version string
    return bool(re.match(r"^.{1,16}\\x00\n\d", b)) or \
        "mysql_native_password" in b or "caching_sha2_password" in b


# ── UDP (opt-in, three ports only) ───────────────────────────────────────

def _snmpv3_discovery() -> bytes:
    """SNMPv3 engine-ID discovery request: noAuthNoPriv, empty user, no community."""
    def tlv(tag: int, val: bytes) -> bytes:
        n = len(val)
        ln = bytes([n]) if n < 128 else bytes([0x81, n])
        return bytes([tag]) + ln + val

    def integer(v: int) -> bytes:
        return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))

    msgid = 0x5356
    header = tlv(0x30, integer(msgid) + integer(65507) + tlv(0x04, b"\x04") + integer(3))
    usm = tlv(0x04, tlv(0x30, tlv(0x04, b"") + integer(0) + integer(0)
                        + tlv(0x04, b"") + tlv(0x04, b"") + tlv(0x04, b"")))
    pdu = tlv(0xA0, integer(msgid) + integer(0) + integer(0) + tlv(0x30, b""))
    scoped = tlv(0x30, tlv(0x04, b"") + tlv(0x04, b"") + pdu)
    return tlv(0x30, integer(3) + header + usm + scoped)


_UDP_PROBES = {
    53: lambda: dns_query("version.bind", 16, 3),
    123: lambda: b"\x1b" + b"\x00" * 47,   # NTP v3 client time request
    161: _snmpv3_discovery,
}
_UDP_SERVICE = {53: "dns", 123: "ntp", 161: "snmp"}


def udp_scan(host: str, ports: Iterable[int] = UDP_PORTS, timeout: float = 2.0,
             allow: Optional[Callable[[int], bool]] = None,
             acquire: Optional[Callable[[], bool]] = None) -> list[OpenPort]:
    """Probe 53/123/161 with one harmless datagram each; a reply means open."""
    found = []
    for port in ports:
        if port not in _UDP_PROBES or (allow is not None and not allow(port)):
            continue
        if acquire is not None and not acquire():
            break
        try:
            with socket.socket(_family(host), socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(_UDP_PROBES[port](), (host, port))
                data, _ = s.recvfrom(BANNER_BYTES)
        except OSError:
            continue
        if data:
            found.append(OpenPort(port=port, proto="udp", service=_UDP_SERVICE[port],
                                  banner=_printable(data)[:200]))
    return found


# ── ssh host key (optional, via ssh-keyscan) ─────────────────────────────

def ssh_hostkey(host: str, port: int, timeout: int = 3) -> Optional[str]:
    """``ssh-ed25519 SHA256:…`` via ``ssh-keyscan`` when installed, else None."""
    exe = shutil.which("ssh-keyscan")
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, "-T", str(timeout), "-p", str(port), host],
                              capture_output=True, text=True, timeout=timeout + 2,
                              shell=False)
    except (OSError, subprocess.SubprocessError):
        return None
    keys = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            try:
                digest = hashlib.sha256(base64.b64decode(parts[2])).digest()
            except ValueError:
                continue
            fp = base64.b64encode(digest).decode().rstrip("=")
            keys.append(f"{parts[1]} SHA256:{fp}")
    return "; ".join(keys) or None


def is_local_address(ip: str) -> bool:
    """True if ``ip`` belongs to this machine (loopback or a local interface)."""
    try:
        with socket.socket(_family(ip), socket.SOCK_DGRAM) as s:
            s.bind((ip, 0))
        return True
    except OSError:
        return False


# ── orchestration ────────────────────────────────────────────────────────

def discover(host: str, resolved_ip: str, ports: Iterable[int], *,
             udp: bool = False, timeout: float = 1.0, concurrency: int = 64,
             allow: Optional[Callable[[int], bool]] = None,
             acquire: Optional[Callable[[], bool]] = None,
             keyscan: bool = True) -> HostProfile:
    """Scan, banner-grab and identify every open port on one host."""
    t0 = time.monotonic()
    ports = list(ports)
    allowed = [p for p in ports if allow is None or allow(p)]
    prof = HostProfile(host=host, resolved_ip=resolved_ip, scanned=len(allowed),
                       skipped=len(ports) - len(allowed))
    open_tcp = tcp_scan(resolved_ip, allowed, timeout=timeout,
                        concurrency=concurrency, acquire=acquire)

    def grab(port: int) -> OpenPort:
        banner, tls = banner_grab(resolved_ip, port, acquire=acquire)
        return identify(host, port, banner, tls)

    with ThreadPoolExecutor(max_workers=max(1, min(16, len(open_tcp) or 1)),
                            thread_name_prefix="banner") as pool:
        prof.open_ports = list(pool.map(grab, open_tcp))

    if udp:
        prof.udp_scanned = len(UDP_PORTS)
        prof.open_ports += udp_scan(resolved_ip, allow=allow, acquire=acquire)

    if prof.open_ports and is_local_address(resolved_ip):
        try:
            from .local import port_owners
            owners = port_owners()
        except Exception:  # noqa: BLE001 - annotation only
            owners = {}
        for p in prof.open_ports:
            p.process = owners.get((p.proto, p.port), "")

    if keyscan:
        for p in prof.open_ports:
            if p.service == "ssh":
                prof.ssh_hostkey = ssh_hostkey(resolved_ip, p.port)
                break
    prof.duration = round(time.monotonic() - t0, 3)
    return prof
