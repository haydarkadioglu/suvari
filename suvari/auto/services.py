"""
Read-only protocol checks for non-HTTP services found by discovery.

Rules every check obeys:
  * no password guessing — the only login attempted anywhere is the FTP
    ``anonymous`` account, which is a published convention, not a credential;
  * no write or state-changing commands — every outgoing payload passes
    :func:`assert_read_only`, which refuses ``CONFIG``/``SET``/``FLUSHALL``/
    ``PUT``/``DELETE``/… before a byte is sent;
  * one attempt, one connection per question, 3-second socket timeout;
  * no data extraction — counts and versions are recorded, never keys,
    documents, index contents or file listings.

Each check returns a :class:`CheckResult` (``{service, check, safe: true,
evidence, …}``) with ``status`` one of ``positive`` (issue present),
``negative`` (issue absent), ``inconclusive`` (could not be decided, e.g. an
optional tool is missing) or ``error`` (the service could not be talked to).
"""

from __future__ import annotations

import datetime as _dt
import http.client
import json
import logging
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from .discovery import _http_get, _printable, _tls_wrap, dns_query, mongo_ismaster_query

log = logging.getLogger("suvari.auto.services")

CHECK_TIMEOUT = 3.0
READ_CAP = 8192

POSITIVE, NEGATIVE, INCONCLUSIVE, ERROR = "positive", "negative", "inconclusive", "error"


@dataclass
class CheckResult:
    service: str
    check: str
    host: str
    port: int
    status: str = INCONCLUSIVE
    severity: str = "INFO"
    title: str = ""
    detail: str = ""
    evidence: str = ""
    sent: list = field(default_factory=list)     # what was sent, for the record
    safe: bool = True
    duration: float = 0.0
    spawn: list = field(default_factory=list)    # services identified (svc-identify)

    @property
    def positive(self) -> bool:
        return self.status == POSITIVE

    def to_dict(self) -> dict:
        return asdict(self)


class UnsafeCommand(RuntimeError):
    """Raised if a check ever tries to send a state-changing command."""


# ── read-only guard ──────────────────────────────────────────────────────

_WRITE_WORDS = {
    # redis
    "config", "set", "setex", "mset", "del", "unlink", "flushall", "flushdb",
    "save", "bgsave", "bgrewriteaof", "shutdown", "slaveof", "replicaof",
    "module", "eval", "evalsha", "script", "debug", "migrate", "restore",
    "rename", "expire", "lpush", "rpush", "sadd", "hset", "zadd", "xadd",
    "incr", "decr", "append", "acl", "failover", "cluster",
    # memcached
    "add", "replace", "cas", "prepend", "delete", "touch", "flush_all",
    "verbosity", "shutdown", "lru_crawler", "slabs",
    # ftp
    "stor", "stou", "appe", "dele", "rmd", "mkd", "rnfr", "rnto", "site",
    "list", "nlst", "retr",
}
_HTTP_WRITE = {"PUT", "POST", "DELETE", "PATCH"}


def assert_read_only(proto: str, payload: bytes) -> None:
    """Refuse any payload whose command verb could change server state."""
    text = payload.decode("latin-1", "replace")
    if proto == "http":
        method = text.split(" ", 1)[0].upper()
        if method in _HTTP_WRITE or method not in ("GET", "HEAD"):
            raise UnsafeCommand(f"refusing HTTP {method}")
        return
    if proto == "redis":
        words = [w for w in re.split(r"\r\n", text) if w and not w[0] in "*$"]
        verb = (words[0] if words else text.split()[0] if text.split() else "").lower()
    elif proto in ("memcached", "ftp", "smtp"):
        verb = (text.split() or [""])[0].lower()
    else:
        return  # binary protocols are built from fixed read-only templates
    if verb in _WRITE_WORDS:
        raise UnsafeCommand(f"refusing {proto} command {verb.upper()}")


class _Conn:
    """One TCP (optionally TLS) connection that records and vets what it sends."""

    def __init__(self, host: str, port: int, proto: str, timeout: float,
                 sent: list, tls: bool = False):
        self.proto = proto
        self.sent = sent
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        if tls:
            self.sock = _tls_wrap(self.sock, host)

    def send(self, data: bytes, label: Optional[str] = None) -> None:
        assert_read_only(self.proto, data)
        self.sent.append(label or _printable(data)[:120])
        self.sock.sendall(data)

    def recv_until(self, done: Callable[[bytes], bool], cap: int = READ_CAP) -> bytes:
        buf = b""
        while len(buf) < cap and not done(buf):
            try:
                chunk = self.sock.recv(cap - len(buf))
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def recv_line_reply(self) -> bytes:
        """Read an FTP/SMTP reply, including ``NNN-`` continuation lines."""
        def done(b: bytes) -> bool:
            if not b.endswith(b"\n"):
                return False
            last = b.rstrip(b"\r\n").split(b"\n")[-1].strip(b"\r")
            return re.match(rb"^\d{3}( |$)", last) is not None
        return self.recv_until(done)

    def read_into(self, buf: bytes, n: int) -> bytes:
        """Extend ``buf`` until it holds at least ``n`` bytes (or EOF/timeout)."""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(min(READ_CAP * 8, n - len(buf)))
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def recv_exact(self, n: int) -> bytes:
        return self.recv_until(lambda b: len(b) >= n, cap=n)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ── BSON (just enough for isMaster / listDatabases) ──────────────────────

def bson_encode(doc: dict) -> bytes:
    out = b""
    for k, v in doc.items():
        key = k.encode() + b"\x00"
        if isinstance(v, bool):
            out += b"\x08" + key + (b"\x01" if v else b"\x00")
        elif isinstance(v, int):
            out += (b"\x10" + key + struct.pack("<i", v)) if -2**31 <= v < 2**31 \
                else (b"\x12" + key + struct.pack("<q", v))
        elif isinstance(v, float):
            out += b"\x01" + key + struct.pack("<d", v)
        elif isinstance(v, str):
            s = v.encode() + b"\x00"
            out += b"\x02" + key + struct.pack("<i", len(s)) + s
        elif isinstance(v, dict):
            out += b"\x03" + key + bson_encode(v)
        elif isinstance(v, list):
            out += b"\x04" + key + bson_encode({str(i): x for i, x in enumerate(v)})
        elif v is None:
            out += b"\x0a" + key
        else:
            raise TypeError(f"bson: unsupported {type(v).__name__}")
    return struct.pack("<i", len(out) + 5) + out + b"\x00"


def bson_decode(data: bytes) -> dict:
    (n,) = struct.unpack_from("<i", data, 0)
    return _bson_doc(data[:n], 4)[0]


def _bson_doc(data: bytes, i: int, end: Optional[int] = None) -> tuple[dict, int]:
    end = len(data) - 1 if end is None else end
    out: dict = {}
    while i < end and data[i] != 0:
        t = data[i]
        j = data.index(b"\x00", i + 1)
        key = data[i + 1:j].decode("utf-8", "replace")
        i = j + 1
        if t == 0x01:
            out[key] = struct.unpack_from("<d", data, i)[0]; i += 8
        elif t == 0x02:
            (ln,) = struct.unpack_from("<i", data, i)
            out[key] = data[i + 4:i + 3 + ln].decode("utf-8", "replace"); i += 4 + ln
        elif t in (0x03, 0x04):
            (ln,) = struct.unpack_from("<i", data, i)
            sub, _ = _bson_doc(data, i + 4, i + ln - 1)
            out[key] = list(sub.values()) if t == 0x04 else sub
            i += ln
        elif t == 0x05:
            (ln,) = struct.unpack_from("<i", data, i); i += 5 + ln
        elif t == 0x07:
            out[key] = data[i:i + 12].hex(); i += 12
        elif t == 0x08:
            out[key] = data[i] == 1; i += 1
        elif t in (0x09, 0x11, 0x12):
            out[key] = struct.unpack_from("<q", data, i)[0]; i += 8
        elif t == 0x0A:
            out[key] = None
        elif t == 0x10:
            out[key] = struct.unpack_from("<i", data, i)[0]; i += 4
        elif t == 0x13:
            i += 16
        else:
            break  # unknown type: stop rather than misparse
    return out, i


def _mongo_read(c: _Conn) -> dict:
    head = c.recv_exact(16)
    if len(head) < 16:
        raise ConnectionError("short MongoDB reply")
    length, _rid, _to, opcode = struct.unpack("<iiii", head)
    if not 16 < length <= 1 << 20:
        raise ConnectionError(f"bad MongoDB reply length {length}")
    body = c.recv_exact(length - 16)
    if opcode == 1:        # OP_REPLY: flags, cursor, start, count, docs
        return bson_decode(body[20:])
    if opcode == 2013:     # OP_MSG: flags, kind-0 section, doc
        return bson_decode(body[5:])
    raise ConnectionError(f"unexpected MongoDB opcode {opcode}")


def _mongo_op_msg(doc: dict) -> bytes:
    body = struct.pack("<I", 0) + b"\x00" + bson_encode(doc)
    return struct.pack("<iiii", 16 + len(body), 2, 0, 2013) + body


def _mongo_op_query(doc: dict) -> bytes:
    bdoc = bson_encode(doc)
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + bdoc
    return struct.pack("<iiii", 16 + len(body), 3, 0, 2004) + body


# ── HTTP helper ──────────────────────────────────────────────────────────

def _http(host: str, port: int, path: str, tls: bool, timeout: float,
          sent: list) -> tuple[int, dict, str]:
    """One read-only GET; returns (status, headers, body[:READ_CAP])."""
    assert_read_only("http", f"GET {path}".encode())
    sent.append(f"GET {path}")
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "suvari", "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(READ_CAP).decode("utf-8", "replace")
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body
    finally:
        conn.close()


def _json(body: str):
    try:
        return json.loads(body)
    except ValueError:
        return None


# ── checks ───────────────────────────────────────────────────────────────

def check_redis(r: CheckResult, timeout: float, meta: dict) -> None:
    with _Conn(r.host, r.port, "redis", timeout, r.sent) as c:
        c.send(b"*1\r\n$4\r\nPING\r\n", "PING")
        reply = c.recv_until(lambda b: b.endswith(b"\r\n"))
    text = reply.decode("latin-1", "replace").strip()
    r.evidence = f"PING -> {text[:120]!r}"
    if text.startswith("+PONG"):
        r.status, r.severity = POSITIVE, "HIGH"
        r.detail = "Redis answered PING without authentication (unauthenticated access)"
    elif text.startswith(("-NOAUTH", "-WRONGPASS")):
        r.status, r.detail = NEGATIVE, "Redis requires authentication"
    elif text.startswith("-DENIED"):
        r.status, r.detail = NEGATIVE, "Redis protected mode refused the remote client"
    else:
        r.status, r.detail = INCONCLUSIVE, "unexpected reply to PING"


def check_memcached(r: CheckResult, timeout: float, meta: dict) -> None:
    with _Conn(r.host, r.port, "memcached", timeout, r.sent) as c:
        c.send(b"stats\r\n", "stats")
        reply = c.recv_until(lambda b: b.endswith(b"END\r\n") or b.startswith(b"ERROR"))
    text = reply.decode("latin-1", "replace")
    stats = dict(re.findall(r"STAT (\S+) (\S+)", text))
    if "pid" in stats or "version" in stats:
        r.status, r.severity = POSITIVE, "HIGH"
        r.detail = "memcached answers `stats` without authentication"
        r.evidence = (f"version={stats.get('version', '?')} "
                      f"curr_items={stats.get('curr_items', '?')} "
                      f"curr_connections={stats.get('curr_connections', '?')}")
    elif "ERROR" in text or "unauthorized" in text.lower():
        r.status, r.detail = NEGATIVE, "memcached refused `stats` (SASL or ACL enabled)"
        r.evidence = text[:120]
    else:
        r.status, r.detail = INCONCLUSIVE, "no stats reply"
        r.evidence = _printable(reply)[:120]


def check_mongodb(r: CheckResult, timeout: float, meta: dict) -> None:
    with _Conn(r.host, r.port, "mongodb", timeout, r.sent) as c:
        c.send(mongo_ismaster_query(), "isMaster")
        hello = _mongo_read(c)
        wire = int(hello.get("maxWireVersion", 0) or 0)
        cmd = {"listDatabases": 1, "nameOnly": True}
        if wire >= 6:
            c.send(_mongo_op_msg({**cmd, "$db": "admin"}), "listDatabases nameOnly")
        else:
            c.send(_mongo_op_query(cmd), "listDatabases nameOnly")
        reply = _mongo_read(c)
    ev = f"isMaster: maxWireVersion={wire} ismaster={hello.get('ismaster', hello.get('isWritablePrimary'))}"
    dbs = reply.get("databases")
    if reply.get("ok") in (1, 1.0, True) and isinstance(dbs, list):
        r.status, r.severity = POSITIVE, "CRITICAL"
        r.detail = (f"MongoDB lists databases without authentication "
                    f"({len(dbs)} databases; names not recorded)")
        r.evidence = ev + f"; listDatabases ok, {len(dbs)} databases"
    elif reply.get("code") == 13 or "auth" in str(reply.get("errmsg", "")).lower():
        r.status, r.detail = NEGATIVE, "MongoDB requires authentication"
        r.evidence = ev + f"; listDatabases: {str(reply.get('errmsg'))[:100]}"
    else:
        r.status, r.detail = INCONCLUSIVE, "unexpected listDatabases reply"
        r.evidence = ev + f"; reply keys={sorted(reply)[:8]}"


def check_elastic(r: CheckResult, timeout: float, meta: dict) -> None:
    tls = bool(meta.get("tls"))
    st, _, body = _http(r.host, r.port, "/", tls, timeout, r.sent)
    info = _json(body) or {}
    if st in (401, 403):
        r.status, r.detail = NEGATIVE, f"Elasticsearch requires authentication (HTTP {st})"
        r.evidence = f"GET / -> {st}"
        return
    if st != 200 or "cluster_name" not in info:
        r.status, r.detail = INCONCLUSIVE, f"not an Elasticsearch root (HTTP {st})"
        r.evidence = f"GET / -> {st}"
        return
    ver = (info.get("version") or {}).get("number", "?")
    st2, _, body2 = _http(r.host, r.port, "/_cat/indices?format=json&h=index", tls,
                          timeout, r.sent)
    idx = _json(body2)
    n = len(idx) if isinstance(idx, list) else "?"
    r.evidence = (f"GET / -> 200 cluster_name={info.get('cluster_name')!r} version={ver}; "
                  f"GET /_cat/indices -> {st2} ({n} indices; names not recorded)")
    if st2 == 200:
        r.status, r.severity = POSITIVE, "HIGH"
        r.detail = f"Elasticsearch {ver} serves cluster info and index list without authentication"
    else:
        r.status, r.severity = POSITIVE, "MEDIUM"
        r.detail = f"Elasticsearch {ver} root is readable without authentication"


def check_docker(r: CheckResult, timeout: float, meta: dict) -> None:
    tls = bool(meta.get("tls")) or r.port == 2376
    try:
        st, _, body = _http(r.host, r.port, "/version", tls, timeout, r.sent)
    except ssl.SSLError as e:
        r.status, r.detail = NEGATIVE, "Docker API requires a TLS client certificate"
        r.evidence = f"TLS handshake: {e.reason or e}"
        return
    info = _json(body) or {}
    if st != 200 or "ApiVersion" not in info:
        r.status = NEGATIVE if st in (401, 403) else INCONCLUSIVE
        r.detail, r.evidence = f"/version -> HTTP {st}", f"GET /version -> {st}"
        return
    st2, _, body2 = _http(r.host, r.port, "/containers/json", tls, timeout, r.sent)
    cont = _json(body2)
    n = len(cont) if isinstance(cont, list) else "?"
    r.status, r.severity = POSITIVE, "CRITICAL"
    r.detail = ("Docker Engine API is reachable without authentication "
                "(equivalent to root on the host)")
    r.evidence = (f"GET /version -> 200 Version={info.get('Version')} "
                  f"ApiVersion={info.get('ApiVersion')} Os={info.get('Os')}; "
                  f"GET /containers/json -> {st2} ({n} running containers)")


def check_ftp(r: CheckResult, timeout: float, meta: dict) -> None:
    with _Conn(r.host, r.port, "ftp", timeout, r.sent) as c:
        banner = c.recv_line_reply().decode("latin-1", "replace").strip()
        c.send(b"USER anonymous\r\n")
        u = c.recv_line_reply().decode("latin-1", "replace").strip()
        p = ""
        if u.startswith("331"):
            c.send(b"PASS anonymous@example.com\r\n", "PASS anonymous@example.com")
            p = c.recv_line_reply().decode("latin-1", "replace").strip()
        try:
            c.send(b"QUIT\r\n")
        except OSError:
            pass
    r.evidence = f"banner={banner[:80]!r}; USER -> {u[:60]!r}" + (f"; PASS -> {p[:60]!r}" if p else "")
    if u.startswith("230") or p.startswith("230"):
        r.status, r.severity = POSITIVE, "MEDIUM"
        r.detail = "FTP accepts anonymous login (no listing was requested)"
    elif u.startswith(("530", "331")) or p.startswith(("530", "5")):
        r.status, r.detail = NEGATIVE, "anonymous FTP login refused"
    else:
        r.status, r.detail = INCONCLUSIVE, "unexpected FTP reply"


def check_smtp(r: CheckResult, timeout: float, meta: dict) -> None:
    with _Conn(r.host, r.port, "smtp", timeout, r.sent) as c:
        banner = c.recv_line_reply().decode("latin-1", "replace").strip()
        c.send(b"EHLO suvari.invalid\r\n")
        ehlo = c.recv_line_reply().decode("latin-1", "replace")
        try:
            c.send(b"QUIT\r\n")
        except OSError:
            pass
    exts = [ln[4:].strip().upper() for ln in ehlo.splitlines() if ln.startswith("250")]
    starttls = any(e.startswith("STARTTLS") for e in exts)
    auth = next((e for e in exts if e.startswith("AUTH")), "")
    r.evidence = f"banner={banner[:100]!r}; EHLO extensions: {', '.join(exts[1:])[:200]}"
    if not ehlo.startswith("250"):
        r.status, r.detail = INCONCLUSIVE, f"EHLO not accepted: {ehlo[:60]!r}"
    elif starttls:
        r.status, r.detail = NEGATIVE, "SMTP offers STARTTLS"
    else:
        r.status, r.severity = POSITIVE, "MEDIUM" if auth else "LOW"
        r.detail = "SMTP does not offer STARTTLS" + (
            f" while advertising {auth} (credentials would cross in cleartext)" if auth else "")


_SSH_WEAK = {
    "kex": {"diffie-hellman-group1-sha1": "MEDIUM", "diffie-hellman-group14-sha1": "LOW",
            "diffie-hellman-group-exchange-sha1": "LOW", "gss-group1-sha1-": "MEDIUM"},
    "hostkey": {"ssh-rsa": "LOW", "ssh-dss": "MEDIUM"},
    "cipher": {"arcfour": "MEDIUM", "arcfour128": "MEDIUM", "arcfour256": "MEDIUM",
               "3des-cbc": "MEDIUM", "des-cbc": "MEDIUM", "blowfish-cbc": "LOW",
               "cast128-cbc": "LOW", "aes128-cbc": "LOW", "aes192-cbc": "LOW",
               "aes256-cbc": "LOW"},
    "mac": {"hmac-md5": "LOW", "hmac-md5-96": "LOW", "hmac-sha1-96": "LOW",
            "umac-64@openssh.com": "LOW"},
}
_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def parse_kexinit(payload: bytes) -> dict:
    """Name-lists from an SSH_MSG_KEXINIT payload (RFC 4253 §7.1)."""
    if not payload or payload[0] != 20:
        raise ValueError("not a KEXINIT")
    i = 17
    names = []
    for _ in range(10):
        (ln,) = struct.unpack_from(">I", payload, i)
        names.append(payload[i + 4:i + 4 + ln].decode("ascii", "replace").split(","))
        i += 4 + ln
    return {"kex": names[0], "hostkey": names[1], "cipher": names[2] + names[3],
            "mac": names[4] + names[5]}


def check_ssh(r: CheckResult, timeout: float, meta: dict) -> None:
    """Server-offered algorithms from its KEXINIT (``ssh -Q`` would only list
    the *local client's* algorithms, so it is not used)."""
    with _Conn(r.host, r.port, "ssh", timeout, r.sent) as c:
        ident = c.recv_until(lambda b: b"\n" in b, cap=256)
        c.send(b"SSH-2.0-Suvari_Probe\r\n")
        rest = c.read_into(ident.split(b"\n", 1)[1] if b"\n" in ident else b"", 5)
        algos = {}
        if len(rest) >= 5:
            (plen,) = struct.unpack(">I", rest[:4])
            if 0 < plen <= 35000:
                rest = c.read_into(rest, 4 + plen)
                pad = rest[4]
                algos = parse_kexinit(rest[5:4 + plen - pad])
    banner = ident.split(b"\n", 1)[0].decode("latin-1", "replace").strip()
    weak = []
    sev = "INFO"
    if banner.startswith("SSH-1.") and not banner.startswith("SSH-1.99"):
        weak.append("protocol SSHv1")
        sev = "HIGH"
    for kind, table in _SSH_WEAK.items():
        for a in algos.get(kind, []):
            s = table.get(a) or next((v for k, v in table.items()
                                      if k.endswith("-") and a.startswith(k)), None)
            if s and f"{kind}:{a}" not in weak:
                weak.append(f"{kind}:{a}")
                sev = s if _SEV_RANK[s] > _SEV_RANK[sev] else sev
    r.evidence = f"banner={banner!r}; " + "; ".join(
        f"{k}={','.join(v)[:160]}" for k, v in algos.items())
    if not algos and not weak:
        r.status, r.detail = INCONCLUSIVE, "no KEXINIT received"
    elif weak:
        r.status, r.severity = POSITIVE, sev
        r.detail = "SSH server offers weak algorithms: " + ", ".join(weak)
    else:
        r.status, r.detail = NEGATIVE, "no weak SSH algorithms offered"


def check_dns_axfr(r: CheckResult, timeout: float, meta: dict) -> None:
    zones = [z for z in meta.get("zones") or [] if z][:2]
    if not zones:
        r.status, r.detail = INCONCLUSIVE, "no zone name known for this host (give a hostname target)"
        return
    outcomes = []
    for zone in zones:
        with _Conn(r.host, r.port, "dns", timeout, r.sent) as c:
            c.send(dns_query(zone, 252, 1, tcp=True, txid=0x5358), f"AXFR {zone}")
            head = c.recv_exact(2)
            if len(head) < 2:
                outcomes.append((zone, "closed", 0))
                continue
            (ln,) = struct.unpack(">H", head)
            msg = c.recv_exact(ln)
        if len(msg) < 12:
            outcomes.append((zone, "short", 0))
            continue
        flags, _qd, an = struct.unpack(">HHH", msg[2:8])
        outcomes.append((zone, flags & 0xF, an))
    r.evidence = "; ".join(f"AXFR {z}: rcode={rc} answers={an}" for z, rc, an in outcomes)
    hit = [z for z, rc, an in outcomes if rc == 0 and an > 0]
    if hit:
        r.status, r.severity = POSITIVE, "HIGH"
        r.detail = f"zone transfer (AXFR) allowed for {', '.join(hit)}"
    else:
        r.status, r.detail = NEGATIVE, "zone transfer refused"


def check_smb(r: CheckResult, timeout: float, meta: dict) -> None:
    exe = shutil.which("smbclient")
    if not exe:
        r.status = INCONCLUSIVE
        r.detail = "smbclient not installed; SMB port is open (null session not tested)"
        r.evidence = f"{r.port}/tcp open"
        return
    args = [exe, "-N", "-L", f"//{r.host}", "-p", str(r.port), "-g"]
    r.sent.append("smbclient -N -L (anonymous share list request)")
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, shell=False)
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        r.status, r.detail = ERROR, f"smbclient timed out after {timeout}s"
        return
    shares = re.findall(r"^Disk\|([^|]+)\|", out, re.M)
    if "NT_STATUS" in out and not shares:
        code = re.search(r"NT_STATUS_\w+", out)
        r.status, r.detail = NEGATIVE, "null session refused"
        r.evidence = code.group(0) if code else out[:120]
    elif shares or "IPC$" in out:
        r.status, r.severity = POSITIVE, "MEDIUM"
        r.detail = f"SMB null session lists shares ({len(shares)} disk shares; names not recorded)"
        r.evidence = f"smbclient -N -L succeeded ({len(shares)} disk shares)"
    else:
        r.status, r.detail, r.evidence = INCONCLUSIVE, "unrecognised smbclient output", out[:120]


def check_vnc(r: CheckResult, timeout: float, meta: dict) -> None:
    """Read the offered security types; no type is ever selected."""
    with _Conn(r.host, r.port, "vnc", timeout, r.sent) as c:
        ver = c.recv_exact(12)
        if not ver.startswith(b"RFB "):
            r.status, r.detail = INCONCLUSIVE, "not an RFB server"
            return
        minor = int(ver[8:11] or b"3") if ver[8:11].isdigit() else 3
        if minor >= 7:
            c.send(b"RFB 003.008\n" if minor >= 8 else b"RFB 003.007\n")
            n = c.recv_exact(1)
            types = list(c.recv_exact(n[0])) if n and n[0] else []
        else:
            c.send(b"RFB 003.003\n")
            raw = c.recv_exact(4)
            types = [struct.unpack(">I", raw)[0]] if len(raw) == 4 else []
    r.evidence = f"{ver.decode('latin-1').strip()}; security types offered: {types}"
    if 1 in types:
        r.status, r.severity = POSITIVE, "HIGH"
        r.detail = "VNC offers security type None (no authentication)"
    elif types:
        r.status, r.detail = NEGATIVE, "VNC requires authentication"
    else:
        r.status, r.detail = INCONCLUSIVE, "no security types received"


def _decode_cert(der: bytes) -> dict:
    """Parse a DER certificate with the stdlib (via a temp PEM file)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        try:
            return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - private API; fall back to openssl
            exe = shutil.which("openssl")
            if not exe:
                return {}
            out = subprocess.run([exe, "x509", "-noout", "-enddate", "-subject",
                                  "-issuer", "-in", path], capture_output=True,
                                 text=True, timeout=3).stdout
            m = re.search(r"notAfter=(.+)", out)
            return {"notAfter": m.group(1).strip()} if m else {}
    finally:
        os.unlink(path)


def _weak_tls(host: str, port: int, version, timeout: float) -> Optional[bool]:
    """True: accepted, False: refused, None: untestable with the local OpenSSL."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None):
                return True
    except ssl.SSLError as e:
        if "no protocols available" in str(e).lower():
            return None
        return False
    except OSError:
        return False


def check_tls(r: CheckResult, timeout: float, meta: dict) -> None:
    issues: list[tuple[str, str]] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    r.sent.append("TLS handshake")
    with socket.create_connection((r.host, r.port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=meta.get("sni")) as s:
            der = s.getpeercert(binary_form=True) or b""
            proto = s.version()
    cert = _decode_cert(der) if der else {}
    ev = [f"negotiated {proto}"]
    na = cert.get("notAfter")
    if na:
        try:
            exp = _dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(na), _dt.timezone.utc)
            days = (exp - _dt.datetime.now(_dt.timezone.utc)).days
            ev.append(f"notAfter={na} ({days} days left)")
            if days < 0:
                issues.append(("MEDIUM", f"certificate expired {-days} days ago"))
            elif days < 30:
                issues.append(("LOW", f"certificate expires in {days} days"))
        except ValueError:
            ev.append(f"notAfter={na}")
    if cert.get("subject") and cert.get("subject") == cert.get("issuer"):
        issues.append(("LOW", "self-signed certificate"))
        ev.append("self-signed")
    untestable = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        r.sent.append(f"TLS handshake limited to {name}")
        ok = _weak_tls(r.host, r.port, ver, timeout)
        if ok:
            issues.append(("MEDIUM", f"accepts {name}"))
        elif ok is None:
            untestable.append(name)
    ev.append("legacy protocols: " + (
        ", ".join(d for _, d in issues if d.startswith("accepts")) or "refused")
        + (f" (untestable locally: {', '.join(untestable)})" if untestable else ""))
    r.evidence = "; ".join(ev)
    if issues:
        r.status = POSITIVE
        r.severity = max((s for s, _ in issues), key=lambda s: _SEV_RANK[s])
        r.detail = "TLS issues: " + ", ".join(d for _, d in issues)
    else:
        r.status, r.detail = NEGATIVE, f"TLS configuration OK ({proto})"


def check_identify(r: CheckResult, timeout: float, meta: dict) -> None:
    """Unknown service: try a few harmless probes on fresh connections and
    report what it turns out to be (follow-up checks are spawned from that)."""
    from .discovery import identify
    probes = [("redis", "redis", b"*1\r\n$4\r\nPING\r\n"),
              ("memcached", "memcached", b"version\r\n"),
              ("http", "http", _http_get(r.host))]
    found = ""
    tried = []
    for name, proto, payload in probes:
        try:
            with _Conn(r.host, r.port, proto, timeout / 2, r.sent) as c:
                c.send(payload, f"{name} probe")
                data = c.recv_until(lambda b: b"\n" in b)
        except OSError:
            data = b""
        tried.append(f"{name}: {_printable(data)[:60]!r}")
        guess = identify(r.host, r.port, _printable(data)).service if data else "unknown"
        if guess and guess != "unknown":
            found = guess
            break
    r.evidence = "; ".join(tried)
    if found:
        r.status, r.severity = POSITIVE, "INFO"
        r.detail = f"unidentified port speaks {found}"
        r.spawn = [found]
    else:
        r.status, r.detail = NEGATIVE, "service could not be identified"


@dataclass(frozen=True)
class Check:
    key: str
    service: str
    title: str
    fn: Callable[[CheckResult, float, dict], None]


CHECKS: dict[str, Check] = {c.key: c for c in [
    Check("redis-noauth", "redis", "Redis reachable without authentication", check_redis),
    Check("memcached-noauth", "memcached", "memcached reachable without authentication",
          check_memcached),
    Check("mongodb-noauth", "mongodb", "MongoDB reachable without authentication",
          check_mongodb),
    Check("elastic-noauth", "elastic", "Elasticsearch reachable without authentication",
          check_elastic),
    Check("docker-api-noauth", "docker-api", "Docker Engine API exposed without authentication",
          check_docker),
    Check("ftp-anonymous", "ftp", "FTP anonymous login allowed", check_ftp),
    Check("smtp-starttls", "smtp", "SMTP without STARTTLS", check_smtp),
    Check("ssh-weak-algos", "ssh", "SSH weak algorithms offered", check_ssh),
    Check("dns-axfr", "dns", "DNS zone transfer (AXFR) allowed", check_dns_axfr),
    Check("smb-null-session", "smb", "SMB null session allowed", check_smb),
    Check("vnc-noauth", "vnc", "VNC without authentication", check_vnc),
    Check("tls-config", "tls", "Weak TLS configuration or certificate", check_tls),
    Check("svc-identify", "unknown", "Identify unknown service", check_identify),
]}

# service -> checks seeded for it
SERVICE_CHECKS: dict[str, list[str]] = {}
for _c in CHECKS.values():
    if _c.service not in ("tls", "unknown"):
        SERVICE_CHECKS.setdefault(_c.service, []).append(_c.key)
SERVICE_CHECKS["unknown"] = ["svc-identify"]

# rough severity of each check's positive outcome (for hypothesis seeding)
CHECK_SEVERITY = {
    "redis-noauth": "HIGH", "memcached-noauth": "HIGH", "mongodb-noauth": "CRITICAL",
    "elastic-noauth": "HIGH", "docker-api-noauth": "CRITICAL", "ftp-anonymous": "MEDIUM",
    "smtp-starttls": "LOW", "ssh-weak-algos": "LOW", "dns-axfr": "HIGH",
    "smb-null-session": "MEDIUM", "vnc-noauth": "HIGH", "tls-config": "MEDIUM",
    "svc-identify": "INFO",
}

RECOMMENDATIONS = {
    "redis-noauth": "Bind Redis to localhost or a private interface, enable `requirepass`/ACLs "
                    "and keep protected mode on.",
    "memcached-noauth": "Bind memcached to localhost (`-l 127.0.0.1`), disable UDP (`-U 0`) "
                        "and firewall port 11211.",
    "mongodb-noauth": "Enable MongoDB authorization (`security.authorization: enabled`) and "
                      "bind to private interfaces only.",
    "elastic-noauth": "Enable Elasticsearch security (xpack.security) and do not expose "
                      "9200 to untrusted networks.",
    "docker-api-noauth": "Never expose the Docker API without mutual TLS; bind it to the unix "
                         "socket only and firewall 2375/2376.",
    "ftp-anonymous": "Disable anonymous FTP (`anonymous_enable=NO`) or move to SFTP.",
    "smtp-starttls": "Enable STARTTLS on the SMTP listener and refuse AUTH before TLS.",
    "ssh-weak-algos": "Restrict `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` and `MACs` in "
                      "sshd_config to modern algorithms.",
    "dns-axfr": "Restrict zone transfers to secondary name servers (`allow-transfer`).",
    "smb-null-session": "Disable anonymous/null sessions (`restrict anonymous = 2`) and "
                        "firewall SMB from untrusted networks.",
    "vnc-noauth": "Require VNC authentication and tunnel VNC over SSH/VPN.",
    "tls-config": "Disable TLS 1.0/1.1 and renew/replace expiring or self-signed certificates.",
}


def checks_for(service: str, tls: bool = False) -> list[str]:
    keys = list(SERVICE_CHECKS.get(service, []))
    if tls and service not in ("docker-api",):
        keys.append("tls-config")
    return keys


def run_check(check: str, host: str, port: int, *, timeout: float = CHECK_TIMEOUT,
              meta: Optional[dict] = None) -> CheckResult:
    """Run one check once; never raises (errors become ``status=error``)."""
    meta = meta or {}
    spec = CHECKS[check]
    r = CheckResult(service=meta.get("service") or spec.service, check=check,
                    host=host, port=port, title=spec.title)
    t0 = time.monotonic()
    try:
        spec.fn(r, min(timeout, CHECK_TIMEOUT), meta)
    except UnsafeCommand:
        raise
    except (OSError, ConnectionError, ValueError, struct.error, http.client.HTTPException) as e:
        r.status, r.detail = ERROR, f"{type(e).__name__}: {e}"
    r.duration = round(time.monotonic() - t0, 3)
    if r.status != POSITIVE:
        r.severity = "INFO"
    return r
