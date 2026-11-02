"""
Target parsing and scope enforcement for multi-target autonomous jobs.

Accepted target / scope entry forms:
  * ``https://host/path``      URL (port implied by the scheme)
  * ``host:port``              host with an explicit port
  * ``1.2.3.4`` / ``host``     bare address or name (any port)
  * ``192.168.1.0/24``         CIDR network (expanded to its host addresses)
  * ``10.0.0.5-10.0.0.20``     inclusive IPv4/IPv6 range (``10.0.0.5-20`` too)

A :class:`Scope` is the allowlist every request is checked against. An entry
with a port (explicit, or implied by a URL scheme) only allows that port; an
entry without one allows any port on that address. Anything outside the scope
is refused before a packet is sent and recorded in :attr:`Scope.blocked`.

Wide ranges are refused unless explicitly allowed: a network or range larger
than a /24 (256 addresses) raises :class:`ScopeError` without
``allow_large=True``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

log = logging.getLogger("suvari.auto.scope")

# Anything wider than a /24 needs --allow-large-scope.
LARGE_SCOPE_ADDRESSES = 256
# Hard ceiling on how many targets one job may expand to, even when allowed.
MAX_EXPANSION = 65_536

_DEFAULT_PORTS = {"http": 80, "https": 443}
_HTTPS_PORTS = {443, 8443}

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(ValueError):
    """Invalid or disallowed target/scope specification."""


@dataclass(frozen=True)
class Target:
    """One concrete scan target: a base URL plus a filesystem-safe key."""
    url: str
    host: str
    port: int

    @property
    def netloc(self) -> str:
        return urlparse(self.url).netloc

    @property
    def key(self) -> str:
        return _slug(f"{self.host}_{self.port}")


@dataclass(frozen=True)
class _Rule:
    """One allowlist entry: an address network or a hostname, optional port."""
    network: Optional[IPNetwork] = None
    hostname: Optional[str] = None
    port: Optional[int] = None

    def describe(self) -> str:
        what = str(self.network) if self.network is not None else self.hostname
        return f"{what}:{self.port}" if self.port is not None else str(what)


# ── parsing ──────────────────────────────────────────────────────────────

def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "target"


def _as_ip(s: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(s.strip("[]"))
    except ValueError:
        return None


def _parse_range(spec: str) -> Optional[tuple[IPAddress, IPAddress]]:
    """``a-b`` where b is a full address or (IPv4) the last octet."""
    if "-" not in spec or "/" in spec or "://" in spec:
        return None
    lo_s, _, hi_s = spec.partition("-")
    lo = _as_ip(lo_s.strip())
    if lo is None:
        return None
    hi_s = hi_s.strip()
    hi = _as_ip(hi_s)
    if hi is None and isinstance(lo, ipaddress.IPv4Address) and hi_s.isdigit():
        prefix = str(lo).rsplit(".", 1)[0]
        hi = _as_ip(f"{prefix}.{hi_s}")
    if hi is None or hi.version != lo.version:
        raise ScopeError(f"invalid IP range: {spec!r}")
    if int(hi) < int(lo):
        raise ScopeError(f"IP range end precedes start: {spec!r}")
    return lo, hi


def _split_host_port(spec: str) -> tuple[str, Optional[int]]:
    """Split ``host:port`` / ``[v6]:port``; a bare IPv6 address has no port."""
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return host, _port(port, spec) if port else None
    if spec.count(":") == 1:
        host, _, port = spec.partition(":")
        return host, _port(port, spec)
    return spec, None


def _port(p: str, spec: str) -> int:
    if not p.isdigit() or not (0 < int(p) < 65536):
        raise ScopeError(f"invalid port in {spec!r}")
    return int(p)


def _check_size(count: int, spec: str, allow_large: bool) -> None:
    if count > MAX_EXPANSION:
        raise ScopeError(f"{spec!r} expands to {count} addresses "
                         f"(hard limit {MAX_EXPANSION})")
    if count > LARGE_SCOPE_ADDRESSES:
        if not allow_large:
            raise ScopeError(
                f"{spec!r} covers {count} addresses (wider than a /24); "
                f"pass --allow-large-scope to permit it")
        log.warning("large scope allowed: %s (%d addresses)", spec, count)


def _url_for(host: str, port: Optional[int], scheme: Optional[str] = None,
             path: str = "/") -> str:
    if scheme is None:
        scheme = "https" if port in _HTTPS_PORTS else "http"
    h = f"[{host}]" if ":" in host else host
    netloc = h if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{h}:{port}"
    return f"{scheme}://{netloc}{path or '/'}"


def expand_target(spec: str, allow_large: bool = False) -> list[Target]:
    """Expand one target spec into concrete :class:`Target` objects."""
    spec = spec.strip()
    if not spec:
        return []

    if "://" in spec:
        p = urlparse(spec)
        if p.scheme not in _DEFAULT_PORTS:
            raise ScopeError(f"unsupported scheme in {spec!r} (http/https only)")
        if not p.hostname:
            raise ScopeError(f"no host in {spec!r}")
        try:
            port = p.port or _DEFAULT_PORTS[p.scheme]
        except ValueError as e:
            raise ScopeError(f"invalid port in {spec!r}") from e
        host = p.hostname.lower()
        return [Target(_url_for(host, port, p.scheme, p.path or "/"), host, port)]

    rng = _parse_range(spec)
    if rng is not None:
        lo, hi = rng
        count = int(hi) - int(lo) + 1
        _check_size(count, spec, allow_large)
        return [_ip_target(ipaddress.ip_address(i)) for i in range(int(lo), int(hi) + 1)]

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as e:
            raise ScopeError(f"invalid CIDR: {spec!r}") from e
        _check_size(net.num_addresses, spec, allow_large)
        return [_ip_target(ip) for ip in net.hosts()]

    host, port = _split_host_port(spec)
    if not host:
        raise ScopeError(f"empty host in {spec!r}")
    ip = _as_ip(host)
    if ip is not None:
        return [_ip_target(ip, port)]
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ScopeError(f"invalid hostname: {spec!r}")
    port = port or 80
    return [Target(_url_for(host.lower(), port), host.lower(), port)]


def _ip_target(ip: IPAddress, port: Optional[int] = None) -> Target:
    port = port or 80
    return Target(_url_for(str(ip), port), str(ip), port)


def expand_targets(specs: Iterable[str], allow_large: bool = False) -> list[Target]:
    """Expand and de-duplicate many specs, preserving first-seen order."""
    out: list[Target] = []
    seen: set[str] = set()
    for spec in specs:
        for t in expand_target(spec, allow_large=allow_large):
            if t.url not in seen:
                seen.add(t.url)
                out.append(t)
    if len(out) > MAX_EXPANSION:
        raise ScopeError(f"too many targets ({len(out)} > {MAX_EXPANSION})")
    return out


def read_spec_file(path: Path) -> list[str]:
    """One spec per line; blank lines and ``#`` comments are ignored."""
    specs = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            specs.append(line)
    return specs


def _rules_for(spec: str, allow_large: bool) -> list[_Rule]:
    """Translate one scope entry into allowlist rules."""
    spec = spec.strip()
    if "://" in spec:
        t = expand_target(spec)[0]
        ip = _as_ip(t.host)
        if ip is not None:
            return [_Rule(network=ipaddress.ip_network(ip), port=t.port)]
        return [_Rule(hostname=t.host, port=t.port)]

    rng = _parse_range(spec)
    if rng is not None:
        lo, hi = rng
        _check_size(int(hi) - int(lo) + 1, spec, allow_large)
        return [_Rule(network=n) for n in ipaddress.summarize_address_range(lo, hi)]

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as e:
            raise ScopeError(f"invalid CIDR: {spec!r}") from e
        _check_size(net.num_addresses, spec, allow_large)
        return [_Rule(network=net)]

    host, port = _split_host_port(spec)
    ip = _as_ip(host)
    if ip is not None:
        return [_Rule(network=ipaddress.ip_network(ip), port=port)]
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ScopeError(f"invalid scope entry: {spec!r}")
    return [_Rule(hostname=host.lower(), port=port)]


# ── scope ────────────────────────────────────────────────────────────────

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    """Resolve ``host`` to its addresses via the system resolver."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({i[4][0] for i in infos})


class Scope:
    """Allowlist of hosts/networks; the single gate every request passes."""

    def __init__(self, entries: Iterable[str], allow_large: bool = False,
                 resolver: Optional[Resolver] = system_resolver):
        self.entries = [e.strip() for e in entries if e and e.strip()]
        self.allow_large = allow_large
        self.resolver = resolver
        self.rules: list[_Rule] = [
            r for e in self.entries for r in _rules_for(e, allow_large)]
        self._lock = threading.Lock()
        self._dns_cache: dict[str, list[str]] = {}
        self.blocked: list[dict] = []

    # ── checks ──────────────────────────────────────────────────────────
    def is_allowed(self, url_or_ip: str) -> bool:
        """True if a URL, ``host:port`` or bare address is inside the scope."""
        return self.check(url_or_ip) is None

    def check(self, url_or_ip: str) -> Optional[str]:
        """Return None if allowed, else the reason it is out of scope."""
        try:
            host, port = _host_port_of(url_or_ip)
        except ScopeError as e:
            return str(e)
        ip = _as_ip(host)
        if ip is not None:
            return None if self._ip_ok(ip, port) else f"{host} not in scope"

        for r in self.rules:
            if r.hostname == host and (r.port is None or r.port == port):
                return None
        # A hostname not listed by name is allowed only if every address it
        # resolves to is inside an allowed network.
        addrs = self._resolve(host)
        if not addrs:
            return f"{host} not in scope (unresolved)"
        ips = [_as_ip(a) for a in addrs]
        if all(i is not None and self._ip_ok(i, port) for i in ips):
            return None
        return f"{host} resolves outside scope ({', '.join(addrs)})"

    def _ip_ok(self, ip: IPAddress, port: Optional[int]) -> bool:
        for r in self.rules:
            if r.network is not None and ip.version == r.network.version \
                    and ip in r.network and (r.port is None or r.port == port):
                return True
        return False

    def _resolve(self, host: str) -> list[str]:
        if self.resolver is None:
            return []
        with self._lock:
            if host in self._dns_cache:
                return self._dns_cache[host]
        try:
            addrs = list(self.resolver(host))
        except (OSError, UnicodeError) as e:
            log.info("DNS resolution failed for %s: %s", host, e)
            addrs = []
        with self._lock:
            self._dns_cache[host] = addrs
        return addrs

    def resolve(self, host: str) -> list[str]:
        """Public host -> addresses lookup (cached; IPs returned as-is)."""
        if _as_ip(host) is not None:
            return [host]
        return self._resolve(host)

    # ── blocked-request log ─────────────────────────────────────────────
    def record_blocked(self, target: str, reason: str, source: str = "") -> dict:
        entry = {"ts": round(time.time(), 3), "target": target,
                 "reason": reason, "source": source}
        with self._lock:
            self.blocked.append(entry)
        log.warning("blocked by scope: %s (%s)", target, reason)
        return entry

    def describe(self) -> list[str]:
        return [r.describe() for r in self.rules]


def _host_port_of(s: str) -> tuple[str, Optional[int]]:
    s = s.strip()
    if "://" in s:
        p = urlparse(s)
        if p.scheme not in _DEFAULT_PORTS:
            raise ScopeError(f"unsupported scheme: {p.scheme or '?'}")
        if not p.hostname:
            raise ScopeError(f"no host in {s!r}")
        try:
            port = p.port or _DEFAULT_PORTS[p.scheme]
        except ValueError as e:
            raise ScopeError(f"invalid port in {s!r}") from e
        return p.hostname.lower(), port
    host, port = _split_host_port(s)
    return host.lower(), port
