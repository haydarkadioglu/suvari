"""
Scope- and allowlist-bound tool executor for the autonomous loop.

Safety properties:
  * allowlist — only detection/evidence tools may run; destructive tooling
    (sqlmap --os-shell, metasploit, hydra, …) is simply not in the list.
  * ``shell=False`` always — arguments are passed as a list, never a string,
    so there is no shell interpolation.
  * scope — any URL-bearing argument must resolve to an allowed host; an
    out-of-scope target is refused and logged, never executed.
  * limits — per-call timeout and output cap; an optional requests/minute
    rate limiter paces HTTP probes. A shared :class:`RateLimiter` makes the
    rate (and an optional total request budget) global across worker threads.
  * job scope — when a :class:`~suvari.auto.scope.Scope` is attached, a URL
    must pass *both* the per-target host check and the job scope; refusals are
    recorded in the scope's blocked log.
"""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

log = logging.getLogger("suvari.auto.executor")

# Detection/evidence tools only. Deliberately excludes exploitation frameworks.
ALLOWLIST = {
    "curl", "httpx", "openssl", "nmap", "ffuf",
    "gobuster", "nikto", "whatweb", "nuclei",
}

# Hard caps regardless of caller request.
MAX_TIMEOUT = 120
MAX_OUTPUT = 65_536
BODY_CAP = 4096


@dataclass
class ExecResult:
    """Structured outcome of one tool invocation."""
    tool: str
    args: list
    ok: bool
    returncode: int = -1
    duration: float = 0.0
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    # HTTP fields (populated for curl probes)
    url: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    # True when nothing was sent because the job budget ran out or the job is
    # stopping; the turn should be rolled back and retried on resume.
    deferred: bool = False


class ScopeError(Exception):
    """Raised when a requested target is outside the allowed host set."""


class RateLimiter:
    """Thread-safe global pacing plus an optional hard request budget.

    Each :meth:`acquire` reserves the next free slot under a lock and sleeps
    outside it, so N workers sharing one limiter together never exceed
    ``rate_per_min``. Once ``max_requests`` slots are handed out, further calls
    return False and the caller must not send anything.
    """

    def __init__(self, rate_per_min: int = 60, max_requests: int | None = None,
                 start_count: int = 0, clock=time.monotonic, sleep=None):
        self.interval = 60.0 / max(1, rate_per_min)
        self.max_requests = max_requests
        self.count = start_count
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0
        self._lock = threading.Lock()
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        """Wake every waiting caller and refuse all further requests."""
        self._cancelled.set()

    def exhausted(self) -> bool:
        with self._lock:
            return self.max_requests is not None and self.count >= self.max_requests

    def acquire(self) -> bool:
        with self._lock:
            if self._cancelled.is_set():
                return False
            if self.max_requests is not None and self.count >= self.max_requests:
                return False
            now = self._clock()
            slot = max(now, self._next)
            self._next = slot + self.interval
            self.count += 1
        if slot > now:
            if self._sleep is not None:
                self._sleep(slot - now)
            elif self._cancelled.wait(slot - now):
                with self._lock:
                    self.count -= 1  # reserved but never sent
                return False
        return True


class Executor:
    def __init__(self, allowed_hosts: list[str], rate_per_min: int = 60,
                 default_timeout: int = 15, scope=None,
                 limiter: RateLimiter | None = None):
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.rate_per_min = max(1, rate_per_min)
        self._min_interval = 60.0 / self.rate_per_min
        self._last_call = 0.0
        self.default_timeout = default_timeout
        self.scope = scope
        self.limiter = limiter

    # ── scope ───────────────────────────────────────────────────────────
    def _host_of(self, url: str) -> str:
        netloc = urlparse(url).netloc.lower()
        return netloc or url.lower()

    def _host_allowed(self, url: str) -> bool:
        host = self._host_of(url)
        if host in self.allowed_hosts:
            return True
        # also accept a bare-hostname match against host:port entries
        bare = host.split(":", 1)[0]
        return any(bare == h.split(":", 1)[0] for h in self.allowed_hosts)

    def scope_reason(self, url: str) -> str | None:
        """None when ``url`` may be requested, else why it is refused."""
        if not self._host_allowed(url):
            return f"{self._host_of(url)} is not this target's host"
        if self.scope is not None:
            return self.scope.check(url)
        return None

    def in_scope(self, url: str) -> bool:
        return self.scope_reason(url) is None

    def _refuse(self, url: str, reason: str, source: str) -> str:
        log.warning("out-of-scope target refused: %s (%s)", url, reason)
        if self.scope is not None:
            self.scope.record_blocked(url, reason, source=source)
        return f"out-of-scope target refused: {url}"

    def _check_scope(self, args: list) -> None:
        for a in args:
            if isinstance(a, str) and ("://" in a):
                reason = self.scope_reason(a)
                if reason is not None:
                    raise ScopeError(self._refuse(a, reason, "executor"))

    # ── rate limit ──────────────────────────────────────────────────────
    def _throttle(self) -> bool:
        """Pace the next request; False when the request budget is spent."""
        if self.limiter is not None:
            return self.limiter.acquire()
        wait = self._min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()
        return True

    # ── availability ────────────────────────────────────────────────────
    @staticmethod
    def available(tool: str) -> bool:
        return shutil.which(tool) is not None

    # ── generic allowlisted run ─────────────────────────────────────────
    def run_tool(self, tool: str, args: list, timeout: int | None = None) -> ExecResult:
        if tool not in ALLOWLIST:
            return ExecResult(tool, args, ok=False,
                              error=f"tool not allowlisted: {tool}")
        if not self.available(tool):
            return ExecResult(tool, args, ok=False,
                              error=f"tool not installed: {tool}")
        try:
            self._check_scope(args)
        except ScopeError as e:
            log.warning("%s", e)
            return ExecResult(tool, args, ok=False, error=str(e))

        timeout = min(timeout or self.default_timeout, MAX_TIMEOUT)
        if not self._throttle():
            return ExecResult(tool, args, ok=False, deferred=True,
                              error="request budget exhausted or job stopping (not sent)")
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                [tool, *args],
                capture_output=True, text=True, timeout=timeout, shell=False,
            )
            dur = time.monotonic() - t0
            return ExecResult(
                tool, args, ok=(proc.returncode == 0),
                returncode=proc.returncode, duration=dur,
                stdout=proc.stdout[:MAX_OUTPUT], stderr=proc.stderr[:MAX_OUTPUT],
            )
        except subprocess.TimeoutExpired:
            return ExecResult(tool, args, ok=False, duration=time.monotonic() - t0,
                              error=f"(TIMEOUT after {timeout}s)")
        except Exception as e:  # noqa: BLE001 - one bad tool must not stop the loop
            log.exception("tool execution error")
            return ExecResult(tool, args, ok=False, error=f"(error: {e})")

    # ── HTTP probe (curl) ───────────────────────────────────────────────
    def http_probe(self, url: str, timeout: int | None = None) -> ExecResult:
        """GET ``url`` with curl, returning status, headers and a body slice."""
        reason = self.scope_reason(url)
        if reason is not None:
            return ExecResult("curl", [url], ok=False, url=url,
                              error=self._refuse(url, reason, "http_probe"))
        timeout = min(timeout or self.default_timeout, MAX_TIMEOUT)
        # no -L: a redirect is reported, never followed off-scope
        args = ["-s", "-S", "-i", "--proto", "=http,https",
                "--max-time", str(timeout), url]
        res = self.run_tool("curl", args, timeout=timeout + 2)
        res.url = url
        if res.error and res.status == 0 and not res.stdout:
            return res
        status, headers, body = _parse_http(res.stdout)
        res.status = status
        res.headers = headers
        res.body = body[:BODY_CAP]
        # curl exit 0 OR we still parsed a response line -> treat as reachable
        res.ok = res.ok or status > 0
        return res


    # ── reachability (TCP connect only) ─────────────────────────────────
    def tcp_reachable(self, url: str, timeout: float = 3.0) -> tuple[bool, str]:
        """Scope-checked TCP connect to the URL's host:port; nothing is sent."""
        reason = self.scope_reason(url)
        if reason is not None:
            return False, self._refuse(url, reason, "reachability")
        p = urlparse(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        if not self._throttle():
            return False, "request budget exhausted or job stopping (not sent)"
        try:
            with socket.create_connection((p.hostname, port), timeout=timeout):
                return True, ""
        except OSError as e:
            return False, f"{p.hostname}:{port} unreachable ({e})"


def _parse_http(raw: str) -> tuple[int, dict, str]:
    """Split a curl ``-i`` response into (status, headers, body).

    Handles proxy/redirect preludes by using the *last* header block that
    precedes the body.
    """
    if not raw:
        return 0, {}, ""
    norm = raw.replace("\r\n", "\n")
    # Separate the final header block from the body.
    if "\n\n" in norm:
        head, _, body = norm.partition("\n\n")
        # If multiple header blocks (redirects), keep splitting while the
        # remaining body still begins with an HTTP status line.
        while body.startswith("HTTP/") and "\n\n" in body:
            head, _, body = body.partition("\n\n")
    else:
        head, body = norm, ""
    lines = head.split("\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers, body
