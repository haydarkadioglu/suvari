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
    rate limiter paces HTTP probes.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
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


class ScopeError(Exception):
    """Raised when a requested target is outside the allowed host set."""


class Executor:
    def __init__(self, allowed_hosts: list[str], rate_per_min: int = 60,
                 default_timeout: int = 15):
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.rate_per_min = max(1, rate_per_min)
        self._min_interval = 60.0 / self.rate_per_min
        self._last_call = 0.0
        self.default_timeout = default_timeout

    # ── scope ───────────────────────────────────────────────────────────
    def _host_of(self, url: str) -> str:
        netloc = urlparse(url).netloc.lower()
        return netloc or url.lower()

    def in_scope(self, url: str) -> bool:
        host = self._host_of(url)
        if host in self.allowed_hosts:
            return True
        # also accept a bare-hostname match against host:port entries
        bare = host.split(":", 1)[0]
        return any(bare == h.split(":", 1)[0] for h in self.allowed_hosts)

    def _check_scope(self, args: list) -> None:
        for a in args:
            if isinstance(a, str) and ("://" in a):
                if not self.in_scope(a):
                    raise ScopeError(f"out-of-scope target refused: {a}")

    # ── rate limit ──────────────────────────────────────────────────────
    def _throttle(self) -> None:
        wait = self._min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

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
        self._throttle()
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
        if not self.in_scope(url):
            log.warning("out-of-scope probe refused: %s", url)
            return ExecResult("curl", [url], ok=False, url=url,
                              error=f"out-of-scope target refused: {url}")
        timeout = min(timeout or self.default_timeout, MAX_TIMEOUT)
        args = ["-s", "-S", "-i", "--max-time", str(timeout), url]
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
