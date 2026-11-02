"""
Known-vulnerability research for a detected technology.

Given a technology key (``nextjs``, ``nginx``, ``wordpress`` …) and an optional
version, look up publicly known vulnerabilities from keyless sources:

  * **NVD API 2.0** — CVE records with CVSS, references and affected version
    ranges. Products with a known CPE name are queried by CPE
    (``virtualMatchString``), which matches version ranges and avoids the noise
    of a free-text keyword search; others fall back to ``keywordSearch``. NVD
    returns results oldest-first, so the *last* page is fetched to get the
    newest records.
  * **CISA KEV** — the Known Exploited Vulnerabilities catalogue. Downloaded
    once, indexed in memory, and used to flag ``exploited_in_wild``.
  * **GitHub Advisory DB** (optional) — package advisories by ecosystem.

Results are cached on disk (``~/.cache/suvari/research/<sha1>.json``, TTL 24h).
Research is *fail-open*: no network → stale cache → empty result, never an
exception into the scan loop.

Safety: this module only issues GET requests to the intelligence sources above —
never to the scan target — and enforces per-source rate limits (NVD 5/30s,
GitHub 60/h) plus a hard request budget per job.
"""

from __future__ import annotations

import collections
import hashlib
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, urlencode

log = logging.getLogger("suvari.auto.research")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_URL = "https://api.github.com/advisories"

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "suvari" / "research"
DEFAULT_TTL = 86400
DEFAULT_SOURCES = ("nvd", "kev")
ALL_SOURCES = ("nvd", "kev", "ghsa")
MAX_REQUESTS_PER_JOB = 60
USER_AGENT = "suvari-research/1.0 (+safe-mode; GET only)"

# Retry policy for 429/503 responses.
MAX_RETRIES = 3
MAX_RETRY_WAIT = 60.0


@dataclass(frozen=True)
class Profile:
    """How to look a technology up in each source."""
    keyword: str                      # NVD keywordSearch fallback
    products: tuple                   # product names that count as "this tech"
    cpe_product: Optional[str] = None  # CPE product name for virtualMatchString
    ghsa: Optional[tuple] = None      # (ecosystem, package)


# Technologies worth researching. Managed platforms (netlify, cloudflare) are
# deliberately absent: their CVEs are patched by the provider, not the target.
PROFILES: dict[str, Profile] = {
    "nextjs": Profile("next.js", ("next.js", "next"), "next.js", ("npm", "next")),
    "nginx": Profile("nginx", ("nginx",), "nginx"),
    "wordpress": Profile("wordpress", ("wordpress",), "wordpress"),
    "express": Profile("express", ("express",), "express", ("npm", "express")),
    "django": Profile("django", ("django",), "django", ("pip", "django")),
    "apache": Profile("apache http server", ("http_server", "apache"), "http_server"),
    "php": Profile("php", ("php",), "php"),
    "iis": Profile("internet information services",
                   ("internet_information_services", "iis"),
                   "internet_information_services"),
    "firebase": Profile("firebase", ("firebase",), None, ("npm", "firebase")),
}


# ── result model ─────────────────────────────────────────────────────────

@dataclass
class ResearchResult:
    tech: str
    version: Optional[str]
    cves: list = field(default_factory=list)
    fetched_at: float = 0.0
    from_cache: bool = False
    stale: bool = False               # served from an expired cache (offline)
    total_found: int = 0              # matches reported by the source(s)
    query: str = ""
    sources: list = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ResearchResult":
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in allowed})


class ResearchError(Exception):
    """A source could not be queried (network, HTTP error, budget)."""


# ── rate limiting ────────────────────────────────────────────────────────

class WindowLimiter:
    """At most ``max_calls`` in any rolling ``period`` seconds (thread-safe)."""

    def __init__(self, max_calls: int, period: float,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.max_calls = max_calls
        self.period = period
        self._clock = clock
        self._sleep = sleep
        self._calls: collections.deque = collections.deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            while True:
                now = self._clock()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                self._sleep(self.period - (now - self._calls[0]))


def _default_fetch(url: str, timeout: float) -> tuple:
    """GET ``url``; return (status, headers, body bytes). Raises on network error."""
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https hosts
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read() if e.fp else b""


# ── parsers ──────────────────────────────────────────────────────────────

_EXPLOIT_REF_RE = re.compile(r"exploit-db\.com|packetstormsecurity|/exploits?/|metasploit|\bpoc\b", re.I)
_RANGE_PART_RE = re.compile(r"(>=|<=|>|<|=)?\s*v?([0-9][0-9A-Za-z.\-+]*)")


def _cpe_parts(criteria: str) -> tuple:
    parts = criteria.split(":")
    if len(parts) < 6:
        return "", "", ""
    return parts[3], parts[4], parts[5]


def parse_range_string(spec: str) -> dict:
    """Parse ``">= 13.0.0, < 13.5.8"`` (NVD ``affected`` / GHSA style)."""
    rng: dict = {}
    for chunk in (spec or "").split(","):
        m = _RANGE_PART_RE.match(chunk.strip())
        if not m:
            continue
        op, ver = m.group(1) or "=", m.group(2)
        key = {">=": "start_incl", ">": "start_excl", "<=": "end_incl",
               "<": "end_excl", "=": "exact"}[op]
        rng[key] = ver
    return rng


def _nvd_ranges(cve: dict) -> list[dict]:
    ranges: list[dict] = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                vendor, product, ver = _cpe_parts(m.get("criteria", ""))
                r = {"vendor": vendor, "product": product}
                for src, dst in (("versionStartIncluding", "start_incl"),
                                 ("versionStartExcluding", "start_excl"),
                                 ("versionEndIncluding", "end_incl"),
                                 ("versionEndExcluding", "end_excl")):
                    if m.get(src):
                        r[dst] = m[src]
                if ver not in ("*", "-", "") and len(r) == 2:
                    r["exact"] = ver
                ranges.append(r)
    # CVE 5.x "affected" block (present on newer records, sometimes the only one)
    for aff in cve.get("affected", []) or []:
        for d in aff.get("affectedData", []) or []:
            for v in d.get("versions", []) or []:
                if v.get("status", "affected") != "affected":
                    continue
                r = {"vendor": str(d.get("vendor", "")).lower(),
                     "product": str(d.get("product", "")).lower()}
                r.update(parse_range_string(v.get("version", "")))
                if len(r) > 2:
                    ranges.append(r)
    out, seen = [], set()
    for r in ranges:
        k = tuple(sorted(r.items()))
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def _nvd_cvss(metrics: dict) -> tuple:
    """Best CVSS: prefer v3.1 > v4.0 > v3.0 > v2, Primary over Secondary."""
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        rows = sorted(rows, key=lambda r: r.get("type") != "Primary")
        data = rows[0].get("cvssData", {})
        score = data.get("baseScore")
        sev = data.get("baseSeverity") or rows[0].get("baseSeverity") or ""
        pr = data.get("privilegesRequired") or ""
        return (float(score) if score is not None else None, str(sev).upper(),
                data.get("vectorString", ""), str(pr).upper())
    return None, "", "", ""


def parse_nvd(data: dict) -> list[dict]:
    """Normalise an NVD 2.0 response into CVE dicts (rejected records dropped)."""
    out = []
    for item in (data or {}).get("vulnerabilities", []) or []:
        cve = item.get("cve") or {}
        if not cve.get("id") or cve.get("vulnStatus") == "Rejected":
            continue
        summary = next((d.get("value", "") for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"), "")
        score, sev, vector, pr = _nvd_cvss(cve.get("metrics") or {})
        refs = cve.get("references", []) or []
        exploit_ref = any("Exploit" in (r.get("tags") or []) or
                          _EXPLOIT_REF_RE.search(r.get("url", "")) for r in refs)
        cwes = sorted({d.get("value", "") for w in cve.get("weaknesses", []) or []
                       for d in w.get("description", []) or []
                       if d.get("value", "").startswith("CWE-")})
        out.append({
            "id": cve["id"],
            "cvss": score,
            "severity": sev,
            "vector": vector,
            "privileges_required": pr,
            "summary": summary,
            "exploited_in_wild": bool(cve.get("cisaExploitAdd")),
            "exploit_ref": exploit_ref,
            "references": [r.get("url", "") for r in refs[:8]],
            "cwes": cwes,
            "published": cve.get("published", ""),
            "status": cve.get("vulnStatus", ""),
            "ranges": _nvd_ranges(cve),
            "source": "nvd",
        })
    return out


def parse_ghsa(data: list) -> list[dict]:
    """Normalise a GitHub Advisory API list response into CVE dicts."""
    out = []
    for adv in data or []:
        if not isinstance(adv, dict) or adv.get("withdrawn_at"):
            continue
        cvss = None
        for k in ("cvss_v3", "cvss_v4"):
            s = ((adv.get("cvss_severities") or {}).get(k) or {}).get("score")
            if s:
                cvss = float(s)
                break
        if cvss is None and (adv.get("cvss") or {}).get("score"):
            cvss = float(adv["cvss"]["score"])
        vector = ""
        for k in ("cvss_v3", "cvss_v4"):
            vector = ((adv.get("cvss_severities") or {}).get(k) or {}).get("vector_string") or vector
        pr = ""
        m = re.search(r"PR:([NLH])", vector or "")
        if m:
            pr = {"N": "NONE", "L": "LOW", "H": "HIGH"}[m.group(1)]
        ranges = []
        for v in adv.get("vulnerabilities", []) or []:
            pkg = (v.get("package") or {}).get("name", "")
            r = {"vendor": "", "product": str(pkg).lower()}
            r.update(parse_range_string(v.get("vulnerable_version_range", "")))
            if len(r) > 2:
                ranges.append(r)
        refs = adv.get("references") or []
        out.append({
            "id": adv.get("cve_id") or adv.get("ghsa_id", ""),
            "ghsa_id": adv.get("ghsa_id", ""),
            "cvss": cvss,
            "severity": str(adv.get("severity", "")).upper().replace("MODERATE", "MEDIUM"),
            "vector": vector or "",
            "privileges_required": pr,
            "summary": adv.get("summary", "") or "",
            "exploited_in_wild": False,
            "exploit_ref": any(_EXPLOIT_REF_RE.search(u) for u in refs),
            "references": list(refs[:8]),
            "cwes": [c.get("cwe_id", "") for c in adv.get("cwes") or []],
            "published": adv.get("published_at", "") or "",
            "status": adv.get("type", ""),
            "ranges": ranges,
            "source": "ghsa",
        })
    return out


def index_kev(data: dict) -> dict:
    """``{cve_id: {date_added, ransomware, name}}`` from the KEV feed."""
    idx = {}
    for v in (data or {}).get("vulnerabilities", []) or []:
        cid = v.get("cveID")
        if cid:
            idx[cid] = {"date_added": v.get("dateAdded", ""),
                        "ransomware": v.get("knownRansomwareCampaignUse", ""),
                        "name": v.get("vulnerabilityName", "")}
    return idx


def mark_kev(cves: list[dict], kev: dict) -> int:
    """Flag CVEs present in KEV; returns how many matched."""
    n = 0
    for c in cves:
        if c["id"] in kev:
            c["exploited_in_wild"] = True
            c["kev"] = kev[c["id"]]
            n += 1
        elif c.get("exploited_in_wild"):
            n += 1  # NVD already carries the CISA flag
    return n


# ── researcher ───────────────────────────────────────────────────────────

class Researcher:
    """Looks up known vulnerabilities for a technology, with cache + limits.

    ``fetch(url, timeout) -> (status, headers, body_bytes)`` and the clocks are
    injectable so tests never touch the network or really sleep.
    """

    def __init__(self, *, cache_dir: Optional[Path] = None, ttl: float = DEFAULT_TTL,
                 sources=DEFAULT_SOURCES, max_results: int = 20,
                 max_requests: int = MAX_REQUESTS_PER_JOB, start_count: int = 0,
                 fetch: Optional[Callable] = None, timeout: float = 20.0,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self.ttl = float(ttl)
        self.sources = tuple(s for s in sources if s in ALL_SOURCES)
        self.max_results = max(1, min(int(max_results), 100))
        self.max_requests = max_requests
        self.requests_made = start_count
        self._fetch = fetch or _default_fetch
        self.timeout = timeout
        self._clock = clock
        self._sleep = sleep
        self._limiters = {
            "nvd": WindowLimiter(5, 30.0, monotonic, sleep),
            "ghsa": WindowLimiter(60, 3600.0, monotonic, sleep),
            "kev": WindowLimiter(5, 30.0, monotonic, sleep),
        }
        self._lock = threading.Lock()
        self._kev: Optional[dict] = None

    # ── http ──────────────────────────────────────────────────────────
    def _take_budget(self) -> None:
        with self._lock:
            if self.max_requests is not None and self.requests_made >= self.max_requests:
                raise ResearchError(f"research request budget exhausted ({self.max_requests})")
            self.requests_made += 1

    def _get_json(self, url: str, source: str):
        """GET JSON with rate limiting and 429/503 back-off; raises ResearchError."""
        for attempt in range(MAX_RETRIES + 1):
            self._take_budget()
            self._limiters[source].acquire()
            try:
                status, headers, body = self._fetch(url, self.timeout)
            except Exception as e:  # noqa: BLE001 - network errors become ResearchError
                raise ResearchError(f"{source}: {e}") from e
            if status in (429, 503):
                if attempt == MAX_RETRIES:
                    break
                wait = _retry_after(headers) or 6.0 * (2 ** attempt)
                log.info("%s returned %s; retrying in %.0fs", source, status, wait)
                self._sleep(min(wait, MAX_RETRY_WAIT))
                continue
            if status != 200:
                raise ResearchError(f"{source}: HTTP {status}")
            try:
                return json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
            except (ValueError, UnicodeDecodeError) as e:
                raise ResearchError(f"{source}: invalid JSON ({e})") from e
        raise ResearchError(f"{source}: rate limited (HTTP {status}) after {MAX_RETRIES} retries")

    # ── cache ─────────────────────────────────────────────────────────
    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / (hashlib.sha1(key.encode()).hexdigest() + ".json")

    def _cache_read(self, key: str) -> Optional[dict]:
        p = self._cache_path(key)
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            return None

    def _cache_write(self, key: str, data: dict) -> None:
        p = self._cache_path(key)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data))
            tmp.replace(p)
        except OSError as e:
            log.warning("research cache write failed: %s", e)

    def _fresh(self, ts: float) -> bool:
        return (self._clock() - float(ts or 0)) < self.ttl

    # ── KEV ───────────────────────────────────────────────────────────
    def kev_index(self) -> dict:
        """The KEV index, from memory, fresh cache, network, or stale cache."""
        if self._kev is not None:
            return self._kev
        key = "kev|index"
        cached = self._cache_read(key)
        if cached and self._fresh(cached.get("fetched_at", 0)):
            self._kev = cached.get("index", {})
            return self._kev
        try:
            idx = index_kev(self._get_json(KEV_URL, "kev"))
            self._cache_write(key, {"fetched_at": self._clock(), "index": idx})
            self._kev = idx
        except ResearchError as e:
            log.warning("KEV unavailable (%s); using %s", e,
                        "stale cache" if cached else "empty index")
            self._kev = (cached or {}).get("index", {})
        return self._kev

    # ── sources ───────────────────────────────────────────────────────
    def _nvd_query(self, profile: Profile, version: Optional[str]) -> dict:
        if profile.cpe_product:
            ver = version if version and re.fullmatch(r"[0-9][0-9A-Za-z.\-]*", version) else "*"
            return {"virtualMatchString": f"cpe:2.3:a:*:{profile.cpe_product}:{ver}"}
        return {"keywordSearch": profile.keyword}

    def _nvd(self, profile: Profile, version: Optional[str]) -> tuple:
        q = self._nvd_query(profile, version)
        n = self.max_results
        url = f"{NVD_URL}?{urlencode(q, quote_via=quote, safe=':*')}&resultsPerPage={n}"
        data = self._get_json(url, "nvd")
        total = int(data.get("totalResults", 0) or 0)
        if total > len(data.get("vulnerabilities") or []):
            # oldest-first ordering: the last page holds the newest records
            data = self._get_json(f"{url}&startIndex={max(0, total - n)}", "nvd")
        cves = parse_nvd(data)
        cves.sort(key=lambda c: c.get("published", ""), reverse=True)
        return cves, total, " ".join(f"{k}={v}" for k, v in q.items())

    def _ghsa(self, profile: Profile) -> list[dict]:
        if not profile.ghsa:
            return []
        eco, pkg = profile.ghsa
        url = f"{GHSA_URL}?{urlencode({'ecosystem': eco, 'affects': pkg, 'per_page': self.max_results})}"
        data = self._get_json(url, "ghsa")
        return parse_ghsa(data if isinstance(data, list) else [])

    # ── main entry ────────────────────────────────────────────────────
    def research(self, tech: str, version: Optional[str] = None) -> ResearchResult:
        """Known vulnerabilities for ``tech`` (fail-open; never raises)."""
        tech = (tech or "").lower().strip()
        profile = PROFILES.get(tech)
        if profile is None:
            return ResearchResult(tech, version, fetched_at=self._clock(),
                                  error=f"no research profile for {tech!r}")
        key = f"{tech}|{version or ''}|{','.join(sorted(self.sources))}|{self.max_results}"
        cached = self._cache_read(key)
        if cached and self._fresh(cached.get("fetched_at", 0)):
            res = ResearchResult.from_dict(cached)
            res.from_cache = True
            return res

        res = ResearchResult(tech, version, fetched_at=self._clock(),
                             sources=list(self.sources))
        errors: list[str] = []
        got_any = False
        if "nvd" in self.sources:
            try:
                cves, total, query = self._nvd(profile, version)
                res.cves.extend(cves)
                res.total_found += total
                res.query = query
                got_any = True
            except ResearchError as e:
                errors.append(str(e))
        if "ghsa" in self.sources:
            try:
                known = {c["id"] for c in res.cves}
                for adv in self._ghsa(profile):
                    if adv["id"] in known:
                        continue  # NVD record already covers it
                    res.cves.append(adv)
                    res.total_found += 1
                got_any = True
            except ResearchError as e:
                errors.append(str(e))
        if "kev" in self.sources and res.cves:
            mark_kev(res.cves, self.kev_index())

        res.error = "; ".join(errors)
        if not got_any:
            # offline / all sources failed: stale cache beats nothing
            if cached:
                stale = ResearchResult.from_dict(cached)
                stale.from_cache, stale.stale = True, True
                stale.error = res.error
                return stale
            return res
        self._cache_write(key, res.to_dict())
        return res


def _retry_after(headers: dict) -> Optional[float]:
    for k, v in (headers or {}).items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except (TypeError, ValueError):
                return None
    return None


def from_config(cfg: Optional[dict] = None, *, cache_ttl: Optional[float] = None,
                start_count: int = 0) -> Researcher:
    """Build a Researcher from the ``research`` config block."""
    cfg = cfg or {}
    return Researcher(
        ttl=cache_ttl if cache_ttl is not None else cfg.get("cache_ttl", DEFAULT_TTL),
        sources=tuple(cfg.get("sources") or DEFAULT_SOURCES),
        max_results=int(cfg.get("max_results", 20)),
        start_count=start_count,
    )
