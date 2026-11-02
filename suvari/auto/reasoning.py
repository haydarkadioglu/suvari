"""
Applicability reasoning: "can this known CVE plausibly be tested on *this* target?"

A CVE list on its own is noise. This module turns each researched CVE into a
scored, explained decision using what the scan has actually observed:

  * does the target's version fall in the CVE's affected range?
  * does the CVE's product match the detected technology (or is it a keyword
    hit for some other product)?
  * is the affected component/endpoint visible on the target
    (e.g. Next.js image optimizer -> ``/_next/image``)?
  * does exploitation need authentication (the scanner has none)?
  * threat signals: CISA KEV, CVSS >= 7, public exploit references.

It then plans **harmless** verification probes (version fingerprint, error page,
component reachability, mitigating security header, plain file exposure). Every
probe is a bare GET to the target host with no payload: nothing here sends an
exploit, a fuzz string or a DoS pattern. :func:`is_safe_probe` enforces that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

from . import tech_vectors
from .research import PROFILES

# Candidates at or above this score are seeded as hypotheses.
APPLICABLE_THRESHOLD = 0.35

# Score contributions (see :func:`applicability`).
W_BASE = 0.10
W_PRODUCT_MATCH = 0.10
W_PRODUCT_MISMATCH = -0.25
W_VERSION_IN_RANGE = 0.30
W_FEATURE_SEEN = 0.15
W_FEATURE_MISSING = -0.10
W_NO_AUTH = 0.05
W_AUTH_REQUIRED = -0.10
W_DOS_ONLY = -0.05
W_KEV = 0.30
W_CVSS_HIGH = 0.20
W_EXPLOIT_REF = 0.15
VERSION_MISMATCH_CAP = 0.05

# Unique, obviously-nonexistent path used to read the error page.
ERROR_PROBE_PATH = "suvari-404-check"


# ── versions ─────────────────────────────────────────────────────────────

def parse_version(v: str) -> tuple:
    """``"15.1.0-canary.3"`` -> ``(15, 1, 0)``; non-numeric parts dropped."""
    core = re.split(r"[-+ ]", str(v or "").strip().lstrip("vV"), maxsplit=1)[0]
    nums = []
    for part in core.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums)


def _cmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version: str, rng: dict) -> bool:
    """True when ``version`` satisfies every bound in ``rng``."""
    v = parse_version(version)
    if not v:
        return False
    if "exact" in rng:
        return _cmp(v, parse_version(rng["exact"])) == 0
    if "start_incl" in rng and _cmp(v, parse_version(rng["start_incl"])) < 0:
        return False
    if "start_excl" in rng and _cmp(v, parse_version(rng["start_excl"])) <= 0:
        return False
    if "end_incl" in rng and _cmp(v, parse_version(rng["end_incl"])) > 0:
        return False
    if "end_excl" in rng and _cmp(v, parse_version(rng["end_excl"])) >= 0:
        return False
    return True


def describe_range(rng: dict) -> str:
    if "exact" in rng:
        return f"= {rng['exact']}"
    parts = []
    for k, op in (("start_incl", ">="), ("start_excl", ">"),
                  ("end_incl", "<="), ("end_excl", "<")):
        if k in rng:
            parts.append(f"{op} {rng[k]}")
    return ", ".join(parts) or "all versions"


def product_ranges(cve: dict, tech: str) -> list[dict]:
    """The CVE's affected ranges that belong to ``tech``'s product."""
    prof = PROFILES.get(tech)
    names = {p.lower() for p in (prof.products if prof else (tech,))}
    return [r for r in cve.get("ranges", []) if str(r.get("product", "")).lower() in names]


def version_verdict(version: Optional[str], ranges: list[dict]) -> tuple:
    """(True|False|None, note). None = cannot tell (unknown version / no ranges)."""
    if not ranges:
        return None, "no version ranges published for this product"
    if not version or not parse_version(version):
        return None, "target version unknown"
    for r in ranges:
        if in_range(version, r):
            return True, f"version {version} is in affected range {describe_range(r)}"
    return False, f"version {version} is outside all affected ranges"


# ── observable features ─────────────────────────────────────────────────

@dataclass(frozen=True)
class Feature:
    tech: str
    traces: tuple            # substrings in recon headers/body that show it is in use
    cve_terms: tuple         # substrings in a CVE summary that make it relevant
    probe_path: Optional[str] = None   # harmless GET that shows the component is live
    expect: tuple = (200,)   # statuses that mean "component responds"
    observable: bool = True  # False: cannot be seen from outside (no penalty)


FEATURES: dict[str, Feature] = {
    "image-optimizer": Feature("nextjs", ("/_next/image",),
                               ("image optimiz", "/_next/image"),
                               "/_next/image", (200, 400)),
    "app-router": Feature("nextjs", ("self.__next_f", "next-router-state-tree", "rsc,"),
                          ("server component", "react server", "server action",
                           "server function", "app router", "flight protocol")),
    "pages-router": Feature("nextjs", ("__next_data__", "/_next/data/"),
                            ("pages router", "getserversideprops", "/_next/data")),
    "isr-cache": Feature("nextjs", ("x-nextjs-cache", "x-nextjs-prerender", "x-nextjs-stale-time"),
                         ("cache poisoning", "incremental static", " isr", "revalidat")),
    "middleware": Feature("nextjs", ("x-middleware-",), ("middleware",), observable=False),
    "xmlrpc": Feature("wordpress", ("xmlrpc.php", "x-pingback"), ("xml-rpc", "xmlrpc"),
                      "/xmlrpc.php", (200, 405)),
    "wp-rest": Feature("wordpress", ("wp-json",), ("rest api", "rest-api", "wp-json"),
                       "/wp-json/", (200,)),
    "wp-login": Feature("wordpress", ("wp-login.php",), ("wp-login",),
                        "/wp-login.php", (200,)),
}

_MANAGED_HOSTS = {"netlify", "vercel", "cloudflare"}


def _blob(res) -> str:
    hdr = " ".join(f"{k}:{v}," for k, v in (getattr(res, "headers", None) or {}).items())
    return (hdr + " " + (getattr(res, "body", "") or "")).lower()


def build_evidence(tech: str, version: Optional[str], responses,
                   detected_tech=(), base_url: str = "") -> dict:
    """What the scan has observed about ``tech`` on this target."""
    text = " ".join(_blob(r) for r in responses or [] if r is not None)
    observed = sorted(k for k, f in FEATURES.items()
                      if f.tech == tech and any(t in text for t in f.traces))
    return {
        "tech": tech,
        "version": version,
        "features": observed,
        "hosting": sorted(set(detected_tech) & _MANAGED_HOSTS),
        "csp": "content-security-policy:" in text,
        "xfo": "x-frame-options:" in text,
        "base_url": base_url,
    }


def cve_features(cve: dict, tech: str) -> list[str]:
    s = (cve.get("summary") or "").lower()
    return [k for k, f in FEATURES.items()
            if f.tech == tech and any(t in s for t in f.cve_terms)]


def _is_dos_only(cve: dict) -> bool:
    vec = cve.get("vector") or ""
    s = (cve.get("summary") or "").lower()
    if re.search(r"/C:N/I:N/A:[HL]", vec) or re.search(r"/VC:N/VI:N/VA:[HL]", vec):
        return True
    return "denial of service" in s and not any(
        w in s for w in ("remote code", "bypass", "disclos", "injection", "xss", "ssrf"))


# ── applicability ───────────────────────────────────────────────────────

def applicability(cve: dict, ev: dict) -> dict:
    """Score how plausibly ``cve`` applies to the observed target.

    Returns ``{"score": 0..1, "why": str, "checks": [...]}`` where each check is
    ``{"check", "result": pass|fail|unknown, "delta", "note"}``.
    """
    tech = ev.get("tech", "")
    checks: list[dict] = []

    def check(name, result, delta, note):
        checks.append({"check": name, "result": result,
                       "delta": round(delta, 2), "note": note})

    score = W_BASE
    # product
    ranges = product_ranges(cve, tech)
    if ranges:
        score += W_PRODUCT_MATCH
        check("product", "pass", W_PRODUCT_MATCH, f"affects {tech} directly")
    elif cve.get("ranges"):
        other = sorted({r.get("product", "?") for r in cve["ranges"]})[:3]
        score += W_PRODUCT_MISMATCH
        check("product", "fail", W_PRODUCT_MISMATCH,
              f"affects a different product ({', '.join(other)})")
    else:
        check("product", "unknown", 0.0, "no affected-product data (not yet analysed)")

    # version
    verdict, vnote = version_verdict(ev.get("version"), ranges)
    if verdict is True:
        score += W_VERSION_IN_RANGE
        check("version", "pass", W_VERSION_IN_RANGE, vnote)
    elif verdict is False:
        check("version", "fail", 0.0, vnote)
    else:
        check("version", "unknown", 0.0, vnote)

    # component / endpoint observed
    feats = cve_features(cve, tech)
    if feats:
        seen = [f for f in feats if f in ev.get("features", [])]
        if seen:
            score += W_FEATURE_SEEN
            check("component", "pass", W_FEATURE_SEEN,
                  "affected component observed on target: " + ", ".join(seen))
        elif any(FEATURES[f].observable for f in feats):
            score += W_FEATURE_MISSING
            check("component", "fail", W_FEATURE_MISSING,
                  "affected component not observed: " + ", ".join(feats))
        else:
            check("component", "unknown", 0.0,
                  "affected component not visible from outside: " + ", ".join(feats))

    # authentication
    pr = (cve.get("privileges_required") or "").upper()
    if pr == "NONE":
        score += W_NO_AUTH
        check("auth", "pass", W_NO_AUTH, "no privileges required (testable unauthenticated)")
    elif pr in ("LOW", "HIGH"):
        score += W_AUTH_REQUIRED
        check("auth", "fail", W_AUTH_REQUIRED,
              f"requires {pr.lower()} privileges; scanner is unauthenticated")

    # managed hosting
    s = (cve.get("summary") or "").lower()
    if ev.get("hosting") and "self-host" in s:
        score -= 0.15
        check("hosting", "fail", -0.15,
              f"self-hosted-only issue; target runs on {', '.join(ev['hosting'])}")

    if _is_dos_only(cve):
        score += W_DOS_ONLY
        check("dos", "fail", W_DOS_ONLY,
              "denial-of-service class: never exercised, version-based verification only")

    # threat signals
    if cve.get("exploited_in_wild"):
        score += W_KEV
        check("kev", "pass", W_KEV, "listed in CISA KEV (exploited in the wild)")
    cvss = cve.get("cvss")
    if cvss is not None and cvss >= 7.0:
        score += W_CVSS_HIGH
        check("cvss", "pass", W_CVSS_HIGH, f"CVSS {cvss} >= 7")
    if cve.get("exploit_ref"):
        score += W_EXPLOIT_REF
        check("exploit-ref", "pass", W_EXPLOIT_REF, "public exploit reference exists")

    score = max(0.01, min(0.99, score))
    if verdict is False:
        score = min(score, VERSION_MISMATCH_CAP)
    return {"score": round(score, 3), "why": _why(checks, verdict), "checks": checks}


def _why(checks: list[dict], verdict) -> str:
    if verdict is False:
        lead = next(c["note"] for c in checks if c["check"] == "version")
        return f"not applicable: {lead}"
    pos = [c["note"] for c in sorted(checks, key=lambda c: -c["delta"]) if c["delta"] > 0]
    neg = [c["note"] for c in checks if c["delta"] < 0]
    unk = [c["note"] for c in checks if c["result"] == "unknown"]
    parts = []
    if pos:
        parts.append("; ".join(pos[:3]))
    if neg:
        parts.append("against: " + "; ".join(neg[:2]))
    if unk:
        parts.append("unknown: " + "; ".join(unk[:2]))
    return " | ".join(parts) or "no signal either way"


# ── harmless test planning ──────────────────────────────────────────────

PROBE_KINDS = ("version-fingerprint", "feature-endpoint", "security-header", "exposed-file")
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/\-]*$")
_FILE_IN_TEXT_RE = re.compile(
    r"(?<![\w.:/])(/(?:[\w.\-]+/)*[\w\-]+\.(?:php|json|xml|txt|conf|env|ya?ml|map|bak|log))\b")


def is_safe_probe(probe: dict, base_url: str = "") -> bool:
    """A probe is safe iff it is a payload-free GET of a plain path on the target."""
    if probe.get("method") != "GET" or probe.get("kind") not in PROBE_KINDS:
        return False
    p = urlparse(probe.get("url", ""))
    if p.scheme not in ("http", "https") or p.query or p.fragment:
        return False
    if base_url and p.netloc != urlparse(base_url).netloc:
        return False
    return bool(_SAFE_PATH_RE.match(p.path or "/")) and ".." not in p.path


def plan_tests(cve: dict, ev: Optional[dict] = None, base_url: str = "") -> list[dict]:
    """Harmless verification steps for ``cve`` (GET-only, no payloads).

    Order: component reachability, plain file exposure, mitigating header,
    version fingerprint (always last and always present).
    """
    ev = ev or {}
    tech = ev.get("tech", "")
    base = (base_url or ev.get("base_url") or "").rstrip("/") + "/"
    probes: list[dict] = []

    def add(kind, path, title, **extra):
        # validate the raw path: urljoin would silently normalise "../"
        if ".." in path or not _SAFE_PATH_RE.match(path):
            return
        url = urljoin(base, path.lstrip("/"))
        p = {"kind": kind, "method": "GET", "url": url, "title": title, **extra}
        if is_safe_probe(p, base) and all(x["url"] != url or x["kind"] != kind for x in probes):
            probes.append(p)

    for f in cve_features(cve, tech):
        feat = FEATURES[f]
        if feat.probe_path:
            add("feature-endpoint", feat.probe_path,
                f"{f} component reachable", feature=f, expect=list(feat.expect))

    for path in _FILE_IN_TEXT_RE.findall(cve.get("summary") or "")[:2]:
        add("exposed-file", path, f"{path} served")

    cwes = set(cve.get("cwes") or [])
    if "CWE-79" in cwes:
        add("security-header", "/", "CSP absent (XSS impact not mitigated)",
            header="content-security-policy")
    if "CWE-1021" in cwes:
        add("security-header", "/", "X-Frame-Options absent (clickjacking)",
            header="x-frame-options")

    if ev.get("version"):
        add("version-fingerprint", "/", f"{tech} version banner vs affected ranges")
    else:
        add("version-fingerprint", "/" + ERROR_PROBE_PATH,
            f"{tech} version via error page vs affected ranges")
    return probes


# ── evaluating a probe response ─────────────────────────────────────────

LR_POSITIVE = 25.0
LR_NEGATIVE = 0.08
LR_NEUTRAL = 1.0


def evaluate_probe(meta: dict, res) -> dict:
    """Interpret a research probe response; same shape as Planner.interpret.

    Extra keys: ``inconclusive`` (cannot tell — leave unresolved) and
    ``verified_cves`` (CVE ids whose affected range contains the observed
    version).
    """
    kind = meta.get("kind")
    sev = meta.get("severity") or "INFO"
    out = {"positive": False, "detail": "", "lr": LR_NEGATIVE, "severity": sev,
           "children": [], "inconclusive": False, "verified_cves": []}

    if kind == "version-fingerprint":
        tech = meta.get("tech", "")
        version = tech_vectors.detect_versions([res]).get(tech) or meta.get("known_version")
        if not version:
            out.update(inconclusive=True, lr=LR_NEUTRAL,
                       detail=f"{tech} version not disclosed (HTTP {res.status}); "
                              "affected-range check inconclusive")
            return out
        hits, misses = [], []
        for c in meta.get("cves", []):
            ok, _ = version_verdict(version, c.get("ranges", []))
            (hits if ok else misses).append(c["id"])
        if hits:
            top = max((c for c in meta["cves"] if c["id"] in hits),
                      key=lambda c: c.get("cvss") or 0)
            out.update(positive=True, lr=LR_POSITIVE, verified_cves=hits,
                       severity=top.get("severity") or "MEDIUM",
                       detail=f"{tech} {version} is in the affected range of "
                              + ", ".join(hits))
        else:
            out["detail"] = f"{tech} {version} is not affected by " + ", ".join(misses)
        return out

    if kind == "feature-endpoint":
        expect = set(meta.get("expect") or [200])
        if res.status in expect:
            out.update(positive=True, lr=LR_POSITIVE, severity="INFO",
                       detail=f"{meta.get('feature')} responds (HTTP {res.status}): "
                              f"attack surface for {meta.get('cve')} is present; "
                              "version not verified")
        else:
            out["detail"] = f"{meta.get('feature')} not reachable (HTTP {res.status})"
        return out

    if kind == "security-header":
        hdr = meta.get("header", "")
        present = hdr in {k.lower() for k in (res.headers or {})}
        if 200 <= res.status < 500 and not present:
            out.update(positive=True, lr=LR_POSITIVE, severity="LOW",
                       detail=f"{hdr} missing: no mitigation for {meta.get('cve')}")
        else:
            out["detail"] = f"{hdr} present" if present else f"HTTP {res.status}"
        return out

    if kind == "exposed-file":
        if res.status == 200 and (res.body or "").strip():
            out.update(positive=True, lr=LR_POSITIVE, severity="INFO",
                       detail=f"file named in {meta.get('cve')} is served (HTTP 200)")
        else:
            out["detail"] = f"file not served (HTTP {res.status})"
        return out

    out.update(inconclusive=True, lr=LR_NEUTRAL, detail=f"unknown probe kind {kind!r}")
    return out


# ── LLM context ─────────────────────────────────────────────────────────

def llm_context(research_state: dict, limit: int = 6) -> str:
    """Compact brief: target tech, candidate CVEs, why, and the harmless tests."""
    if not research_state or not research_state.get("candidates"):
        return ""
    lines = []
    for t in research_state.get("techs", []):
        lines.append(f"Researched {t['tech']} (version {t.get('version') or 'unknown'}): "
                     f"{t.get('returned', 0)} CVEs analysed")
    cands = [c for c in research_state["candidates"] if c.get("hypotheses")]
    cands.sort(key=lambda c: -c["score"])
    if cands:
        lines.append("Candidate CVEs (applicability score; why; harmless tests):")
    for c in cands[:limit]:
        tags = [f"CVSS {c['cvss']}" if c.get("cvss") is not None else "CVSS ?"]
        if c.get("kev"):
            tags.append("KEV")
        tests = ", ".join(f"{p['kind']} {urlparse(p['url']).path}" for p in c.get("tests", []))
        lines.append(f"  {c['cve']} ({', '.join(tags)}) score={c['score']:.2f}: "
                     f"{c['why'][:160]} | tests: {tests} | hypotheses: {', '.join(c['hypotheses'])}")
    lines.append("Only safe GET verification is allowed (no exploitation, no DoS). "
                 "Prefer the candidate whose test can best confirm or rule it out.")
    return "\n".join(lines) + "\n"
