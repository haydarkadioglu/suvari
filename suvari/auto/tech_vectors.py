"""
Technology-aware hypothesis bank.

The deterministic rule table (:mod:`suvari.auto.planner`) always seeds the same
generic vectors (headers, robots, /admin, /backup, /.git). That is blind to what
the target is actually built with. This module fingerprints the stack from the
first responses and proposes an *attack surface specific to that stack* — e.g. a
Firebase site gets Realtime-Database / Firestore / Storage read checks, a Next.js
site gets source-map and build-manifest probes.

Safety: every spec is a **read-only GET** carried out by curl (the only tool
these specs name). Firebase checks only ask "is unauthenticated read open?" —
there is never an authentication attempt, write, or delete. Scope stays on the
target host plus the detected Firebase project's own backend hosts
(:func:`scope_hosts`).

Nothing here executes; the planner turns the returned :class:`HypothesisSpec`
list into hypotheses and the executor enforces the allowlist and scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin

from .executor import ExecResult


# ── detection signatures ───────────────────────────────────────────────────
def _hdr(res: ExecResult, name: str) -> str:
    return res.headers.get(name.lower(), "")


def detect_tech(responses) -> set[str]:
    """Fingerprint the stack from one or more probe responses.

    Looks at response headers, body text and URL/path traces. Returns the set of
    recognised technology keys (``nextjs``, ``netlify``, ``firebase``,
    ``wordpress``, ``cloudflare``, ``express``, ``django``, ``nginx``).
    """
    tech: set[str] = set()
    for res in responses or []:
        if res is None:
            continue
        body = (res.body or "")
        low = body.lower()
        server = _hdr(res, "server").lower()
        powered = _hdr(res, "x-powered-by").lower()
        hdr_blob = " ".join(f"{k}:{v}" for k, v in (res.headers or {}).items()).lower()

        if "/_next/" in low or "next.js" in powered or "x-nextjs-cache" in hdr_blob:
            tech.add("nextjs")
        if "netlify" in server or "x-nf-request-id" in hdr_blob:
            tech.add("netlify")
        if any(s in low for s in (
            "firebaseio.com", "firestore.googleapis.com", "identitytoolkit",
            "gstatic.com/firebasejs", "firebaseapp.com", "firebase",
        )):
            tech.add("firebase")
        if "wp-content" in low or "wp-json" in low or "wordpress" in low:
            tech.add("wordpress")
        if "cloudflare" in server or "cf-ray" in hdr_blob:
            tech.add("cloudflare")
        if "express" in powered:
            tech.add("express")
        if "csrftoken" in hdr_blob or "wsgiserver" in server or "django" in powered:
            tech.add("django")
        if "nginx" in server:
            tech.add("nginx")
    return tech


# (tech, where, pattern) — ``where`` is a header name or "body".
_VERSION_PATTERNS = [
    ("nginx", "server", r"nginx/(\d+\.\d+(?:\.\d+)?)"),
    ("apache", "server", r"apache/(\d+\.\d+(?:\.\d+)?)"),
    ("iis", "server", r"microsoft-iis/(\d+\.\d+)"),
    ("php", "x-powered-by", r"php/(\d+\.\d+(?:\.\d+)?)"),
    ("nextjs", "x-powered-by", r"next\.js[ /]v?(\d+\.\d+(?:\.\d+)?)"),
    ("nextjs", "body", r"window\.next\s*=\s*\{\s*version:\s*[\"'](\d+\.\d+\.\d+)"),
    ("nextjs", "body", r"\"next\"\s*:\s*\"[\^~]?(\d+\.\d+\.\d+)\""),
    ("nextjs", "body", r"next\.js\s+v?(\d+\.\d+\.\d+)"),
    ("wordpress", "body", r"<meta[^>]+generator[^>]+wordpress\s+(\d+\.\d+(?:\.\d+)?)"),
    ("wordpress", "body", r"wp-(?:includes|emoji)[^\"']*[?&]ver=(\d+\.\d+(?:\.\d+)?)"),
]


def detect_versions(responses) -> dict[str, str]:
    """Version traces per technology (``{"nginx": "1.24.0"}``), best effort.

    Reads Server / X-Powered-By banners, meta generators and inline bundle
    markers. Absent when the target hides them — callers must treat a missing
    version as *unknown*, never as *not vulnerable*.
    """
    found: dict[str, str] = {}
    for res in responses or []:
        if res is None:
            continue
        for tech, where, pat in _VERSION_PATTERNS:
            if tech in found:
                continue
            text = (res.body or "") if where == "body" else _hdr(res, where)
            m = re.search(pat, text, re.I)
            if m:
                found[tech] = m.group(1)
    return found


_FIREBASE_PROJECT_RE = re.compile(
    r'(?:"projectId"\s*:\s*"|projectId\s*:\s*["\'])([a-z0-9][a-z0-9-]{3,})',
    re.I,
)
_FIREBASE_RTDB_RE = re.compile(
    r'https://([a-z0-9-]+?)(?:-default-rtdb)?\.(?:firebaseio\.com|firebasedatabase\.app)',
    re.I,
)
_FIREBASE_BUCKET_RE = re.compile(
    r'(?:"storageBucket"\s*:\s*"|storageBucket\s*:\s*["\'])([a-z0-9][a-z0-9._-]+)',
    re.I,
)
_FIREBASE_APIKEY_RE = re.compile(r'"?apiKey"?\s*[:=]\s*["\']?AIza[0-9A-Za-z_\-]{10,}', re.I)


def firebase_context(responses) -> dict:
    """Best-effort extraction of the Firebase project id / bucket from bodies.

    Returns ``{"project": str|None, "bucket": str|None, "apikey_seen": bool}``.
    The project id is what scopes the Realtime-Database / Firestore checks, so
    without it those probes stay out of scope and are never sent.
    """
    project = bucket = None
    apikey = False
    for res in responses or []:
        if res is None:
            continue
        body = res.body or ""
        if project is None:
            m = _FIREBASE_PROJECT_RE.search(body) or _FIREBASE_RTDB_RE.search(body)
            if m:
                project = m.group(1)
        if bucket is None:
            m = _FIREBASE_BUCKET_RE.search(body)
            if m:
                bucket = m.group(1)
        if not apikey and _FIREBASE_APIKEY_RE.search(body):
            apikey = True
    if bucket is None and project:
        bucket = f"{project}.appspot.com"
    return {"project": project, "bucket": bucket, "apikey_seen": apikey}


# ── detection rules for the new vectors ─────────────────────────────────────
# detect(res) -> (positive: bool, detail: str); same contract as planner's table.
def _reachable(res: ExecResult) -> bool:
    return res.status == 200


def _json_has(res: ExecResult, *needles: str) -> bool:
    b = res.body or ""
    return res.status == 200 and any(n in b for n in needles)


def _d_firebase_init(res):
    if _json_has(res, '"apiKey"', '"projectId"', '"databaseURL"', '"storageBucket"'):
        return True, "Firebase init config is publicly served (leaks project config)"
    return False, ""


def _d_firebase_config_leak(res):
    found = [k for k in ("apiKey", "projectId", "databaseURL", "storageBucket")
             if k in (res.body or "")]
    if res.status == 200 and found:
        return True, "client JS exposes Firebase config keys: " + ", ".join(found)
    return False, ""


def _d_firebase_rtdb(res):
    body = (res.body or "").strip()
    if res.status == 200 and body and body != "null":
        return True, "Realtime Database allows UNAUTHENTICATED read (data returned)"
    return False, "RTDB read denied / empty (expected)"


def _d_firestore(res):
    if _json_has(res, '"documents"', '"fields"', '"name"'):
        return True, "Firestore documents readable without authentication"
    return False, "Firestore read denied (403 expected)"


def _d_firebase_storage(res):
    if _json_has(res, '"items"', '"prefixes"'):
        return True, "Storage bucket objects are publicly listable"
    return False, "Storage listing denied (expected)"


def _d_identity_config(res):
    if _json_has(res, "signupEnabled", "emailPasswordEnabled", "authorizedDomains"):
        return True, "Identity Toolkit project config disclosed (informational)"
    return False, ""


def _d_firebase_files(res):
    low = (res.body or "").lower()
    if res.status == 200 and any(s in low for s in (
        '"hosting"', '"firestore"', '"rules"', "private_key", "service_account",
        '"projects"', '"default"',
    )):
        return True, "Firebase project/config file is exposed"
    return False, ""


def _d_nextjs_sourcemap(res):
    if _json_has(res, '"sources"', '"mappings"', '"sourcesContent"'):
        return True, "Next.js JavaScript source map is served (leaks original source)"
    return False, ""


def _d_nextjs_data(res):
    if _json_has(res, '"pageProps"', '"__N_SSG"', '"__N_SSP"'):
        return True, "Next.js data endpoint exposes server-rendered props"
    return False, ""


def _d_api_reachable(res):
    if res.status in (200, 401, 403):
        return True, f"endpoint responds (HTTP {res.status}) — API surface present"
    return False, ""


def _d_netlify_functions(res):
    if res.status in (200, 404) and ("function" in (res.body or "").lower()
                                     or res.status == 200):
        return True, f"Netlify functions path responds (HTTP {res.status})"
    return False, ""


def _d_wp_users(res):
    if _json_has(res, '"slug"', '"name"', '"id"'):
        return True, "WordPress REST exposes user accounts (username enumeration)"
    return False, ""


def _d_reachable_200(res):
    if res.status == 200 and (res.body or "").strip():
        return True, f"path is reachable (HTTP 200)"
    return False, ""


def _d_dotenv(res):
    body = res.body or ""
    if res.status == 200 and "=" in body and "<html" not in body.lower():
        keys = re.findall(r"(?m)^([A-Z][A-Z0-9_]{2,})=", body)
        return True, "environment file served" + (
            f" (keys: {', '.join(keys[:6])})" if keys else "")
    return False, ""


def _d_server_status(res):
    if res.status == 200 and "server" in (res.body or "").lower()[:200]:
        return True, "Apache server-status page is public"
    return False, ""


@dataclass(frozen=True)
class TechVectorRule:
    """Detection metadata for a technology-specific vector."""
    key: str
    title: str
    prior: float
    severity: str
    detect: Callable[[ExecResult], tuple]


# Registered by the planner into its VECTOR_RULES so interpret()/reporting work.
TECH_RULES: list[TechVectorRule] = [
    # firebase
    TechVectorRule("firebase-init-exposure", "Firebase init config exposed", 0.35, "HIGH", _d_firebase_init),
    TechVectorRule("firebase-config-leak", "Firebase config in client JS", 0.40, "MEDIUM", _d_firebase_config_leak),
    TechVectorRule("firebase-rtdb-open", "Firebase Realtime DB unauth read", 0.30, "CRITICAL", _d_firebase_rtdb),
    TechVectorRule("firestore-open", "Firestore unauth read", 0.25, "CRITICAL", _d_firestore),
    TechVectorRule("firebase-storage-open", "Firebase Storage public listing", 0.30, "CRITICAL", _d_firebase_storage),
    TechVectorRule("firebase-identity-config", "Identity Toolkit config disclosure", 0.25, "INFO", _d_identity_config),
    TechVectorRule("firebase-files-exposure", "Firebase project files exposed", 0.30, "HIGH", _d_firebase_files),
    # nextjs
    TechVectorRule("nextjs-sourcemap", "Next.js source map exposed", 0.30, "MEDIUM", _d_nextjs_sourcemap),
    TechVectorRule("nextjs-data", "Next.js data endpoint exposed", 0.25, "LOW", _d_nextjs_data),
    TechVectorRule("nextjs-api", "Next.js API route discovery", 0.25, "LOW", _d_api_reachable),
    # netlify
    TechVectorRule("netlify-functions", "Netlify functions exposed", 0.25, "LOW", _d_netlify_functions),
    TechVectorRule("netlify-identity", "Netlify Identity enabled", 0.25, "INFO", _d_api_reachable),
    TechVectorRule("netlify-config", "Netlify _headers/_redirects exposed", 0.30, "LOW", _d_reachable_200),
    # wordpress
    TechVectorRule("wp-users", "WordPress user enumeration", 0.40, "MEDIUM", _d_wp_users),
    TechVectorRule("wp-xmlrpc", "WordPress XML-RPC reachable", 0.30, "MEDIUM", _d_api_reachable),
    TechVectorRule("wp-login", "WordPress login reachable", 0.30, "LOW", _d_reachable_200),
    # generic
    TechVectorRule("sitemap-leak", "Sitemap discloses paths", 0.30, "INFO", _d_reachable_200),
    TechVectorRule("security-txt", "security.txt present", 0.25, "INFO", _d_reachable_200),
    TechVectorRule("dotenv-exposure", "Environment file exposed", 0.20, "CRITICAL", _d_dotenv),
    TechVectorRule("server-status", "Apache server-status public", 0.20, "MEDIUM", _d_server_status),
]

TECH_RULE_BY_KEY: dict[str, TechVectorRule] = {r.key: r for r in TECH_RULES}


@dataclass(frozen=True)
class HypothesisSpec:
    """A proposed technology-specific hypothesis (what the planner seeds)."""
    title: str
    vector: str
    target: str
    prior: float
    probe: str = "curl"


def _spec(key: str, target: str) -> HypothesisSpec:
    r = TECH_RULE_BY_KEY[key]
    return HypothesisSpec(title=r.title, vector=key, target=target, prior=r.prior)


def vectors_for(tech: str, base_url: str, ctx: dict | None = None) -> list[HypothesisSpec]:
    """Return the read-only probe specs for a detected technology.

    ``ctx`` may carry Firebase ``project`` / ``bucket`` (see
    :func:`firebase_context`); when absent, placeholders are used and the
    cross-origin Firebase probes will simply be refused as out-of-scope.
    """
    base = base_url.rstrip("/") + "/"
    ctx = ctx or {}

    def u(path: str) -> str:
        return urljoin(base, path.lstrip("/"))

    if tech == "firebase":
        project = ctx.get("project") or "PROJECT"
        bucket = ctx.get("bucket") or f"{project}.appspot.com"
        return [
            _spec("firebase-init-exposure", u("__/firebase/init.json")),
            _spec("firebase-config-leak", base),
            _spec("firebase-rtdb-open",
                  f"https://{project}-default-rtdb.firebaseio.com/.json"),
            _spec("firestore-open",
                  "https://firestore.googleapis.com/v1/projects/"
                  f"{project}/databases/(default)/documents/users"),
            _spec("firebase-storage-open",
                  f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"),
            _spec("firebase-identity-config",
                  "https://identitytoolkit.googleapis.com/v1/projects/"
                  f"{project}/config"),
            _spec("firebase-files-exposure", u("firebase.json")),
        ]
    if tech == "nextjs":
        return [
            _spec("nextjs-sourcemap", u("_next/static/chunks/main-app.js.map")),
            _spec("nextjs-data", u("_next/data/")),
            _spec("nextjs-api", u("api/")),
        ]
    if tech == "netlify":
        return [
            _spec("netlify-functions", u(".netlify/functions/")),
            _spec("netlify-identity", u(".netlify/identity")),
            _spec("netlify-config", u("_headers")),
        ]
    if tech == "wordpress":
        return [
            _spec("wp-users", u("wp-json/wp/v2/users")),
            _spec("wp-xmlrpc", u("xmlrpc.php")),
            _spec("wp-login", u("wp-login.php")),
        ]
    return []


def generic_vectors(base_url: str) -> list[HypothesisSpec]:
    """Stack-agnostic read-only probes seeded on every run."""
    base = base_url.rstrip("/") + "/"

    def u(path: str) -> str:
        return urljoin(base, path.lstrip("/"))

    return [
        _spec("sitemap-leak", u("sitemap.xml")),
        _spec("security-txt", u(".well-known/security.txt")),
        _spec("dotenv-exposure", u(".env")),
        _spec("server-status", u("server-status")),
    ]


def scope_hosts(techs: set[str], ctx: dict | None = None) -> list[str]:
    """Extra in-scope hosts implied by the detected stack.

    For Firebase this is the project's own Google backend hosts — the only
    off-site targets the generated probes touch, and only when the project was
    actually detected on the target.
    """
    ctx = ctx or {}
    hosts: list[str] = []
    if "firebase" in techs:
        hosts += [
            "firestore.googleapis.com",
            "firebasestorage.googleapis.com",
            "identitytoolkit.googleapis.com",
        ]
        project = ctx.get("project")
        if project:
            hosts.append(f"{project}-default-rtdb.firebaseio.com")
            hosts.append(f"{project}.firebaseio.com")
    return hosts
