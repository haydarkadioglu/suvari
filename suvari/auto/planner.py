"""
Planner for the autonomous loop.

Two sources of plans:
  * Deterministic (always available, used by ``--dry-run`` and as the fallback):
    a rule table of detection vectors plus evidence interpretation.
  * LLM (optional): proposes extra hypotheses and picks the next one to test,
    constrained by a strict JSON schema. On a schema/parse error it retries
    twice and then falls back to the deterministic planner.

The *action* that actually runs is always derived from the chosen hypothesis's
vector (a scoped HTTP probe), never from free-form model text — the LLM steers
*which* belief to test and *why*, the rule table decides *how*, and the executor
enforces the allowlist and scope. That keeps model influence from ever widening
the command surface.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

from . import reasoning, services, tech_vectors
from .executor import ALLOWLIST, ExecResult
from .hypothesis import (
    Hypothesis, STATUS_CONFIRMED, STATUS_REFUTED,
)
from .usage import UsageRecord, UsageTracker, estimate_tokens

log = logging.getLogger("suvari.auto.planner")

# Evidence strength as likelihood ratios for the Bayesian update.
LR_POSITIVE = 25.0   # vector signature observed -> strong support
LR_NEGATIVE = 0.08   # probe ran, signature absent -> refuting
CONFIRM_THRESHOLD = 0.8


def _has(headers: dict, name: str) -> bool:
    return name.lower() in {k.lower() for k in headers}


# ── vector rule table ───────────────────────────────────────────────────
# detect(res) -> (positive: bool, detail: str)
def _detect_missing_headers(res: ExecResult):
    if not (200 <= res.status < 500):
        return False, ""
    missing = [h for h in ("content-security-policy", "x-frame-options")
               if not _has(res.headers, h)]
    if missing:
        return True, "missing: " + ", ".join(missing)
    return False, "security headers present"


def _detect_git(res: ExecResult):
    if res.status == 200 and "[core]" in res.body.lower():
        return True, "/.git/config is served (contains [core])"
    return False, ""


def _detect_admin(res: ExecResult):
    b = res.body.lower()
    if res.status == 200 and ("password" in b or "login" in b or "<form" in b):
        return True, "admin interface reachable with a login form"
    return False, ""


def _detect_dir_listing(res: ExecResult):
    b = res.body.lower()
    if res.status == 200 and ("directory listing" in b or "index of" in b):
        return True, "directory listing is enabled"
    return False, ""


def _detect_robots(res: ExecResult):
    if res.status == 200 and "disallow" in res.body.lower():
        paths = re.findall(r"(?im)^\s*disallow:\s*(\S+)", res.body)
        return True, "robots.txt discloses paths: " + ", ".join(paths[:10])
    return False, ""


def _detect_path(res: ExecResult):
    if res.status == 200:
        return True, f"path is reachable (HTTP 200)"
    return False, ""


@dataclass
class Vector:
    key: str
    title: str
    path: str
    prior: float
    severity: str
    detect: Callable[[ExecResult], tuple]


VECTOR_RULES: dict[str, Vector] = {v.key: v for v in [
    Vector("missing-security-headers", "Missing security headers", "/",
           0.5, "LOW", _detect_missing_headers),
    Vector("git-exposure", "Exposed .git repository", "/.git/config",
           0.15, "HIGH", _detect_git),
    Vector("admin-auth-bypass", "Exposed admin interface", "/admin",
           0.2, "MEDIUM", _detect_admin),
    Vector("dir-listing", "Directory listing enabled", "/backup/",
           0.2, "MEDIUM", _detect_dir_listing),
    Vector("robots-info-leak", "robots.txt information disclosure", "/robots.txt",
           0.3, "LOW", _detect_robots),
    # Dynamic vector: path comes from the hypothesis target (robots children).
    Vector("path-probe", "Reachable disclosed path", "",
           0.5, "MEDIUM", _detect_path),
]}

# Merge the technology-aware vectors (firebase, nextjs, …) into the rule table
# so interpret()/reporting treat them exactly like the built-in vectors. Their
# target is dynamic (supplied by the hypothesis), so path stays empty.
for _r in tech_vectors.TECH_RULES:
    VECTOR_RULES.setdefault(_r.key, Vector(
        _r.key, _r.title, "", _r.prior, _r.severity, _r.detect))


@dataclass
class Plan:
    hypothesis: Hypothesis
    tool: str
    args: list
    url: str
    rationale: str
    source: str  # "deterministic" | "llm"


# Research-derived hypotheses use these vector keys; they are interpreted by
# :func:`reasoning.evaluate_probe`, not by the rule table.
RESEARCH_VECTORS = {
    "version-fingerprint": "cve-version-check",
    "feature-endpoint": "cve-surface",
    "security-header": "cve-mitigation-header",
    "exposed-file": "cve-file-exposure",
}


SERVICE_PRIOR_KNOWN = 0.5     # port open and the service was identified
SERVICE_PRIOR_UNKNOWN = 0.3   # port open, service not identified


class Planner:
    def __init__(self, base_url: str, llm=None, dry_run: bool = False,
                 on_blocked: Optional[Callable[[str, str], None]] = None,
                 researcher=None, max_cves: int = 5,
                 host_profile: Optional[dict] = None, service_mode: bool = False):
        self.base_url = base_url.rstrip("/") + "/"
        # discovery result for this host (context for every prompt); in
        # service mode the planner seeds protocol checks instead of web vectors
        self.host_profile = host_profile
        self.service_mode = service_mode
        self.llm = llm
        self.dry_run = dry_run
        self.usage = UsageTracker()
        self.detected_tech: set[str] = set()
        self.tech_ctx: dict = {}
        # optional known-vulnerability research (suvari.auto.research.Researcher)
        self.researcher = researcher
        self.max_cves = max_cves
        # called with (url, reason) when a proposed target leaves the host
        self.on_blocked = on_blocked

    def _blocked(self, url: str, reason: str) -> None:
        log.info("dropped off-target hypothesis %s (%s)", url, reason)
        if self.on_blocked is not None:
            self.on_blocked(url, reason)

    def use_llm(self) -> bool:
        return self.llm is not None and not self.dry_run

    # ── bootstrap ───────────────────────────────────────────────────────
    def bootstrap(self, state, recon_responses=None) -> None:
        """Seed the initial hypotheses.

        Seeds the static rule table, then — before any LLM call — fingerprints
        the stack from ``recon_responses`` and seeds the technology-specific and
        generic read-only vectors so the LLM steers an informed surface rather
        than a blind one.
        """
        if self.service_mode:
            self._seed_services(state)
            if self.use_llm():
                self._llm_augment(state)
            return

        # Static, built-in vectors (skip the dynamic ones added by tech/robots).
        static_keys = {v.key for v in VECTOR_RULES.values()} - set(
            tech_vectors.TECH_RULE_BY_KEY) - {"path-probe"}
        for key in static_keys:
            v = VECTOR_RULES[key]
            hid = state.next_hypothesis_id()
            url = urljoin(self.base_url, v.path.lstrip("/"))
            state.add_hypothesis(Hypothesis(
                id=hid, title=v.title, target=url, vector=v.key,
                prior=v.prior, posterior=v.prior, severity=v.severity,
                rationale="seed hypothesis from rule table",
            ))

        # Tech-aware and generic probes are seeded only once recon has run
        # (``recon_responses`` provided, even if empty); a bare bootstrap with
        # no recon context stays on the deterministic static table.
        if recon_responses is not None:
            self._seed_tech_vectors(state, recon_responses)
            if self.researcher is not None:
                try:
                    self._seed_research(state, recon_responses)
                except Exception as e:  # noqa: BLE001 - research is fail-open
                    log.warning("research failed: %s", e)
                    state.notes.append(f"research skipped: {e}")

        if self.use_llm():
            self._llm_augment(state)

    def _seed_tech_vectors(self, state, recon_responses) -> None:
        """Detect the stack and seed tech-specific + generic probe hypotheses."""
        self.detected_tech = tech_vectors.detect_tech(recon_responses or [])
        if "firebase" in self.detected_tech:
            self.tech_ctx = tech_vectors.firebase_context(recon_responses or [])

        specs = list(tech_vectors.generic_vectors(self.base_url))
        for tech in sorted(self.detected_tech):
            specs.extend(tech_vectors.vectors_for(tech, self.base_url, self.tech_ctx))

        existing = {(h.vector, h.target) for h in state.hypotheses.values()}
        seeded = 0
        for spec in specs:
            if (spec.vector, spec.target) in existing:
                continue
            rule = tech_vectors.TECH_RULE_BY_KEY[spec.vector]
            hid = state.next_hypothesis_id()
            state.add_hypothesis(Hypothesis(
                id=hid, title=spec.title, target=spec.target, vector=spec.vector,
                prior=spec.prior, posterior=spec.prior, severity=rule.severity,
                rationale="tech-aware seed" + (
                    f" ({', '.join(sorted(self.detected_tech))})"
                    if self.detected_tech else " (generic)"),
            ))
            existing.add((spec.vector, spec.target))
            seeded += 1
        if self.detected_tech:
            state.notes.append(
                f"detected tech: {', '.join(sorted(self.detected_tech))}; "
                f"seeded {seeded} tech-aware vectors")
            if self.tech_ctx.get("project"):
                state.notes.append(
                    f"firebase project: {self.tech_ctx['project']}")

    def _seed_research(self, state, recon_responses) -> None:
        """Research known CVEs for the detected stack and seed the applicable ones.

        For each researchable technology: query the sources, score every CVE's
        applicability against what recon observed, and seed hypotheses only for
        the top candidates (prior = applicability score). Version checks are
        grouped into one hypothesis per technology because a single fingerprint
        answers the range question for all of its CVEs.
        """
        from .research import PROFILES

        versions = tech_vectors.detect_versions(recon_responses or [])
        techs = sorted((self.detected_tech | set(versions)) & set(PROFILES))
        rs = state.research = {"enabled": True, "techs": [], "candidates": []}
        if not techs:
            state.notes.append("research: no researchable technology detected")
            return

        existing = {(h.vector, h.target) for h in state.hypotheses.values()}
        for tech in techs:
            version = versions.get(tech)
            rr = self.researcher.research(tech, version)
            ev = reasoning.build_evidence(tech, version, recon_responses,
                                          self.detected_tech, self.base_url)
            rs["techs"].append({
                "tech": tech, "version": version, "query": rr.query,
                "total_found": rr.total_found, "returned": len(rr.cves),
                "kev": sum(1 for c in rr.cves if c.get("exploited_in_wild")),
                "from_cache": rr.from_cache, "stale": rr.stale, "error": rr.error,
                "features": ev["features"],
            })
            scored = []
            for cve in rr.cves:
                app = reasoning.applicability(cve, ev)
                scored.append({
                    "cve": cve["id"], "tech": tech, "cvss": cve.get("cvss"),
                    "severity": cve.get("severity") or "", "kev": bool(cve.get("exploited_in_wild")),
                    "exploit_ref": bool(cve.get("exploit_ref")),
                    "summary": (cve.get("summary") or "")[:240],
                    "source": cve.get("source", ""),
                    "score": app["score"], "why": app["why"], "checks": app["checks"],
                    "ranges": reasoning.product_ranges(cve, tech),
                    "tests": reasoning.plan_tests(cve, ev, self.base_url),
                    "hypotheses": [], "results": [],
                })
            scored.sort(key=lambda c: (-c["score"], -(c["cvss"] or 0)))
            rs["candidates"].extend(scored)
            applicable = [c for c in scored if c["score"] >= reasoning.APPLICABLE_THRESHOLD]
            self._seed_cve_hypotheses(state, tech, version, applicable, existing)

        n_app = sum(1 for c in rs["candidates"] if c["score"] >= reasoning.APPLICABLE_THRESHOLD)
        state.notes.append(
            f"research: {len(rs['candidates'])} CVEs for {', '.join(techs)}; "
            f"{n_app} scored applicable; {sum(1 for c in rs['candidates'] if c['hypotheses'])} seeded")

    def _seed_cve_hypotheses(self, state, tech, version, applicable, existing) -> None:
        """Seed one shared version check for every applicable CVE (a single
        request answers all of them) plus a component/file/header check for
        each of the top ``max_cves``."""
        if not applicable:
            return

        def add(title, vector, target, prior, severity, meta, rationale):
            hid = state.next_hypothesis_id()
            state.add_hypothesis(Hypothesis(
                id=hid, title=title[:120], target=target, vector=vector,
                prior=prior, posterior=prior, severity=severity or "INFO",
                rationale=rationale[:200], max_attempts=1,
                meta={"source": "research", **meta},
            ))
            existing.add((vector, target))
            return hid

        # one version check per technology, covering every applicable CVE
        vp = next(p for p in applicable[0]["tests"] if p["kind"] == "version-fingerprint")
        top = applicable[0]
        hid = add(
            f"{tech} version in affected range of {len(applicable)} candidate CVE(s)",
            RESEARCH_VECTORS["version-fingerprint"], vp["url"], top["score"],
            top["severity"],
            {"kind": "version-fingerprint", "tech": tech, "known_version": version,
             "cves": [{"id": c["cve"], "cvss": c["cvss"], "severity": c["severity"],
                       "kev": c["kev"], "ranges": c["ranges"]} for c in applicable]},
            "research: " + ", ".join(c["cve"] for c in applicable))
        for c in applicable:
            c["hypotheses"].append(hid)

        # one component/mitigation/file check per top CVE (first non-version test)
        for c in applicable[:self.max_cves]:
            probe = next((p for p in c["tests"] if p["kind"] != "version-fingerprint"), None)
            if probe is None:
                continue
            vector = RESEARCH_VECTORS[probe["kind"]]
            if (vector, probe["url"]) in existing:
                # same check already seeded for another CVE: share it
                for h in state.hypotheses.values():
                    if h.vector == vector and h.target == probe["url"]:
                        h.meta.setdefault("also_cves", []).append(c["cve"])
                        c["hypotheses"].append(h.id)
                        break
                continue
            tags = f"CVSS {c['cvss']}" + (", KEV" if c["kev"] else "")
            meta = {k: v for k, v in probe.items() if k not in ("url", "method", "title")}
            meta.update(cve=c["cve"], tech=tech, severity=c["severity"])
            hid = add(f"{c['cve']} ({tags}): {probe['title']}", vector, probe["url"],
                      c["score"], c["severity"], meta, f"research: {c['why']}")
            c["hypotheses"].append(hid)

    # ── service (non-HTTP) hypotheses ───────────────────────────────────
    def _seed_services(self, state) -> None:
        """One hypothesis per (open port, applicable read-only check)."""
        prof = self.host_profile or {}
        seeded = 0
        for p in prof.get("open_ports", []):
            if p.get("proto", "tcp") != "tcp":
                continue
            for key in services.checks_for(p["service"], p.get("tls", False)):
                if self._add_service_hyp(state, key, p, parent=None):
                    seeded += 1
        state.notes.append(f"host profile: {len(prof.get('open_ports', []))} open ports; "
                           f"seeded {seeded} service checks")

    def _add_service_hyp(self, state, check: str, port: dict, parent: Optional[str],
                         prior: Optional[float] = None, title: str = "",
                         rationale: str = "") -> Optional[Hypothesis]:
        prof = self.host_profile or {}
        host = prof.get("host", "")
        netloc = f"[{host}]:{port['port']}" if ":" in host else f"{host}:{port['port']}"
        if any(h.vector == check and h.target == netloc for h in state.hypotheses.values()):
            return None
        if prior is None:
            prior = SERVICE_PRIOR_UNKNOWN if port["service"] == "unknown" else SERVICE_PRIOR_KNOWN
        spec = services.CHECKS[check]
        hid = state.next_hypothesis_id()
        label = f"{port['port']}/tcp {port['service']}"
        h = Hypothesis(
            id=hid, title=(title or f"{spec.title} ({label})")[:120], target=netloc,
            vector=check, prior=prior, posterior=prior,
            severity=services.CHECK_SEVERITY.get(check, "INFO"),
            rationale=(rationale or f"service seed: {label}"
                       + (" (unidentified)" if port["service"] == "unknown" else ""))[:200],
            max_attempts=1, parent=parent,
            meta={"source": "service", "check": check, "service": port["service"],
                  "host": host, "connect": prof.get("resolved_ip") or host,
                  "port": port["port"], "tls": bool(port.get("tls")),
                  "zones": _zones_for(host)},
        )
        state.add_hypothesis(h)
        return h

    def spawn_service_checks(self, state, parent: Hypothesis, found: list[str]) -> list[Hypothesis]:
        """svc-identify named the service: seed its checks and fix the profile."""
        spawned = []
        port_no = parent.meta.get("port")
        prof = state.host.get("profile") or {}
        for p in prof.get("open_ports", []):
            if p["port"] == port_no and p.get("proto", "tcp") == "tcp" and found:
                p["service"] = found[0]
        for svc in found:
            port = {"port": port_no, "service": svc, "tls": parent.meta.get("tls", False)}
            for key in services.checks_for(svc, port["tls"]):
                h = self._add_service_hyp(state, key, port, parent=parent.id,
                                          rationale=f"identified as {svc} by {parent.id}")
                if h is not None:
                    spawned.append(h)
        return spawned

    def _host_context_hint(self) -> str:
        if not self.host_profile:
            return ""
        prof = self.host_profile
        lines = ", ".join(
            f"{p['port']}/{p.get('proto', 'tcp')} {p['service']}"
            + (" " + " ".join(x for x in (p.get("product"), p.get("version")) if x)
               if p.get("product") or p.get("version") else "")
            for p in prof.get("open_ports", [])) or "no open ports"
        return f"Host profile ({prof.get('host')}): {lines}\n"

    # ── selection ───────────────────────────────────────────────────────
    def select(self, state) -> Optional[Plan]:
        """Choose the next hypothesis to test (highest posterior)."""
        testable = state.testable()
        if not testable:
            return None
        if self.use_llm():
            plan = self._llm_select(state, testable)
            if plan is not None:
                return plan
            state.fell_back_to_deterministic = True
        return self._deterministic_select(testable)

    def _deterministic_select(self, testable: list[Hypothesis]) -> Plan:
        h = max(testable, key=lambda x: (x.posterior, _sev_weight(x.severity)))
        return self._action_for(h, source="deterministic",
                                rationale=f"highest posterior ({h.posterior:.2f})")

    def _action_for(self, h: Hypothesis, source: str, rationale: str) -> Plan:
        if h.meta.get("source") == "service":
            return Plan(hypothesis=h, tool="suvari-svc", args=[h.vector, h.target],
                        url=h.target, rationale=rationale, source=source)
        return Plan(hypothesis=h, tool="curl",
                    args=["-s", "-S", "-i", h.target],
                    url=h.target, rationale=rationale, source=source)

    # ── evidence interpretation ─────────────────────────────────────────
    def interpret(self, h: Hypothesis, res: ExecResult) -> dict:
        """Detect the vector signature in a probe result.

        Returns {positive, detail, lr, severity} and, for robots, a list of
        child paths to spawn.
        """
        if h.meta.get("source") == "research":
            return reasoning.evaluate_probe(h.meta, res)
        if h.meta.get("source") == "service":
            return _interpret_service(h, res)
        vec = VECTOR_RULES[h.vector]
        positive, detail = vec.detect(res)
        children: list[str] = []
        if positive and h.vector == "robots-info-leak":
            children = _robots_paths(res.body)
        return {
            "positive": positive,
            "detail": detail,
            "lr": LR_POSITIVE if positive else LR_NEGATIVE,
            "severity": vec.severity,
            "children": children,
        }

    def spawn_children(self, state, parent: Hypothesis, paths: list[str]) -> list[Hypothesis]:
        """Create path-probe hypotheses for robots-disclosed paths."""
        spawned = []
        existing_targets = {h.target for h in state.hypotheses.values()}
        for p in paths:
            url = urljoin(self.base_url, p.lstrip("/"))
            if urlparse(url).netloc != urlparse(self.base_url).netloc:
                self._blocked(url, f"disclosed by {parent.id}, off target host")
                continue  # stay on target host
            if url in existing_targets:
                continue
            hid = state.next_hypothesis_id()
            h = Hypothesis(
                id=hid, title=f"Reachable disclosed path {p}", target=url,
                vector="path-probe", prior=0.5, posterior=0.5, severity="MEDIUM",
                rationale=f"disclosed by {parent.id} (robots.txt)", parent=parent.id,
            )
            state.add_hypothesis(h)
            existing_targets.add(url)
            spawned.append(h)
        return spawned

    # ── LLM helpers ─────────────────────────────────────────────────────
    _SCHEMA_HINT = (
        'Respond with ONLY this JSON (no prose, no markdown fences):\n'
        '{"hypotheses":[{"title":str,"vector":str,"target":str,"prior":float,'
        '"rationale":str}],'
        '"next_action":{"hypothesis_id":str,"tool":str,"args":[str],"why":str}}\n'
        f'Valid vectors: {sorted(VECTOR_RULES)}\n'
        f'Valid tools: {sorted(ALLOWLIST)}\n'
    )

    def _chat(self, prompt: str, max_tokens: int = 900) -> str:
        """Call ``llm.chat`` once, recording token usage and wall time.

        Uses the provider's ``usage`` block when available (exact counts); when
        the provider returns none, falls back to a character/4 estimate flagged
        ``estimated=True`` so the report never overstates its precision.
        """
        t0 = time.monotonic()
        text = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=max_tokens,
        )
        duration = time.monotonic() - t0
        model = getattr(self.llm, "model", "") or "unknown"
        reported = getattr(self.llm, "last_usage", None)
        if reported and (reported.get("prompt_tokens") or reported.get("completion_tokens")):
            rec = UsageRecord(
                model=model,
                prompt_tokens=int(reported.get("prompt_tokens", 0)),
                completion_tokens=int(reported.get("completion_tokens", 0)),
                duration=duration, estimated=False,
            )
        else:
            rec = UsageRecord(
                model=model,
                prompt_tokens=estimate_tokens(prompt),
                completion_tokens=estimate_tokens(text or ""),
                duration=duration, estimated=True,
            )
        self.usage.add(rec)
        return text

    def _llm_call_json(self, prompt: str) -> Optional[dict]:
        """Call the LLM and parse strict JSON, up to 3 attempts total."""
        for attempt in range(3):
            try:
                text = self._chat(prompt, max_tokens=900)
            except Exception as e:  # noqa: BLE001
                log.warning("LLM call failed (attempt %d): %s", attempt + 1, e)
                continue
            data = _extract_json(text)
            if data is not None:
                return data
            log.warning("LLM returned unparseable JSON (attempt %d)", attempt + 1)
        return None

    def _llm_augment(self, state) -> None:
        if self.service_mode:
            return self._llm_augment_services(state)
        prompt = (
            "You are a web security planner. Given the target, propose up to 4 "
            "additional distinct hypotheses worth testing.\n"
            f"Target: {self.base_url}\n"
            + self._host_context_hint()
            + self._tech_context_hint(state)
            + reasoning.llm_context(state.research)
            + self._SCHEMA_HINT
        )
        data = self._llm_call_json(prompt)
        if data is None:
            state.fell_back_to_deterministic = True
            return
        for hd in data.get("hypotheses", [])[:4]:
            vector = hd.get("vector")
            if vector not in VECTOR_RULES:
                continue
            target = hd.get("target") or urljoin(self.base_url, VECTOR_RULES[vector].path.lstrip("/"))
            if urlparse(target).netloc != urlparse(self.base_url).netloc:
                self._blocked(target, "llm-proposed target off target host")
                continue  # scope guard
            if any(h.target == target and h.vector == vector
                   for h in state.hypotheses.values()):
                continue
            hid = state.next_hypothesis_id()
            prior = _safe_prob(hd.get("prior"), VECTOR_RULES[vector].prior)
            state.add_hypothesis(Hypothesis(
                id=hid, title=str(hd.get("title", VECTOR_RULES[vector].title))[:120],
                target=target, vector=vector, prior=prior, posterior=prior,
                severity=VECTOR_RULES[vector].severity,
                rationale=str(hd.get("rationale", "llm-proposed"))[:200],
            ))

    def _llm_augment_services(self, state) -> None:
        """Let the model propose extra read-only service checks on open ports."""
        open_ports = {p["port"]: p for p in (self.host_profile or {}).get("open_ports", [])
                      if p.get("proto", "tcp") == "tcp"}
        if not open_ports:
            return
        host = (self.host_profile or {}).get("host", "")
        prompt = (
            "You are a network security planner. Given this host profile, propose up "
            "to 4 additional read-only service checks worth running (no credentials, "
            "no writes).\n"
            + self._host_context_hint()
            + 'Respond with ONLY this JSON: {"hypotheses":[{"title":str,"vector":str,'
              '"target":"host:port","prior":float,"rationale":str}]}\n'
            f"Valid vectors: {sorted(k for k in services.CHECKS if k != 'svc-identify')}\n"
            f"Targets must be {host}:<port> for one of the open ports.\n"
        )
        data = self._llm_call_json(prompt)
        if data is None:
            state.fell_back_to_deterministic = True
            return
        for hd in (data.get("hypotheses") or [])[:4]:
            check, target = hd.get("vector"), str(hd.get("target") or "")
            if check not in services.CHECKS:
                continue
            _, _, port_s = target.rpartition(":")
            port = open_ports.get(int(port_s)) if port_s.isdigit() else None
            expected = f"[{host}]:" if ":" in host else f"{host}:"
            if port is None or not target.startswith(expected):
                self._blocked(target, "llm-proposed service target is not an open port")
                continue
            self._add_service_hyp(state, check, port, parent=None,
                                  # floor keeps one positive result enough to confirm
                                  prior=max(0.2, _safe_prob(hd.get("prior"),
                                                            SERVICE_PRIOR_UNKNOWN)),
                                  title=str(hd.get("title") or ""),
                                  rationale=str(hd.get("rationale") or "llm-proposed"))

    def _tech_context_hint(self, state) -> str:
        """Tell the model what stack was detected and which vectors are seeded.

        The model still chooses; it just chooses informed rather than blind.
        """
        if not self.detected_tech:
            return ""
        seeded = sorted({h.vector for h in state.hypotheses.values()
                         if h.vector in tech_vectors.TECH_RULE_BY_KEY})
        hint = ("Detected technology: " + ", ".join(sorted(self.detected_tech)) + ".\n")
        if self.tech_ctx.get("project"):
            hint += f"Firebase project id: {self.tech_ctx['project']}.\n"
        if seeded:
            hint += ("Stack-specific vectors already seeded (read-only GET only): "
                     + ", ".join(seeded) + ".\n")
        return hint

    def _llm_select(self, state, testable: list[Hypothesis]) -> Optional[Plan]:
        listing = "\n".join(
            f'  {h.id}: vector={h.vector} posterior={h.posterior:.2f} target={h.target}'
            + (f' cve={h.meta.get("cve") or ",".join(c["id"] for c in h.meta.get("cves", []))}'
               if h.meta.get("source") == "research" else "")
            for h in testable
        )
        prompt = (
            "Pick the single most promising hypothesis to test next and explain "
            "why. Choose from these open hypotheses:\n" + listing + "\n\n"
            + self._host_context_hint()
            + reasoning.llm_context(state.research)
            + self._SCHEMA_HINT
            + "\nThe next_action.hypothesis_id MUST be one of the ids above and "
            "next_action.tool MUST be an allowlisted tool."
        )
        data = self._llm_call_json(prompt)
        if data is None:
            return None
        action = data.get("next_action") or {}
        hid = action.get("hypothesis_id")
        tool = action.get("tool")
        by_id = {h.id: h for h in testable}
        if hid not in by_id:
            log.warning("LLM chose unknown hypothesis_id=%r; falling back", hid)
            return None
        if by_id[hid].meta.get("source") == "service":
            tool = "suvari-svc"  # the check itself is the action; tool is ignored
        if tool not in ALLOWLIST and tool != "suvari-svc":
            log.warning("LLM chose non-allowlisted tool=%r; falling back", tool)
            return None
        h = by_id[hid]
        # Execution still goes through the vector's safe probe.
        return self._action_for(
            h, source="llm",
            rationale=str(action.get("why", "model selection"))[:200],
        )


def _interpret_service(h: Hypothesis, res: ExecResult) -> dict:
    """Map a service CheckResult onto the loop's evidence vocabulary."""
    d = res.data or {}
    status = d.get("status", services.ERROR)
    out = {"positive": status == services.POSITIVE,
           "detail": d.get("detail") or res.error,
           "severity": d.get("severity") or h.severity,
           "children": [], "spawn_services": list(d.get("spawn") or [])}
    if status == services.POSITIVE:
        out["lr"] = LR_POSITIVE
    elif status == services.NEGATIVE:
        out["lr"] = LR_NEGATIVE
    else:
        out["lr"] = 1.0
        out["inconclusive"] = status == services.INCONCLUSIVE
    return out


def _zones_for(host: str) -> list[str]:
    """Zone names worth an AXFR attempt for a hostname target (none for IPs)."""
    if not host or re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", host) or "." not in host:
        return []
    labels = host.rstrip(".").split(".")
    zones = [host.rstrip(".")]
    if len(labels) > 2:
        zones.append(".".join(labels[-2:]))
    return zones


def _sev_weight(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev.upper(), 0)


def _robots_paths(body: str) -> list[str]:
    return [p for p in re.findall(r"(?im)^\s*disallow:\s*(\S+)", body) if p and p != "/"]


def _safe_prob(val, default: float) -> float:
    try:
        f = float(val)
    except (TypeError, ValueError):
        return default
    if 0.0 < f < 1.0:
        return f
    return default


def _extract_json(text: str) -> Optional[dict]:
    """Best-effort JSON extraction from a model reply."""
    if not text:
        return None
    s = text.strip()
    if s.startswith("```"):
        nl = s.find("\n")
        if nl != -1:
            s = s[nl + 1:]
        if s.endswith("```"):
            s = s[:-3]
    s = s.strip()
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    # Fall back to the first balanced {...} block.
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(s[start:i + 1])
                    return obj if isinstance(obj, dict) else None
                except json.JSONDecodeError:
                    return None
    return None
