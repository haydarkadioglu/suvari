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

from . import tech_vectors
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


class Planner:
    def __init__(self, base_url: str, llm=None, dry_run: bool = False,
                 on_blocked: Optional[Callable[[str, str], None]] = None):
        self.base_url = base_url.rstrip("/") + "/"
        self.llm = llm
        self.dry_run = dry_run
        self.usage = UsageTracker()
        self.detected_tech: set[str] = set()
        self.tech_ctx: dict = {}
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
        return Plan(hypothesis=h, tool="curl",
                    args=["-s", "-S", "-i", h.target],
                    url=h.target, rationale=rationale, source=source)

    # ── evidence interpretation ─────────────────────────────────────────
    def interpret(self, h: Hypothesis, res: ExecResult) -> dict:
        """Detect the vector signature in a probe result.

        Returns {positive, detail, lr, severity} and, for robots, a list of
        child paths to spawn.
        """
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
        prompt = (
            "You are a web security planner. Given the target, propose up to 4 "
            "additional distinct hypotheses worth testing.\n"
            f"Target: {self.base_url}\n"
            + self._tech_context_hint(state)
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
            for h in testable
        )
        prompt = (
            "Pick the single most promising hypothesis to test next and explain "
            "why. Choose from these open hypotheses:\n" + listing + "\n\n"
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
        if tool not in ALLOWLIST:
            log.warning("LLM chose non-allowlisted tool=%r; falling back", tool)
            return None
        h = by_id[hid]
        # Execution still goes through the vector's safe probe.
        return self._action_for(
            h, source="llm",
            rationale=str(action.get("why", "model selection"))[:200],
        )


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
    except json.JSONDecodeError as e:
        log.debug("planner reply is not bare JSON, scanning for a {...} block: %s", e)
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
