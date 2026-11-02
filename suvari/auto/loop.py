"""
The autonomous, probability-driven scan loop.

Each turn: select the highest-posterior testable hypothesis -> run its scoped
probe -> classify the result (L0-L5) -> write evidence -> Bayes-update the
posterior -> spawn follow-up hypotheses from new signals -> append a decision-log
entry -> persist state atomically. The loop stops on budget exhaustion or when
no testable hypotheses remain, then writes a report.

Every turn is wrapped in try/except: a single failing probe is logged and the
loop continues.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from ..failure import classify_failure
from . import tech_vectors
from .evidence import EvidenceStore
from .executor import Executor
from .hypothesis import (
    Hypothesis, STATUS_CONFIRMED, STATUS_REFUTED, STATUS_EXHAUSTED, PROB_MIN,
)
from .planner import Planner, CONFIRM_THRESHOLD
from .state import ScanState

log = logging.getLogger("suvari.auto.loop")


def _action_key(tool: str, args: list) -> str:
    return tool + "|" + " ".join(str(a) for a in args)


class AutoLoop:
    # Hard cap on total HTTP probes per run, independent of other budgets.
    MAX_REQUESTS = 200

    def __init__(self, state: ScanState, planner: Planner, executor: Executor,
                 max_steps: int = 20, time_budget: float = 300.0,
                 max_tokens: Optional[int] = None,
                 logger: Optional[logging.Logger] = None):
        self.state = state
        self.planner = planner
        self.executor = executor
        self.max_steps = max_steps
        self.time_budget = time_budget
        self.max_tokens = max_tokens
        self.log = logger or log
        self.evidence = EvidenceStore(state.auto_dir)
        # keep evidence sequence consistent across resume
        self.evidence._seq = _max_evidence_seq(state)
        # continue token accounting across resume rather than restarting at zero
        self.planner.usage.merge_totals(state.usage)

    def _budget_left(self) -> Optional[str]:
        if self.state.turn >= self.max_steps:
            return f"max-steps reached ({self.max_steps})"
        if len(self.state.tried_actions) >= self.MAX_REQUESTS:
            return f"request cap reached ({self.MAX_REQUESTS})"
        if self.state.wall_elapsed() >= self.time_budget:
            return f"time-budget reached ({self.time_budget:.0f}s)"
        if self.max_tokens is not None and \
                self.state.usage.get("total_tokens", 0) >= self.max_tokens:
            return f"token-budget reached ({self.max_tokens} tokens)"
        return None

    def _sync_usage(self) -> None:
        self.state.usage = self.planner.usage.totals()

    def _extend_scope(self) -> None:
        """Widen scope to the detected Firebase project's own backend hosts."""
        hosts = tech_vectors.scope_hosts(self.planner.detected_tech,
                                         self.planner.tech_ctx)
        for h in hosts:
            self.executor.allowed_hosts.add(h.lower())
            if h not in self.state.allowed_hosts:
                self.state.allowed_hosts.append(h)

    def _recon(self) -> list:
        """One read-only GET of the homepage to fingerprint the stack."""
        try:
            return [self.executor.http_probe(self.planner.base_url)]
        except Exception as e:  # noqa: BLE001 - recon must never kill the run
            self.log.warning("recon probe failed: %s", e)
            return []

    def run(self) -> dict:
        self.state.ensure_dirs()
        if not self.state.hypotheses:
            recon = self._recon()
            self.planner.bootstrap(self.state, recon)
            self._extend_scope()
            self._sync_usage()
            self.state.save()

        stop_reason = ""
        while True:
            over = self._budget_left()
            if over:
                stop_reason = over
                break
            plan = self.planner.select(self.state)
            self._sync_usage()  # select() may have made LLM calls
            if plan is None:
                stop_reason = "no testable hypotheses remain"
                break

            self.state.turn += 1
            try:
                self._run_turn(plan)
            except Exception as e:  # noqa: BLE001 - never let one turn kill the loop
                self.log.exception("turn %d failed", self.state.turn)
                self.state.notes.append(f"turn {self.state.turn} error: {e}")
            self._sync_usage()
            self.state.save()

        self.state.notes.append(f"stopped: {stop_reason}")
        self._sync_usage()
        self.state.save()
        return {
            "stop_reason": stop_reason,
            "turns": self.state.turn,
            "findings": self.state.findings,
            "hypotheses": [h.to_dict() for h in self.state.hypotheses.values()],
            "fell_back": self.state.fell_back_to_deterministic,
            "usage": self.state.usage,
            "detected_tech": sorted(self.planner.detected_tech),
        }

    def _run_turn(self, plan) -> None:
        h: Hypothesis = plan.hypothesis
        key = _action_key(plan.tool, plan.args)

        # repeat protection: never run the same tool+args twice
        if self.state.already_tried(key):
            h.status = STATUS_EXHAUSTED
            self._log_decision(plan, None, "skipped (duplicate action)")
            return
        self.state.mark_tried(key)

        posterior_before = h.posterior
        h.attempts += 1

        # execute (scoped HTTP probe)
        res = self.executor.http_probe(plan.url)

        # classify L0-L5
        classifier_output = res.error or f"HTTP {res.status}\n{res.body}"
        level = classify_failure(res.tool, classifier_output, res.duration)

        # interpret evidence against the hypothesis vector
        interp = self.planner.interpret(h, res)
        positive = interp["positive"]

        ev = self.evidence.record(
            hypothesis_id=h.id, vector=h.vector, turn=self.state.turn,
            res=res, failure_level=level.name, positive=positive,
            detail=interp["detail"],
        )
        h.evidence.append(ev.id)

        # Bayesian posterior update
        h.update_posterior(interp["lr"])
        posterior_after = h.posterior

        # resolve status + emit finding
        if positive:
            h.status = STATUS_CONFIRMED
            if posterior_after >= CONFIRM_THRESHOLD:
                self._emit_finding(h, interp, ev)
            # spawn follow-ups (concentrate where probability is high)
            if interp["children"]:
                spawned = self.planner.spawn_children(self.state, h, interp["children"])
                if spawned:
                    self.state.notes.append(
                        f"{h.id} spawned {len(spawned)} follow-up hypotheses")
        else:
            if res.error and res.status == 0:
                # probe could not run (not installed / out of scope / timeout);
                # leave open for a retry unless attempts exhausted
                if h.attempts >= h.max_attempts:
                    h.status = STATUS_EXHAUSTED
            elif h.posterior <= 0.1 or h.attempts >= h.max_attempts:
                h.status = STATUS_REFUTED

        self._log_decision(plan, ev, interp["detail"] or res.error,
                           posterior_before, posterior_after, level.name, positive)

    def _emit_finding(self, h: Hypothesis, interp: dict, ev) -> None:
        if any(f["vector"] == h.vector and f["target"] == h.target
               for f in self.state.findings):
            return
        self.state.findings.append({
            "id": f"F{len(self.state.findings) + 1:03d}",
            "hypothesis_id": h.id,
            "title": h.title,
            "severity": interp["severity"],
            "vector": h.vector,
            "target": h.target,
            "detail": interp["detail"],
            "evidence": self.evidence.rel_path(ev),
            "posterior": round(h.posterior, 3),
            "confirmed_turn": self.state.turn,
        })

    def _log_decision(self, plan, ev, result, posterior_before=None,
                      posterior_after=None, level="", positive=False) -> None:
        h = plan.hypothesis
        self.state.decision_log.append({
            "turn": self.state.turn,
            "hypothesis_id": h.id,
            "hypothesis": h.title,
            "vector": h.vector,
            "prior": round(h.prior, 3),
            "posterior_before": round(posterior_before, 3) if posterior_before is not None else None,
            "posterior_after": round(posterior_after, 3) if posterior_after is not None else None,
            "action": f"{plan.tool} {plan.url}",
            "rationale": plan.rationale,
            "source": plan.source,
            "result_class": level,
            "positive": positive,
            "result": (result or "")[:200],
            "evidence": self.evidence.rel_path(ev) if ev else None,
        })


def _max_evidence_seq(state: ScanState) -> int:
    seq = 0
    for h in state.hypotheses.values():
        for eid in h.evidence:
            try:
                seq = max(seq, int(eid.lstrip("E")))
            except ValueError:
                pass
    return seq
