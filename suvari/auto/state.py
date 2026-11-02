"""
Persistent, resumable state for the autonomous scan loop.

State is written atomically (write to a temp file, then ``os.replace``) after
every turn so a crash or interrupt never leaves a half-written ``state.json``,
and ``--resume`` can pick up exactly where the loop left off.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from .hypothesis import Hypothesis


class ScanState:
    """In-memory loop state backed by ``<workspace>/auto/state.json``."""

    def __init__(self, root: Path, target: str, allowed_hosts: list[str],
                 budget: Optional[dict] = None):
        self.root = Path(root)
        self.auto_dir = self.root / "auto"
        self.evidence_dir = self.auto_dir / "evidence"
        self.state_file = self.auto_dir / "state.json"

        self.target = target
        self.allowed_hosts = list(allowed_hosts)
        self.budget = budget or {}

        self.hypotheses: dict[str, Hypothesis] = {}
        self.decision_log: list[dict] = []
        self.findings: list[dict] = []
        self.tried_actions: list[str] = []     # dedupe keys "tool|args"
        self.turn = 0
        self.started_at = time.time()
        self.elapsed_before_resume = 0.0        # seconds consumed in prior runs
        self.fell_back_to_deterministic = False
        self.notes: list[str] = []
        self.usage: dict = {
            "calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
            "total_tokens": 0, "estimated_calls": 0, "cost_usd": 0.0,
        }
        self._seq = 0

    # ── id helpers ──────────────────────────────────────────────────────
    def next_hypothesis_id(self) -> str:
        self._seq += 1
        return f"H{self._seq:03d}"

    def add_hypothesis(self, h: Hypothesis) -> None:
        self.hypotheses[h.id] = h

    def testable(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses.values() if h.is_testable()]

    def already_tried(self, action_key: str) -> bool:
        return action_key in self.tried_actions

    def mark_tried(self, action_key: str) -> None:
        if action_key not in self.tried_actions:
            self.tried_actions.append(action_key)

    def wall_elapsed(self) -> float:
        return self.elapsed_before_resume + (time.time() - self.started_at)

    # ── persistence ─────────────────────────────────────────────────────
    def ensure_dirs(self) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        """Atomically persist the full state to disk."""
        self.ensure_dirs()
        data = {
            "target": self.target,
            "allowed_hosts": self.allowed_hosts,
            "budget": self.budget,
            "turn": self.turn,
            "elapsed": self.wall_elapsed(),
            "seq": self._seq,
            "fell_back_to_deterministic": self.fell_back_to_deterministic,
            "notes": self.notes,
            "usage": self.usage,
            "hypotheses": [h.to_dict() for h in self.hypotheses.values()],
            "decision_log": self.decision_log,
            "findings": self.findings,
            "tried_actions": self.tried_actions,
        }
        tmp = self.state_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, self.state_file)

    @classmethod
    def load(cls, root: Path) -> "ScanState":
        """Rebuild a ScanState from a previously saved ``state.json``."""
        root = Path(root)
        state_file = root / "auto" / "state.json"
        data = json.loads(state_file.read_text())
        st = cls(root, data["target"], data.get("allowed_hosts", []),
                 data.get("budget", {}))
        st.turn = data.get("turn", 0)
        st._seq = data.get("seq", 0)
        st.elapsed_before_resume = data.get("elapsed", 0.0)
        st.fell_back_to_deterministic = data.get("fell_back_to_deterministic", False)
        st.notes = data.get("notes", [])
        if data.get("usage"):
            st.usage = data["usage"]
        st.decision_log = data.get("decision_log", [])
        st.findings = data.get("findings", [])
        st.tried_actions = data.get("tried_actions", [])
        for hd in data.get("hypotheses", []):
            h = Hypothesis.from_dict(hd)
            st.hypotheses[h.id] = h
        return st

    @staticmethod
    def exists(root: Path) -> bool:
        return (Path(root) / "auto" / "state.json").exists()
