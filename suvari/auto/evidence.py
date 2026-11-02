"""
Evidence capture for the autonomous loop.

Every probe produces a machine-readable record at
``<workspace>/auto/evidence/<id>.json`` (request, status, headers, body slice,
duration) and a human-readable line appended to ``<workspace>/auto/evidence.md``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .executor import ExecResult, BODY_CAP


@dataclass
class Evidence:
    id: str
    hypothesis_id: str
    vector: str
    turn: int
    timestamp: float
    request: dict
    response: dict
    duration: float
    failure_level: str
    positive: bool
    detail: str
    error: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceStore:
    def __init__(self, auto_dir: Path, *, evidence_dir: Path | None = None,
                 md_path: Path | None = None, rel_prefix: str = "auto/evidence"):
        self.dir = Path(evidence_dir) if evidence_dir else Path(auto_dir) / "evidence"
        self.md = Path(md_path) if md_path else Path(auto_dir) / "evidence.md"
        self.rel_prefix = rel_prefix.rstrip("/")
        self._seq = 0

    @classmethod
    def for_state(cls, state) -> "EvidenceStore":
        return cls(state.auto_dir, evidence_dir=state.evidence_dir,
                   md_path=state.evidence_md, rel_prefix=state.evidence_rel)

    def next_id(self) -> str:
        self._seq += 1
        return f"E{self._seq:03d}"

    def record(self, hypothesis_id: str, vector: str, turn: int,
               res: ExecResult, failure_level: str, positive: bool,
               detail: str, extra: dict | None = None) -> Evidence:
        self.dir.mkdir(parents=True, exist_ok=True)
        ev = Evidence(
            id=self.next_id(),
            hypothesis_id=hypothesis_id,
            vector=vector,
            turn=turn,
            timestamp=time.time(),
            request={"method": "GET", "url": res.url,
                     "tool": res.tool, "args": res.args},
            response={
                "status": res.status,
                "headers": res.headers,
                "body": res.body[:BODY_CAP],
                "returncode": res.returncode,
            },
            duration=round(res.duration, 3),
            failure_level=failure_level,
            positive=positive,
            detail=detail,
            error=res.error,
            extra=dict(extra or {}),
        )
        (self.dir / f"{ev.id}.json").write_text(json.dumps(ev.to_dict(), indent=2))
        self._append_md(ev)
        return ev

    def rel_path(self, ev: Evidence) -> str:
        return f"{self.rel_prefix}/{ev.id}.json"

    def _append_md(self, ev: Evidence) -> None:
        self.md.parent.mkdir(parents=True, exist_ok=True)
        if not self.md.exists():
            self.md.write_text("# Evidence log\n\n")
        mark = "POSITIVE" if ev.positive else "negative"
        tag = ""
        if ev.extra.get("source"):
            tag = f" (source: {ev.extra['source']}"
            if ev.extra.get("cves"):
                tag += ", " + ", ".join(ev.extra["cves"][:6])
            if ev.extra.get("reused_response"):
                tag += ", reused response — no new request"
            tag += ")"
        line = (
            f"## {ev.id} — {ev.hypothesis_id} ({ev.vector}) [{mark}]{tag}\n"
            f"- turn: {ev.turn}\n"
            f"- request: GET {ev.request['url']}\n"
            f"- status: {ev.response['status']}  "
            f"({ev.failure_level}, {ev.duration}s)\n"
            f"- detail: {ev.detail or ev.error or '-'}\n\n"
        )
        with self.md.open("a") as fh:
            fh.write(line)
