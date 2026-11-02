"""
Markdown report writer for the autonomous loop.

Writes ``<workspace>/reports/auto-<ts>.md`` with a summary, findings (severity +
evidence path), the full decision-log table (why the loop went where it did),
the hypotheses that were tried and refuted, and recommendations.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .hypothesis import STATUS_CONFIRMED, STATUS_REFUTED
from .state import ScanState

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_RECS = {
    "git-exposure": "Block access to `/.git/` at the web server and remove the "
                    "repository from the web root.",
    "admin-auth-bypass": "Restrict the admin interface by IP/VPN and enforce "
                         "strong authentication and rate limiting.",
    "dir-listing": "Disable automatic directory indexing (e.g. `Options -Indexes`).",
    "robots-info-leak": "Do not list sensitive paths in robots.txt; protect them "
                        "with authentication instead.",
    "missing-security-headers": "Add Content-Security-Policy and X-Frame-Options "
                                "(plus HSTS) response headers.",
    "path-probe": "Protect disclosed internal paths with authentication or remove "
                  "them from the public server.",
}


def write_report(state: ScanState, result: dict) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = state.root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / f"auto-{ts}.md"

    findings = sorted(state.findings,
                      key=lambda f: _SEV_ORDER.get(f["severity"].upper(), 9))
    lines: list[str] = []
    a = lines.append

    a(f"# Suvari autonomous scan — {state.target}")
    a("")
    a(f"- Generated: {datetime.now().isoformat(timespec='seconds')}")
    a(f"- Turns run: {state.turn}")
    a(f"- Stop reason: {result.get('stop_reason', '-')}")
    a(f"- Hypotheses: {len(state.hypotheses)} "
      f"(confirmed {sum(1 for h in state.hypotheses.values() if h.status == STATUS_CONFIRMED)}, "
      f"refuted {sum(1 for h in state.hypotheses.values() if h.status == STATUS_REFUTED)})")
    a(f"- Findings: {len(findings)}")
    a(f"- Planner: {'deterministic fallback used' if state.fell_back_to_deterministic else 'as configured'}")
    a("")

    # ── findings ──
    a("## Findings")
    a("")
    if findings:
        for f in findings:
            a(f"### [{f['severity']}] {f['title']}")
            a(f"- Target: `{f['target']}`")
            a(f"- Detail: {f['detail']}")
            a(f"- Posterior: {f['posterior']}")
            a(f"- Evidence: `{f['evidence']}`")
            rec = _RECS.get(f["vector"])
            if rec:
                a(f"- Recommendation: {rec}")
            a("")
    else:
        a("_No findings._\n")

    # ── decision log ──
    a("## Decision log")
    a("")
    a("| Turn | Hypothesis | Prior | Post→ | Source | Result (L) | + | Action |")
    a("|-----:|------------|------:|------:|--------|-----------|---|--------|")
    for d in state.decision_log:
        pb = d.get("posterior_before")
        pa = d.get("posterior_after")
        trans = f"{pb}→{pa}" if pb is not None else "-"
        a(f"| {d['turn']} | {d['hypothesis']} | {d.get('prior','-')} | {trans} "
          f"| {d['source']} | {d.get('result_class','-')} "
          f"| {'Y' if d.get('positive') else 'n'} | `{d['action']}` |")
    a("")

    # ── tried & refuted ──
    a("## Tried but not confirmed")
    a("")
    dull = [h for h in state.hypotheses.values() if h.status != STATUS_CONFIRMED]
    if dull:
        for h in dull:
            a(f"- `{h.id}` {h.title} — status={h.status}, "
              f"posterior={h.posterior:.2f}, attempts={h.attempts}")
    else:
        a("_All tested hypotheses were confirmed._")
    a("")

    # ── recommendations ──
    a("## Recommendations")
    a("")
    seen = set()
    for f in findings:
        rec = _RECS.get(f["vector"])
        if rec and rec not in seen:
            a(f"- {rec}")
            seen.add(rec)
    if not seen:
        a("- No confirmed issues; re-run with an LLM provider for deeper coverage.")
    a("")

    if state.notes:
        a("## Notes")
        a("")
        for n in state.notes:
            a(f"- {n}")
        a("")

    out.write_text("\n".join(lines))
    return out
