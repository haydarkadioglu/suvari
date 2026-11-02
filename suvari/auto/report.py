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
from .usage import format_summary, human_tokens

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
    # technology-aware vectors
    "firebase-init-exposure": "Do not serve `/__/firebase/init.json`; load Firebase "
                              "config from the SDK's reserved URLs only where needed.",
    "firebase-config-leak": "A public Firebase web config is expected, but lock it "
                            "down with Security Rules and App Check so the keys are "
                            "not usable for unauthorized reads/writes.",
    "firebase-rtdb-open": "Tighten Realtime Database Security Rules — require auth "
                          "for reads/writes; never leave `.read: true` at the root.",
    "firestore-open": "Tighten Firestore Security Rules to deny unauthenticated "
                      "document reads.",
    "firebase-storage-open": "Tighten Storage Security Rules so objects are not "
                             "publicly listable or readable.",
    "firebase-identity-config": "Review enabled sign-in providers; disable any that "
                                "are not used.",
    "firebase-files-exposure": "Remove `firebase.json`/`.firebaserc`/service-account "
                               "keys from the web root; never deploy service "
                               "credentials to the client.",
    "nextjs-sourcemap": "Disable production source maps (`productionBrowserSourceMaps: "
                        "false`) so original source is not served.",
    "nextjs-data": "Treat `/_next/data` payloads as public; keep secrets out of "
                   "server-rendered props.",
    "nextjs-api": "Review exposed API routes for authentication and input validation.",
    "netlify-functions": "Require authorization in serverless functions; do not rely "
                         "on obscurity of the endpoint path.",
    "netlify-identity": "Review Netlify Identity registration settings and disable "
                        "open signup if not intended.",
    "netlify-config": "Remove sensitive rules from public `_headers`/`_redirects`.",
    "wp-users": "Restrict the `wp-json/wp/v2/users` endpoint to block username "
                "enumeration.",
    "wp-xmlrpc": "Disable `xmlrpc.php` if unused to cut brute-force/pingback surface.",
    "wp-login": "Rate-limit and protect `wp-login.php` (e.g. 2FA, IP allowlist).",
    "sitemap-leak": "Review the sitemap for paths that should not be publicly "
                    "discoverable.",
    "security-txt": "Informational — a security.txt is good practice; keep it current.",
    "dotenv-exposure": "Remove the `.env` file from the web root immediately and "
                       "rotate any leaked secrets.",
    "server-status": "Restrict `/server-status` (mod_status) to localhost/trusted IPs.",
}


def write_report(state: ScanState, result: dict) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = state.root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / f"auto-{ts}.md"

    findings = _sorted_findings(state)
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
    tech = result.get("detected_tech") or []
    if tech:
        n_tech = sum(1 for h in state.hypotheses.values()
                     if h.rationale.startswith("tech-aware"))
        a(f"- Detected technology: {', '.join(tech)} "
          f"({n_tech} technology-aware vectors seeded)")
    a("")

    # ── LLM usage ──
    a("## LLM usage")
    a("")
    u = state.usage or {}
    if u.get("calls"):
        a(f"- Calls: {u.get('calls', 0)}")
        a(f"- Prompt tokens: {human_tokens(u.get('prompt_tokens', 0))} "
          f"({u.get('prompt_tokens', 0)})")
        a(f"- Completion tokens: {human_tokens(u.get('completion_tokens', 0))} "
          f"({u.get('completion_tokens', 0)})")
        a(f"- Total tokens: {human_tokens(u.get('total_tokens', 0))} "
          f"({u.get('total_tokens', 0)})")
        if u.get("models"):
            a(f"- Model(s): {', '.join(u['models'])}")
        if u.get("cost_known") and u.get("cost_usd") is not None:
            a(f"- Approx. cost: ~${u['cost_usd']:.4f} USD")
        else:
            a("- Approx. cost: cost unknown (no price for this model)")
        if u.get("estimated_calls"):
            a(f"- Note: {u['estimated_calls']} of {u['calls']} calls had "
              f"**estimated** token counts (provider returned no usage data).")
    else:
        a("_No LLM calls (deterministic engine)._")
    a("")
    a(f"`{format_summary(u)}`")
    a("")

    lines += _findings_section(findings, "##")
    lines += _decision_log_section(state, "##")
    lines += _tried_section(state, "##")
    lines += _recommendations_section(findings, "##")
    lines += _notes_section(state, "##")

    out.write_text("\n".join(lines))
    return out


# ── reusable sections ──────────────────────────────────────────────────

def _sorted_findings(state: ScanState) -> list[dict]:
    return sorted(state.findings,
                  key=lambda f: _SEV_ORDER.get(f["severity"].upper(), 9))


def _findings_section(findings: list[dict], h: str) -> list[str]:
    lines = [f"{h} Findings", ""]
    a = lines.append
    if findings:
        for f in findings:
            a(f"{h}# [{f['severity']}] {f['title']}")
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
    return lines


def _decision_log_section(state: ScanState, h: str) -> list[str]:
    lines = [f"{h} Decision log", "",
             "| Turn | Hypothesis | Prior | Post→ | Source | Result (L) | + | Action |",
             "|-----:|------------|------:|------:|--------|-----------|---|--------|"]
    for d in state.decision_log:
        pb = d.get("posterior_before")
        pa = d.get("posterior_after")
        trans = f"{pb}→{pa}" if pb is not None else "-"
        lines.append(
            f"| {d['turn']} | {d['hypothesis']} | {d.get('prior','-')} | {trans} "
            f"| {d['source']} | {d.get('result_class','-')} "
            f"| {'Y' if d.get('positive') else 'n'} | `{d['action']}` |")
    lines.append("")
    return lines


def _tried_section(state: ScanState, h: str) -> list[str]:
    lines = [f"{h} Tried but not confirmed", ""]
    dull = [x for x in state.hypotheses.values() if x.status != STATUS_CONFIRMED]
    if dull:
        for x in dull:
            lines.append(f"- `{x.id}` {x.title} — status={x.status}, "
                         f"posterior={x.posterior:.2f}, attempts={x.attempts}")
    else:
        lines.append("_All tested hypotheses were confirmed._")
    lines.append("")
    return lines


def _recommendations_section(findings: list[dict], h: str) -> list[str]:
    lines = [f"{h} Recommendations", ""]
    seen = set()
    for f in findings:
        rec = _RECS.get(f["vector"])
        if rec and rec not in seen:
            lines.append(f"- {rec}")
            seen.add(rec)
    if not seen:
        lines.append("- No confirmed issues; re-run with an LLM provider for deeper coverage.")
    lines.append("")
    return lines


def _notes_section(state: ScanState, h: str) -> list[str]:
    if not state.notes:
        return []
    return [f"{h} Notes", ""] + [f"- {n}" for n in state.notes] + [""]


# ── multi-target job report ────────────────────────────────────────────

def job_report_path(job, job_dir: Path) -> Path:
    ts = datetime.fromtimestamp(job.created_at).strftime("%Y%m%d_%H%M%S")
    return Path(job_dir) / "reports" / f"auto-{ts}.md"


def write_job_report(job, job_dir: Path, final: bool = False) -> Path:
    """Write (or rewrite) the single report for a job.

    Built only from what is on disk (checkpoint + per-target state files), so
    it can be produced while the job is still running; ``final`` marks the
    report as complete instead of interim.
    """
    from .jobs import format_duration

    job_dir = Path(job_dir)
    out = job_report_path(job, job_dir)
    states: dict[str, ScanState] = {}
    for t in job.targets:
        sf = job_dir / t.state_rel
        if sf.exists():
            try:
                states[t.key] = ScanState.load(job_dir, state_file=sf)
            except (OSError, ValueError, KeyError):
                pass

    all_findings = [f for st in states.values() for f in st.findings]
    c = job.counters
    lines: list[str] = []
    a = lines.append
    mark = "FINAL" if final else "INTERIM — job still in progress or paused"

    a(f"# Suvari autonomous job — {job.id}")
    a("")
    a(f"**Report status: {mark}**")
    a("")
    a(f"- Generated: {datetime.now().isoformat(timespec='seconds')}")
    a(f"- Job status: {job.status}" + (f" ({job.stop_reason})" if job.stop_reason else ""))
    a(f"- Engine: {'deterministic (dry-run)' if job.engine.get('dry_run') else (job.engine.get('provider') or '-') + '/' + (job.engine.get('model') or 'default')}")
    a(f"- Scope: {', '.join(f'`{e}`' for e in job.scope)}")
    a("")

    a("## Targets")
    a("")
    a("| # | Target | Status | Turns | Findings | Note |")
    a("|--:|--------|--------|------:|---------:|------|")
    for i, t in enumerate(job.targets, 1):
        a(f"| {i} | `{t.url}` | {t.status} | {t.turns} | {t.findings} "
          f"| {(t.stop_reason or '-').replace('|', '/')[:120]} |")
    a("")

    for t in job.targets:
        a(f"## Target: {t.url}")
        a("")
        a(f"- Status: {t.status}" + (f" — {t.stop_reason}" if t.stop_reason else ""))
        a(f"- Evidence directory: `{t.evidence_rel}/`")
        st = states.get(t.key)
        if st is None:
            a("- Not scanned.")
            a("")
            continue
        a(f"- Turns: {st.turn}; hypotheses: {len(st.hypotheses)}; "
          f"findings: {len(st.findings)}")
        a("")
        findings = _sorted_findings(st)
        lines += _findings_section(findings, "###")
        lines += _decision_log_section(st, "###")
        lines += _tried_section(st, "###")
        lines += _notes_section(st, "###")

    a("## Blocked by scope")
    a("")
    if job.blocked:
        a("| Target | Reason | Source |")
        a("|--------|--------|--------|")
        for b in job.blocked:
            a(f"| `{b['target']}` | {b['reason']} | {b.get('source', '')} |")
    else:
        a("_No requests were refused by scope._")
    a("")

    a("## Recommendations")
    a("")
    seen = set()
    for f in sorted(all_findings, key=lambda f: _SEV_ORDER.get(f["severity"].upper(), 9)):
        rec = _RECS.get(f["vector"])
        if rec and rec not in seen:
            a(f"- {rec}")
            seen.add(rec)
    if not seen:
        a("- No confirmed issues.")
    a("")

    counts = job.target_counts()
    a("## Summary")
    a("")
    a(f"- Targets: {len(job.targets)} ("
      + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ")")
    a(f"- Requests sent: {c.get('requests', 0)}"
      + (f" / budget {job.budget['max_requests']}" if job.budget.get("max_requests") else ""))
    a(f"- Active time: {format_duration(c.get('elapsed', 0))}"
      + (f" / budget {format_duration(job.budget['duration'])}" if job.budget.get("duration") else "")
      + f" over {c.get('runs', 0)} run(s)")
    a(f"- Turns: {c.get('turns', 0)}")
    sev: dict[str, int] = {}
    for f in all_findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    a(f"- Findings: {len(all_findings)}"
      + (" (" + ", ".join(f"{k} {v}" for k, v in sorted(sev.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))) + ")" if sev else ""))
    a(f"- LLM usage: {c.get('llm_calls', 0)} calls, ~{c.get('llm_tokens', 0)} tokens"
      + (f" / budget {job.budget['max_tokens']}" if job.budget.get("max_tokens") else ""))
    a(f"- Blocked by scope: {len(job.blocked)}")
    a("")

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".md.tmp")
    tmp.write_text("\n".join(lines))
    tmp.replace(out)
    return out
