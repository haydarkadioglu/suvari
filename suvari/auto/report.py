"""
Markdown report writer for the autonomous loop.

Writes ``<workspace>/reports/auto-<ts>.md`` with a summary, findings (severity +
evidence path), the full decision-log table (why the loop went where it did),
the hypotheses that were tried and refuted, and recommendations.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from . import services
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
    # research-derived (known CVE) checks
    "cve-version-check": "Upgrade the component to a release outside the CVE's affected "
                         "range (see the advisory references in the Research section).",
    "cve-surface": "The component a known CVE targets is exposed; verify its version "
                   "and upgrade, or disable the component if unused.",
    "cve-mitigation-header": "Add the missing security header; it limits the impact of "
                             "the related known CVE class.",
    "cve-file-exposure": "Block public access to the file named in the advisory.",
}

APPLICABLE = 0.35  # mirrors reasoning.APPLICABLE_THRESHOLD


def _rec(vector: str) -> str | None:
    return _RECS.get(vector) or services.RECOMMENDATIONS.get(vector)


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
    lines += _research_section(state, "##")
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
            rec = _rec(f["vector"])
            if rec:
                a(f"- Recommendation: {rec}")
            a("")
    else:
        a("_No findings._\n")
    return lines


def research_stats(state: ScanState) -> dict:
    """Counts for the Research section and CLI summary."""
    cands = (state.research or {}).get("candidates", [])
    tested = [c for c in cands if c.get("results")]
    return {
        "found": len(cands),
        "applicable": sum(1 for c in cands if c["score"] >= APPLICABLE),
        "tested": len(tested),
        "verified": sum(1 for c in tested if any(
            r["positive"] and r["kind"] == "version-fingerprint" for r in c["results"])),
        "surface": sum(1 for c in tested if any(
            r["positive"] and r["kind"] != "version-fingerprint" for r in c["results"])),
        "ruled_out": sum(1 for c in tested if any(
            not r["positive"] and not r["inconclusive"] and r["kind"] == "version-fingerprint"
            for r in c["results"])),
    }


def _cve_tags(c: dict) -> str:
    tags = [f"CVSS {c['cvss']}" if c.get("cvss") is not None else "CVSS n/a"]
    if c.get("kev"):
        tags.append("KEV")
    return ", ".join(tags)


def _cve_outcome(c: dict) -> str:
    res = c.get("results") or []
    if not res:
        if c["score"] < APPLICABLE:
            return "not tested (below applicability threshold)"
        if not c.get("hypotheses"):
            return "not tested (not seeded)"
        return "not tested (step budget ran out first)"
    parts = []
    for r in res:
        if r["inconclusive"]:
            verdict = "inconclusive"
        elif r["positive"]:
            verdict = "VERIFIED" if r["kind"] == "version-fingerprint" else "surface present"
        else:
            verdict = "ruled out" if r["kind"] == "version-fingerprint" else "negative"
        parts.append(f"{r['kind']}: {verdict} — {r['detail']}")
    return "tested: " + "; ".join(parts)


def _research_section(state: ScanState, h: str) -> list[str]:
    rs = state.research or {}
    if not rs.get("enabled"):
        return []
    lines = [f"{h} Research", ""]
    a = lines.append
    for t in rs.get("techs", []):
        src = "cache (stale, offline)" if t.get("stale") else (
            "cache" if t.get("from_cache") else "live")
        a(f"- `{t['tech']}` version {t.get('version') or 'unknown'}: "
          f"{t.get('total_found', 0)} matching records, {t.get('returned', 0)} newest analysed, "
          f"{t.get('kev', 0)} in CISA KEV · source: {src}"
          + (f" · query `{t['query']}`" if t.get("query") else "")
          + (f" · observed components: {', '.join(t['features'])}" if t.get("features") else "")
          + (f" · error: {t['error']}" if t.get("error") else ""))
    if not rs.get("techs"):
        a("- No researchable technology detected.")
    st = research_stats(state)
    a(f"- CVEs found: {st['found']} · scored applicable (≥{APPLICABLE}): {st['applicable']} "
      f"· tested: {st['tested']} · verified (version in affected range): {st['verified']} "
      f"· ruled out by version: {st['ruled_out']} · attack surface present: {st['surface']}")
    a("")
    cands = sorted(rs.get("candidates", []), key=lambda c: -c["score"])
    shown = [c for c in cands if c.get("results") or c["score"] >= APPLICABLE] or cands[:5]
    for c in shown[:15]:
        a(f"- **{c['cve']}** ({_cve_tags(c)}) score {c['score']:.2f} → {_cve_outcome(c)}")
        a(f"  - why: {c['why']}")
    if len(cands) > len(shown[:15]):
        rest = cands[len(shown[:15]):]
        a("")
        a(f"<details><summary>{len(rest)} lower-scored CVEs</summary>")
        a("")
        a("| CVE | CVSS | KEV | Score | Why |")
        a("|-----|-----:|:---:|------:|-----|")
        for c in rest:
            a(f"| {c['cve']} | {c.get('cvss') if c.get('cvss') is not None else '-'} "
              f"| {'Y' if c.get('kev') else ''} | {c['score']:.2f} "
              f"| {c['why'].replace('|', '/')[:140]} |")
        a("")
        a("</details>")
    a("")
    return lines


def _decision_log_section(state: ScanState, h: str) -> list[str]:
    lines = [f"{h} Decision log", "",
             "| Turn | Hypothesis | Prior | Post→ | Source | Result (L) | + | Action |",
             "|-----:|------------|------:|------:|--------|-----------|---|--------|"]
    for d in state.decision_log:
        pb = d.get("posterior_before")
        pa = d.get("posterior_after")
        trans = f"{pb}→{pa}" if pb is not None else "-"
        src = d["source"] + ("/research" if d.get("origin") == "research" else "")
        lines.append(
            f"| {d['turn']} | {d['hypothesis']} | {d.get('prior','-')} | {trans} "
            f"| {src} | {d.get('result_class','-')} "
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
        rec = _rec(f["vector"])
        if rec and rec not in seen:
            lines.append(f"- {rec}")
            seen.add(rec)
    if not seen:
        lines.append("- No confirmed issues; re-run with an LLM provider for deeper coverage.")
    lines.append("")
    return lines


def _cell(s, n: int = 80) -> str:
    return str(s or "").replace("|", "/").replace("\r", "").replace("\n", " ")[:n]


def _host_section(state: ScanState, h: str) -> list[str]:
    """Host profile (open ports) and every service check outcome."""
    host = state.host or {}
    prof = host.get("profile")
    if not prof:
        return []
    lines = [f"{h} Host profile", ""]
    a = lines.append
    a(f"- Host: `{prof.get('host')}` (resolved {prof.get('resolved_ip')}); "
      f"{prof.get('scanned', 0)} TCP ports scanned"
      + (f", UDP 53/123/161 probed" if prof.get("udp_scanned") else "")
      + (f", {prof['skipped']} out of scope" if prof.get("skipped") else "")
      + f" in {prof.get('duration', 0)}s")
    if prof.get("ssh_hostkey"):
        a(f"- SSH host key(s): {prof['ssh_hostkey']}")
    a("")
    ports = prof.get("open_ports") or []
    if ports:
        local = any(p.get("process") for p in ports)
        a("| Port | Service | Product / version | TLS | Banner |" + (" Process |" if local else ""))
        a("|-----:|---------|-------------------|:---:|--------|" + ("---------|" if local else ""))
        for p in ports:
            prod = " ".join(x for x in (p.get("product"), p.get("version")) if x)
            a(f"| {p['port']}/{p.get('proto', 'tcp')} | {p['service']} | {_cell(prod, 40) or '-'} "
              f"| {'Y' if p.get('tls') else ''} | `{_cell(p.get('banner'), 70) or '-'}` |"
              + (f" {_cell(p.get('process'), 60) or '-'} |" if local else ""))
    else:
        a("_No open ports found._")
    a("")
    checks = host.get("checks") or []
    lines += [f"{h} Service findings", ""]
    if checks:
        a("| Port | Service | Check | Result | Severity | Detail | Evidence |")
        a("|-----:|---------|-------|--------|----------|--------|----------|")
        order = {services.POSITIVE: 0, services.ERROR: 1, services.INCONCLUSIVE: 2,
                 services.NEGATIVE: 3}
        for c in sorted(checks, key=lambda c: (order.get(c.get("status"), 9), c.get("port", 0))):
            res = c.get("status", "?")
            res = "**ISSUE**" if res == services.POSITIVE else res
            ev = _cell(c.get("evidence"), 160)
            a(f"| {c.get('port')} | {c.get('service')} | {c.get('check')} | {res} "
              f"| {c.get('severity', '')} | {_cell(c.get('detail'), 120)} "
              f"| {ev}{' — ' if ev else ''}`{c.get('evidence_path', '')}` |")
        a("")
        a("_All checks are read-only, single-attempt, 3 s timeout; no credentials were "
          "guessed and no write commands were sent._")
    else:
        a("_No service checks ran: no open port runs a service with a protocol check (HTTP ports are covered by the web targets), or the step budget ran out._")
    a("")
    return lines


def local_section(audit: dict | None, h: str = "##") -> list[str]:
    if not audit:
        return []
    findings = audit.get("findings") or []
    lines = [f"{h} Local audit", ""]
    a = lines.append
    st = audit.get("stats") or {}
    a(f"- Listening sockets: {st.get('listeners', 0)} · SUID binaries: {st.get('suid', '?')} "
      f"· SGID: {st.get('sgid', '?')} · accounts: {st.get('accounts', '?')} "
      f"· sshd config source: {st.get('sshd_source', '-')}")
    a("")
    if findings:
        a("| ID | Severity | Finding | Evidence | Fix |")
        a("|----|----------|---------|----------|-----|")
        for f in findings:
            a(f"| {f['id']} | {f['severity']} | {_cell(f['title'], 90)} "
              f"| {_cell(f['evidence'], 120)} | {_cell(f['fix'], 120)} |")
    else:
        a("_No local findings._")
    a("")
    listeners = audit.get("listeners") or []
    if listeners:
        a("<details><summary>Listening sockets</summary>")
        a("")
        a("| Proto | Address | Port | Process |")
        a("|-------|---------|-----:|---------|")
        for l in listeners:
            a(f"| {l['proto']} | {l['address']} | {l['port']} "
              f"| {l.get('process') or '-'}{' (' + str(l['pid']) + ')' if l.get('pid') else ''} |")
        a("")
        a("</details>")
        a("")
    for n in audit.get("notes") or []:
        a(f"- Note: {n}")
    if audit.get("notes"):
        a("")
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
        a(f"## Target: {t.url}" + (" (host)" if getattr(t, "kind", "web") == "host" else ""))
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
        lines += _host_section(st, "###")
        lines += _findings_section(findings, "###")
        lines += _research_section(st, "###")
        lines += _decision_log_section(st, "###")
        lines += _tried_section(st, "###")
        lines += _notes_section(st, "###")

    local_audit = None
    lp = job_dir / "local.json"
    if lp.exists():
        try:
            import json
            local_audit = json.loads(lp.read_text())
        except (OSError, ValueError):
            local_audit = None
    lines += local_section(local_audit)

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
        rec = _rec(f["vector"])
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
    svc_findings = [f for f in all_findings if f.get("source") == "service"]
    hosts = [t for t in job.targets if getattr(t, "kind", "web") == "host"]
    if hosts or local_audit is not None:
        open_ports = sum(len((st.host.get("profile") or {}).get("open_ports") or [])
                         for st in states.values() if st.host)
        a(f"- Hosts discovered: {len(hosts)} · open ports: {open_ports} · "
          f"web targets: {len(job.targets) - len(hosts)}")
        a(f"- Service findings: {len(svc_findings)} · web findings: "
          f"{len(all_findings) - len(svc_findings)}"
          + (f" · local findings: {len(local_audit.get('findings') or [])}"
             if local_audit is not None else ""))
    a(f"- LLM usage: {c.get('llm_calls', 0)} calls, ~{c.get('llm_tokens', 0)} tokens"
      + (f" / budget {job.budget['max_tokens']}" if job.budget.get("max_tokens") else ""))
    a(f"- Blocked by scope: {len(job.blocked)}")
    if (job.engine.get("research") or {}).get("enabled"):
        rs = [research_stats(st) for st in states.values()]
        a(f"- Research: {sum(r['found'] for r in rs)} CVEs found, "
          f"{sum(r['applicable'] for r in rs)} applicable, {sum(r['tested'] for r in rs)} tested, "
          f"{sum(r['verified'] for r in rs)} verified · "
          f"{c.get('research_requests', 0)} intel requests")
    a("")

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".md.tmp")
    tmp.write_text("\n".join(lines))
    tmp.replace(out)
    return out
