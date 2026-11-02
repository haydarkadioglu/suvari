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
