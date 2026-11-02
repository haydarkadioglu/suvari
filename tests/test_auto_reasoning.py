"""Tests for CVE applicability reasoning and the research-driven loop. No network."""

import json
from pathlib import Path
from urllib.parse import urlparse

from suvari.auto import reasoning as RS
from suvari.auto import research as R
from suvari.auto.executor import ExecResult
from suvari.auto.loop import AutoLoop
from suvari.auto.planner import Planner
from suvari.auto.report import write_report, research_stats
from suvari.auto.state import ScanState
from suvari.auto.tech_vectors import detect_versions

FIX = Path(__file__).parent / "fixtures"
BASE = "http://127.0.0.1:9999/"


def _cves():
    cves = R.parse_nvd(json.loads((FIX / "nvd_sample.json").read_text()))
    R.mark_kev(cves, R.index_kev(json.loads((FIX / "kev_sample.json").read_text())))
    return {c["id"]: c for c in cves}


def _res(url=BASE, status=200, headers=None, body=""):
    return ExecResult("curl", [url], ok=True, url=url, status=status,
                      headers=headers or {}, body=body)


HOME = _res(headers={"x-powered-by": "Next.js", "vary": "rsc, next-router-state-tree"},
            body='<img srcset="/_next/image?url=%2Fa.png&w=64&q=75">')


def _ev(version=None, responses=(HOME,)):
    return RS.build_evidence("nextjs", version, list(responses), {"nextjs"}, BASE)


# ── versions ─────────────────────────────────────────────────────────────
def test_in_range_bounds():
    r = {"start_incl": "15.0.0", "end_excl": "15.2.3"}
    assert RS.in_range("15.1.0", r) and RS.in_range("15.0.0", r)
    assert not RS.in_range("15.2.3", r) and not RS.in_range("14.9.9", r)
    assert RS.in_range("15.1", r)                       # padded
    assert RS.in_range("15.1.0-canary.4", r)            # pre-release core
    assert RS.in_range("1.2.3", {"exact": "1.2.3"})
    assert not RS.in_range("", r)


def test_detect_versions_from_banners():
    v = detect_versions([_res(headers={"server": "nginx/1.24.0",
                                       "x-powered-by": "PHP/8.1.2"}),
                         _res(body='<meta name="generator" content="WordPress 6.4.2" />')])
    assert v == {"nginx": "1.24.0", "php": "8.1.2", "wordpress": "6.4.2"}
    assert detect_versions([HOME]) == {}                 # bare "Next.js" -> unknown


# ── applicability ─────────────────────────────────────────────────────────
def test_version_mismatch_scores_low():
    c = _cves()["CVE-2025-55182"]                         # KEV, CVSS 10 — still capped
    a = RS.applicability(c, _ev("16.3.0"))
    assert a["score"] <= RS.VERSION_MISMATCH_CAP
    assert a["why"].startswith("not applicable")
    assert any(x["check"] == "version" and x["result"] == "fail" for x in a["checks"])


def test_kev_and_high_cvss_score_high():
    c = _cves()["CVE-2025-55182"]
    a = RS.applicability(c, _ev())                        # version unknown
    assert a["score"] >= 0.7
    names = {x["check"]: x for x in a["checks"]}
    assert names["kev"]["delta"] == RS.W_KEV and names["cvss"]["delta"] == RS.W_CVSS_HIGH
    assert "KEV" in a["why"]
    # in range on top of that -> near certain
    assert RS.applicability(c, _ev("15.1.0"))["score"] > a["score"]


def test_other_product_keyword_hit_scores_low():
    a = RS.applicability(_cves()["CVE-2021-21310"], _ev())   # next-auth, not next.js
    assert a["score"] < RS.APPLICABLE_THRESHOLD
    assert "different product" in a["why"]


def test_observed_component_raises_score():
    c = _cves()["CVE-2025-55173"]                        # image optimizer
    seen = RS.applicability(c, _ev())
    unseen = RS.applicability(c, _ev(responses=[_res(headers={"x-powered-by": "Next.js"})]))
    assert seen["score"] > unseen["score"]
    assert "image-optimizer" in seen["why"]


def test_auth_required_lowers_score():
    c = dict(_cves()["CVE-2025-29927"])
    base = RS.applicability(c, _ev())["score"]
    c["privileges_required"] = "HIGH"
    assert RS.applicability(c, _ev())["score"] < base


def test_score_bounds():
    for c in _cves().values():
        for v in (None, "15.1.0", "9.0.0"):
            s = RS.applicability(c, _ev(v))["score"]
            assert 0.0 < s < 1.0


# ── harmless test planning ──────────────────────────────────────────────
_UNSAFE = ("'", '"', "<", ">", ";", "|", "`", "$", "..", "%", "?", "&", " ")


def test_plan_tests_only_produces_harmless_gets():
    for c in _cves().values():
        for v in (None, "15.1.0"):
            probes = RS.plan_tests(c, _ev(v), BASE)
            assert probes, c["id"]
            assert probes[-1]["kind"] == "version-fingerprint"
            for p in probes:
                assert p["method"] == "GET"
                assert p["kind"] in RS.PROBE_KINDS
                assert RS.is_safe_probe(p, BASE)
                u = urlparse(p["url"])
                assert u.netloc == urlparse(BASE).netloc
                assert not any(ch in u.path for ch in _UNSAFE), p["url"]
                assert "payload" not in p and "data" not in p and "headers" not in p


def test_plan_tests_rejects_hostile_paths_from_cve_text():
    c = {"id": "CVE-X", "summary": "RCE via /../../etc/passwd.conf and "
         "/cgi-bin/x.php?cmd=id and http://evil.example/x.php and /admin/setup.php",
         "cwes": ["CWE-79"], "ranges": []}
    probes = RS.plan_tests(c, {"tech": "php"}, BASE)
    urls = [p["url"] for p in probes]
    assert all(urlparse(u).netloc == "127.0.0.1:9999" for u in urls)
    assert not any(".." in u or "cmd=" in u or "passwd" in u for u in urls)
    kinds = {p["kind"] for p in probes}
    assert kinds == {"exposed-file", "security-header", "version-fingerprint"}


def test_plan_tests_component_probe_for_image_optimizer():
    probes = RS.plan_tests(_cves()["CVE-2025-55173"], _ev(), BASE)
    assert probes[0]["kind"] == "feature-endpoint"
    assert probes[0]["url"] == BASE + "_next/image"
    # version unknown -> read the error page, not the homepage
    assert probes[-1]["url"].endswith(RS.ERROR_PROBE_PATH)


def test_is_safe_probe_rejects_non_get_query_and_offsite():
    ok = {"kind": "exposed-file", "method": "GET", "url": BASE + "a.php"}
    assert RS.is_safe_probe(ok, BASE)
    assert not RS.is_safe_probe({**ok, "method": "POST"}, BASE)
    assert not RS.is_safe_probe({**ok, "url": BASE + "a.php?x=1"}, BASE)
    assert not RS.is_safe_probe({**ok, "url": "http://other.test/a.php"}, BASE)
    assert not RS.is_safe_probe({**ok, "kind": "exploit"}, BASE)


# ── probe evaluation ────────────────────────────────────────────────────
def _vmeta(version=None):
    cves = _cves()
    return {"source": "research", "kind": "version-fingerprint", "tech": "nextjs",
            "known_version": version,
            "cves": [{"id": i, "cvss": cves[i]["cvss"], "severity": cves[i]["severity"],
                      "kev": cves[i]["exploited_in_wild"],
                      "ranges": RS.product_ranges(cves[i], "nextjs")}
                     for i in ("CVE-2025-29927", "CVE-2025-55182")]}


def test_evaluate_version_fingerprint_verified_and_ruled_out():
    out = RS.evaluate_probe(_vmeta(), _res(headers={"x-powered-by": "Next.js 15.1.0"}))
    assert out["positive"] and set(out["verified_cves"]) == {"CVE-2025-29927", "CVE-2025-55182"}
    assert out["severity"] == "CRITICAL"
    out = RS.evaluate_probe(_vmeta(), _res(headers={"x-powered-by": "Next.js 16.3.0"}))
    assert not out["positive"] and not out["inconclusive"] and "not affected" in out["detail"]


def test_evaluate_version_unknown_is_inconclusive():
    out = RS.evaluate_probe(_vmeta(), _res(status=404, body="Not found"))
    assert out["inconclusive"] and out["lr"] == 1.0 and not out["positive"]


def test_evaluate_feature_endpoint():
    meta = {"kind": "feature-endpoint", "feature": "image-optimizer",
            "expect": [200, 400], "cve": "CVE-2025-55173"}
    assert RS.evaluate_probe(meta, _res(status=400))["positive"]
    assert not RS.evaluate_probe(meta, _res(status=404))["positive"]


def test_llm_context_mentions_candidates_and_safety():
    rs = {"techs": [{"tech": "nextjs", "version": None, "returned": 5}],
          "candidates": [{"cve": "CVE-2025-55182", "cvss": 10.0, "kev": True, "score": 0.9,
                          "why": "listed in CISA KEV", "hypotheses": ["H030"],
                          "tests": [{"kind": "version-fingerprint", "url": BASE + "x"}]}]}
    text = RS.llm_context(rs)
    assert "CVE-2025-55182 (CVSS 10.0, KEV) score=0.90" in text
    assert "no exploitation" in text
    assert RS.llm_context({}) == ""


# ── loop integration (fake researcher + fake executor) ─────────────────────
class FakeResearcher:
    def __init__(self, version=None):
        self.calls = []
        self.requests_made = 0

    def research(self, tech, version=None):
        self.calls.append((tech, version))
        cves = list(_cves().values()) if tech == "nextjs" else []
        return R.ResearchResult(tech, version, cves=cves, total_found=len(cves),
                                query="virtualMatchString=cpe:2.3:a:*:next.js:*")


class FakeExecutor:
    """Serves canned responses; records every URL actually requested."""

    def __init__(self, routes):
        self.routes = routes
        self.allowed_hosts = {"127.0.0.1:9999"}
        self.sent = []

    def http_probe(self, url, timeout=None):
        self.sent.append(url)
        r = self.routes.get(url) or _res(url, status=404, body="Not Found")
        return ExecResult("curl", ["-s", url], ok=True, url=url, status=r.status,
                          headers=r.headers, body=r.body)


def _run(tmp_path, routes, researcher, max_steps=60):
    state = ScanState(tmp_path, BASE, ["127.0.0.1:9999"])
    planner = Planner(BASE, dry_run=True, researcher=researcher)
    ex = FakeExecutor(routes)
    result = AutoLoop(state, planner, ex, max_steps=max_steps).run()
    return state, ex, result


def test_loop_seeds_scored_cve_hypotheses_and_reports(tmp_path):
    routes = {BASE: HOME, BASE + "_next/image": _res(status=400, body='"url" parameter is required')}
    fr = FakeResearcher()
    state, ex, result = _run(tmp_path, routes, fr)

    assert fr.calls == [("nextjs", None)]
    res_h = [h for h in state.hypotheses.values() if h.meta.get("source") == "research"]
    assert res_h
    cands = {c["cve"]: c for c in state.research["candidates"]}
    kev = cands["CVE-2025-55182"]
    # prior == applicability score
    vh = next(h for h in res_h if h.meta["kind"] == "version-fingerprint")
    assert vh.prior == max(c["score"] for c in cands.values())
    assert cands["CVE-2021-21310"]["hypotheses"] == []          # other product: not seeded
    # version unknown -> inconclusive, not refuted
    assert vh.status == "exhausted"
    assert any(r["inconclusive"] for r in kev["results"])
    # image optimizer surface confirmed for its CVE
    assert any(r["positive"] and r["kind"] == "feature-endpoint"
               for r in cands["CVE-2025-55173"]["results"])
    # each research URL is requested once and shared by every CVE it covers
    assert ex.sent.count(BASE + RS.ERROR_PROBE_PATH) == 1
    assert ex.sent.count(BASE + "_next/image") == 1
    # evidence tagged as research
    ev = json.loads((tmp_path / "auto" / "evidence" / f"{vh.evidence[0]}.json").read_text())
    assert ev["extra"]["source"] == "research" and "CVE-2025-55182" in ev["extra"]["cves"]
    assert any(d.get("origin") == "research" for d in state.decision_log)

    report = write_report(state, result).read_text()
    assert "## Research" in report
    assert "**CVE-2025-55182** (CVSS 10.0, KEV)" in report
    assert "→ tested:" in report
    st = research_stats(state)
    assert st["found"] == 5 and st["tested"] >= 2 and st["verified"] == 0


def test_loop_verifies_cve_when_version_in_range(tmp_path):
    home = _res(headers={"x-powered-by": "Next.js 15.1.0"}, body='<script src="/_next/static/x.js">')
    state, ex, result = _run(tmp_path, {BASE: home}, FakeResearcher())
    vf = [f for f in state.findings if f.get("source") == "research"]
    ids = {f["cve"] for f in vf}
    assert {"CVE-2025-29927", "CVE-2025-55182"} <= ids
    assert all(f["vector"] == "cve-version-check" for f in vf)
    assert research_stats(state)["verified"] >= 2
    assert "VERIFIED" in write_report(state, result).read_text()


def test_research_state_survives_save_and_load(tmp_path):
    state, _, _ = _run(tmp_path, {BASE: HOME}, FakeResearcher(), max_steps=1)
    loaded = ScanState.load(tmp_path)
    assert loaded.research == state.research
    h = next(h for h in loaded.hypotheses.values() if h.meta.get("source") == "research")
    assert h.meta["tech"] == "nextjs"


def test_planner_without_researcher_has_no_research(tmp_path):
    state, _, _ = _run(tmp_path, {BASE: HOME}, None, max_steps=1)
    assert state.research == {}
    assert not any(h.meta for h in state.hypotheses.values())
