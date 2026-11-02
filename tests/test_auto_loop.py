"""Integration tests for the autonomous loop against the local vuln server.

No real network: the fixture binds 127.0.0.1 only and curl talks to it.
"""

import json
import shutil
from pathlib import Path

import pytest

from suvari.auto.executor import Executor
from suvari.auto.session import run_auto
from suvari.auto.state import ScanState

pytestmark = pytest.mark.skipif(
    shutil.which("curl") is None, reason="curl not installed"
)


def _run(url, root, **kw):
    kw.setdefault("max_steps", 25)
    return run_auto(url, root, dry_run=True, time_budget=60,
                    rate_per_min=600, **kw)


def test_dry_run_finds_at_least_three(vuln_server, tmp_path):
    result = _run(vuln_server, tmp_path)
    findings = result["findings"]
    vectors = {f["vector"] for f in findings}
    assert len(findings) >= 3, f"expected >=3 findings, got {findings}"
    # the fixture's planted issues should surface
    assert "git-exposure" in vectors
    assert "missing-security-headers" in vectors
    # at least one of the medium findings
    assert vectors & {"admin-auth-bypass", "dir-listing"}


def test_dry_run_writes_state_evidence_and_report(vuln_server, tmp_path):
    result = _run(vuln_server, tmp_path)

    state_file = tmp_path / "auto" / "state.json"
    assert state_file.exists()
    data = json.loads(state_file.read_text())
    assert data["target"] == vuln_server
    assert data["decision_log"], "decision log must not be empty"

    ev_dir = tmp_path / "auto" / "evidence"
    ev_files = list(ev_dir.glob("E*.json"))
    assert ev_files, "evidence files must be written"
    sample = json.loads(ev_files[0].read_text())
    for key in ("request", "response", "duration", "failure_level"):
        assert key in sample
    assert (tmp_path / "auto" / "evidence.md").exists()

    report = Path(result["report"])
    assert report.exists()
    body = report.read_text()
    assert "Decision log" in body
    assert "Findings" in body


def test_decision_log_captures_reasoning(vuln_server, tmp_path):
    result = _run(vuln_server, tmp_path)
    log = ScanState.load(tmp_path).decision_log
    assert log
    entry = log[0]
    for key in ("turn", "hypothesis", "prior", "posterior_before",
                "posterior_after", "action", "rationale", "result_class"):
        assert key in entry
    # a positive git-exposure test should show the posterior rising
    git = [d for d in log if d["vector"] == "git-exposure"]
    assert git and git[0]["posterior_after"] > git[0]["posterior_before"]


def test_robots_spawns_and_confirms_internal_path(vuln_server, tmp_path):
    _run(vuln_server, tmp_path)
    st = ScanState.load(tmp_path)
    # a path-probe child for /internal/ should have been created and confirmed
    internal = [h for h in st.hypotheses.values()
                if h.vector == "path-probe" and h.target.endswith("/internal/")]
    assert internal, "robots.txt disclosure should spawn an /internal/ probe"


def test_no_duplicate_actions(vuln_server, tmp_path):
    _run(vuln_server, tmp_path)
    st = ScanState.load(tmp_path)
    assert len(st.tried_actions) == len(set(st.tried_actions))


def test_resume_does_not_restart(vuln_server, tmp_path):
    first = _run(vuln_server, tmp_path, max_steps=2)
    assert first["turns"] == 2
    st = ScanState.load(tmp_path)
    tried_after_first = list(st.tried_actions)
    # resume with a larger budget continues rather than restarting
    second = run_auto(vuln_server, tmp_path, dry_run=True, max_steps=25,
                      time_budget=60, rate_per_min=600, resume=True)
    st2 = ScanState.load(tmp_path)
    assert st2.turn > first["turns"]
    # earlier actions are preserved, not repeated
    assert tried_after_first == st2.tried_actions[:len(tried_after_first)]


def test_out_of_scope_probe_is_refused():
    ex = Executor(["127.0.0.1:9999"], rate_per_min=600)
    res = ex.http_probe("http://evil.example.com/")
    assert res.ok is False
    assert "out-of-scope" in res.error


def test_budget_stops_the_loop(vuln_server, tmp_path):
    result = run_auto(vuln_server, tmp_path, dry_run=True, max_steps=1,
                      time_budget=60, rate_per_min=600)
    assert result["turns"] == 1
    assert "max-steps" in result["stop_reason"]
