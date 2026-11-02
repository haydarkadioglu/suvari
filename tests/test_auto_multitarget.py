"""Two fixture servers (127.0.0.1:8097 and :8098) scanned as one job.

Loopback only. Also drives the real CLI in a subprocess to prove SIGINT pauses
a job and ``--resume <job_id>`` finishes it, and that the legacy single-URL
form still works.
"""

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from suvari.auto.jobs import JobManager, JobRunner

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")

PORTS = (8097, 8098)
REPO = Path(__file__).resolve().parent.parent
SUVARI = REPO / "suvari.py"


def _no_dns(host):
    raise AssertionError(f"DNS must not be queried for {host!r}")


def _port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


@pytest.fixture()
def two_servers(make_server):
    if not all(_port_free(p) for p in PORTS):
        pytest.skip(f"ports {PORTS} are in use")
    return [make_server(p) for p in PORTS]


class FakeLLM:
    """Steers the planner and keeps proposing an out-of-scope canary target."""

    def __init__(self, canary_url: str):
        self.canary = canary_url
        self.prompts = []

    def chat(self, messages, **kw):
        prompt = messages[-1]["content"]
        self.prompts.append(prompt)
        ids = re.findall(r"^\s+(H\d+):", prompt, re.M)
        return json.dumps({
            "hypotheses": [{"title": "Canary git", "vector": "git-exposure",
                            "target": self.canary + "/.git/config", "prior": 0.9,
                            "rationale": "try another host"}],
            "next_action": {"hypothesis_id": ids[0] if ids else "H001",
                            "tool": "curl", "args": [], "why": "fake pick"},
        })


def test_two_targets_separate_evidence_and_two_report_sections(tmp_path, two_servers, make_server):
    (srv_a, a), (srv_b, b) = two_servers
    canary, canary_url = make_server()
    mgr = JobManager(tmp_path)
    job = mgr.create([a, b], concurrency=2, rate_per_min=6000, duration=120,
                     resolver=_no_dns)
    llm = FakeLLM(canary_url)
    result = JobRunner(job, mgr, llm=llm, resolver=_no_dns, handle_signals=False).run()
    assert result["status"] == "done"
    jdir = tmp_path / job.id

    # evidence lives in one directory per target and only ever hit that target
    for port, srv in zip(PORTS, (srv_a, srv_b)):
        ev_dir = jdir / "evidence" / f"127.0.0.1_{port}"
        files = sorted(ev_dir.glob("E*.json"))
        assert files, f"no evidence for :{port}"
        assert (ev_dir / "evidence.md").exists()
        for f in files:
            url = json.loads(f.read_text())["request"]["url"]
            assert url.startswith(f"http://127.0.0.1:{port}/"), url
        assert srv.hits
        st = json.loads((jdir / "targets" / f"127.0.0.1_{port}.state.json").read_text())
        # no finding leakage between targets
        assert st["findings"]
        assert all(f["target"].startswith(f"http://127.0.0.1:{port}/") for f in st["findings"])
        assert all(f["evidence"].startswith(f"evidence/127.0.0.1_{port}/") for f in st["findings"])

    # the out-of-scope canary was proposed but never contacted
    assert llm.prompts
    assert canary.hits == []
    assert any(canary_url in bl["target"] for bl in result_blocked(mgr, job.id))

    body = Path(result["report"]).read_text()
    assert "Report status: FINAL" in body
    assert body.count("\n## Target: ") == 2
    assert f"## Target: {a}/" in body and f"## Target: {b}/" in body
    assert body.count("### Decision log") == 2
    assert "## Blocked by scope" in body and canary_url in body
    summary = body.split("## Summary")[1]
    assert "Targets: 2" in summary and "LLM usage:" in summary
    assert result["counters"]["llm_calls"] > 0 and result["counters"]["llm_tokens"] > 0


def result_blocked(mgr, job_id):
    return mgr.load(job_id).blocked


# ── real CLI ─────────────────────────────────────────────────────────────

def _cli(args, cwd, **kw):
    return subprocess.run([sys.executable, str(SUVARI), *args], cwd=cwd,
                          capture_output=True, text=True, timeout=120, **kw)


def test_cli_sigint_pauses_and_resume_finishes(tmp_path, two_servers):
    (_, a), (_, b) = two_servers
    jobs_dir = tmp_path / "jobs"
    env = dict(os.environ, COLUMNS="200")
    proc = subprocess.Popen(
        [sys.executable, str(SUVARI), "auto", "--target", a, "--target", b,
         "--dry-run", "--concurrency", "2", "--rate", "20", "--duration", "5m",
         "--jobs-dir", str(jobs_dir)],
        cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        deadline = time.time() + 60
        cp = None
        while time.time() < deadline:
            cps = list(jobs_dir.glob("*/checkpoint.json"))
            if cps:
                cp = cps[0]
                try:
                    if json.loads(cp.read_text())["counters"]["turns"] >= 1:
                        break
                except (ValueError, KeyError):
                    pass
            time.sleep(0.2)
        assert cp is not None, "job never started"
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()

    job_id = cp.parent.name
    data = json.loads(cp.read_text())
    assert data["status"] == "paused", out
    assert f"--resume {job_id}" in out
    turns_before = data["counters"]["turns"]
    assert 1 <= turns_before < 12

    res = _cli(["auto", "--resume", job_id, "--rate", "6000",
                "--jobs-dir", str(jobs_dir)], tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    data = json.loads(cp.read_text())
    assert data["status"] == "done"
    assert data["counters"]["runs"] == 2
    assert data["counters"]["turns"] > turns_before
    assert all(t["status"] == "done" for t in data["targets"])

    listing = _cli(["auto", "--jobs", "--jobs-dir", str(jobs_dir)], tmp_path, env=env)
    assert job_id in listing.stdout and "done" in listing.stdout


def test_cli_legacy_single_url_is_a_one_target_job(tmp_path, vuln_server):
    jobs_dir = tmp_path / "jobs"
    env = dict(os.environ, COLUMNS="200")
    res = _cli(["auto", vuln_server, "--max-steps", "3", "--dry-run", "--rate", "6000",
                "--jobs-dir", str(jobs_dir)], tmp_path, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    [cp] = jobs_dir.glob("*/checkpoint.json")
    data = json.loads(cp.read_text())
    assert len(data["targets"]) == 1
    assert data["targets"][0]["turns"] == 3
    assert data["status"] == "done"


def test_cli_legacy_output_mode_unchanged(tmp_path, vuln_server):
    out_dir = tmp_path / "ws"
    res = _cli(["auto", vuln_server, "--max-steps", "2", "--dry-run", "--rate", "6000",
                "--output", str(out_dir)], tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert (out_dir / "auto" / "state.json").exists()
    # legacy bare --resume flag still continues the same workspace
    res = _cli(["auto", vuln_server, "--max-steps", "4", "--dry-run", "--rate", "6000",
                "--resume", "--output", str(out_dir)], tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    st = json.loads((out_dir / "auto" / "state.json").read_text())
    assert st["turn"] == 4


def test_cli_refuses_large_scope_without_flag(tmp_path):
    res = _cli(["auto", "--target", "10.0.0.0/16", "--dry-run",
                "--jobs-dir", str(tmp_path / "jobs")], tmp_path)
    assert res.returncode == 2
    assert "allow-large-scope" in res.stdout
    assert not list((tmp_path / "jobs").glob("*")) if (tmp_path / "jobs").exists() else True
