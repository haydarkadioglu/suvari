"""Job model, checkpointing, crash/resume and budgets — loopback fixtures only."""

import json
import shutil
from pathlib import Path

import pytest

from suvari.auto.jobs import (
    DONE, FAILED, PAUSED, RUNNING, Job, JobManager, JobRunner, parse_duration,
)
from suvari.auto.state import ScanState

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")


def _no_dns(host):
    raise AssertionError(f"DNS must not be queried for {host!r}")


def _create(mgr, urls, **kw):
    kw.setdefault("dry_run", True)
    kw.setdefault("rate_per_min", 6000)
    kw.setdefault("duration", 60)
    return mgr.create(urls, resolver=_no_dns, **kw)


def _runner(job, mgr, **kw):
    kw.setdefault("handle_signals", False)
    return JobRunner(job, mgr, resolver=_no_dns, **kw)


class Crash(Exception):
    """Stands in for the process dying (kill -9)."""


def test_parse_duration():
    assert parse_duration("90") == 90
    assert parse_duration("30m") == 1800
    assert parse_duration("2h") == 7200
    assert parse_duration("1h30m") == 5400
    assert parse_duration(None) is None
    for bad in ("2x", "h", "1h junk"):
        with pytest.raises(ValueError):
            parse_duration(bad)


def test_create_writes_checkpoint(tmp_path, make_server):
    _, a = make_server()
    _, b = make_server()
    mgr = JobManager(tmp_path)
    job = _create(mgr, [a, b], concurrency=2, max_requests=500)
    cp = tmp_path / job.id / "checkpoint.json"
    data = json.loads(cp.read_text())
    assert data["status"] == "queued"
    assert data["checkpoint"] == "checkpoint.json"
    assert [t["url"] for t in data["targets"]] == [a + "/", b + "/"]
    assert data["budget"]["concurrency"] == 2
    assert data["budget"]["max_requests"] == 500
    assert {"requests", "turns", "findings", "elapsed"} <= set(data["counters"])
    again = mgr.load(job.id)
    assert isinstance(again, Job) and again.targets[1].url == b + "/"


def test_invalid_job_id_rejected(tmp_path):
    mgr = JobManager(tmp_path)
    for bad in ("../etc", "a/b", ""):
        with pytest.raises(ValueError):
            mgr.job_dir(bad)


def test_crash_then_resume_continues_from_remaining_target(tmp_path, make_server):
    srv_a, a = make_server()
    srv_b, b = make_server()
    live = tmp_path / "live"
    crashed = tmp_path / "crashed"
    mgr = JobManager(live)
    job = _create(mgr, [a, b], concurrency=1)

    def die_mid_second_target(runner, t):
        # target A finished, target B has done two turns -> the process "dies".
        if t.url == b + "/" and t.turns == 2:
            # what is on disk at this instant is exactly what kill -9 leaves
            shutil.copytree(live, crashed)
            raise Crash()

    _runner(job, mgr, on_turn=die_mid_second_target).run()

    # ---- new process: fresh manager over the on-disk state ----
    mgr2 = JobManager(crashed)
    job2 = mgr2.load(job.id)
    assert job2.status == RUNNING                         # died while running
    ta, tb = job2.targets
    assert ta.status == "done" and tb.status == "running"
    assert tb.turns == 2 and tb.last_hypothesis
    jdir = crashed / job.id
    st_a_before = json.loads((jdir / ta.state_rel).read_text())
    st_b_before = ScanState.load(jdir, state_file=jdir / tb.state_rel)
    assert st_b_before.turn == 2
    hits_a_before = len(srv_a.hits)
    hits_b_before = len(srv_b.hits)

    result = _runner(job2, mgr2).run()

    assert result["status"] == DONE
    # A was not touched again: no new requests, state file unchanged
    assert len(srv_a.hits) == hits_a_before
    assert json.loads((jdir / ta.state_rel).read_text())["decision_log"] == \
        st_a_before["decision_log"]
    # B resumed at turn 3 — earlier turns/actions preserved, never repeated
    st_b = ScanState.load(jdir, state_file=jdir / tb.state_rel)
    assert st_b.turn > 2
    assert st_b.decision_log[:2] == st_b_before.decision_log
    assert st_b.decision_log[2]["turn"] == 3
    assert st_b.tried_actions[:2] == st_b_before.tried_actions
    assert len(st_b.tried_actions) == len(set(st_b.tried_actions))
    # no reachability re-check on resume: only probe GETs reached B
    assert len(srv_b.hits) - hits_b_before == st_b.turn - 2
    # both runs recorded; final report written
    job_final = mgr2.load(job.id)
    assert job_final.counters["runs"] == 2
    body = (jdir / job_final.report).read_text()
    assert "Report status: FINAL" in body


def test_interrupt_pauses_then_resume_finishes(tmp_path, make_server):
    _, a = make_server()
    _, b = make_server()
    mgr = JobManager(tmp_path)
    job = _create(mgr, [a, b], concurrency=2)

    def stop_after_first_turn(runner, t):
        runner.request_stop()  # what the SIGINT handler does

    r1 = _runner(job, mgr, on_turn=stop_after_first_turn).run()
    assert r1["status"] == PAUSED
    assert r1["stop_reason"] == "interrupted"
    saved = mgr.load(job.id)
    assert saved.status == PAUSED
    assert all(t.status in ("paused", "pending") for t in saved.targets)
    report = (tmp_path / job.id / saved.report).read_text()
    assert "INTERIM" in report
    assert mgr.latest_resumable().id == job.id

    r2 = _runner(saved, mgr).run()
    assert r2["status"] == DONE
    assert all(t["status"] == "done" for t in r2["targets"])
    assert mgr.latest_resumable() is None
    with pytest.raises(RuntimeError, match="already done"):
        _runner(mgr.load(job.id), mgr).run()


def test_duration_budget_ends_job_done_with_report(tmp_path, make_server):
    _, a = make_server()
    _, b = make_server()
    mgr = JobManager(tmp_path)
    job = _create(mgr, [a, b], duration=30, concurrency=1)

    t = [0.0]

    def clock():  # every look at the clock costs 10 virtual seconds
        t[0] += 10.0
        return t[0]

    result = _runner(job, mgr, clock=clock).run()
    assert result["status"] == DONE
    assert "duration budget reached" in result["stop_reason"]
    assert "not completed" in result["stop_reason"]
    assert result["counters"]["elapsed"] >= 30
    statuses = [x["status"] for x in result["targets"]]
    assert statuses != ["done", "done"]
    body = Path(result["report"]).read_text()
    assert "Report status: FINAL" in body
    assert "duration budget reached" in body
    assert "## Summary" in body


def test_max_requests_budget_is_hard(tmp_path, make_server):
    srv_a, a = make_server()
    srv_b, b = make_server()
    mgr = JobManager(tmp_path)
    job = _create(mgr, [a, b], max_requests=4, concurrency=2)
    result = _runner(job, mgr).run()
    assert result["status"] == DONE
    assert "max-requests reached (4)" in result["stop_reason"]
    assert result["counters"]["requests"] == 4
    # a reachability connect sends no HTTP request, so hits <= budget
    assert len(srv_a.hits) + len(srv_b.hits) <= 4
    # a probe refused by the budget is rolled back, not burned: every tried
    # action has a real evidence-backed decision, so resume can retry it
    jdir = tmp_path / job.id
    for t in mgr.load(job.id).targets:
        sf = jdir / t.state_rel
        if sf.exists():
            st = ScanState.load(jdir, state_file=sf)
            assert len(st.tried_actions) == st.turn
            assert all(d["evidence"] for d in st.decision_log)
            assert sum(h.attempts for h in st.hypotheses.values()) == st.turn


def test_unreachable_target_is_skipped_quickly(tmp_path, make_server):
    _, a = make_server()
    mgr = JobManager(tmp_path)
    job = _create(mgr, [a, "127.0.0.1:1"])
    result = _runner(job, mgr).run()
    by_url = {t["url"]: t for t in result["targets"]}
    assert by_url["http://127.0.0.1:1/"]["status"] == "unreachable"
    assert by_url[a + "/"]["status"] == "done"
    assert result["status"] == DONE


def test_target_outside_scope_file_is_blocked_and_never_contacted(tmp_path, make_server):
    srv_a, a = make_server()
    srv_b, b = make_server()
    mgr = JobManager(tmp_path)
    job = _create(mgr, [a, b], scope_specs=[a])   # explicit scope: only A
    assert job.targets[1].status == "blocked"
    result = _runner(job, mgr).run()
    assert srv_b.hits == []
    assert srv_a.hits
    body = Path(result["report"]).read_text()
    assert "## Blocked by scope" in body
    assert b + "/" in body.split("## Blocked by scope")[1]


def test_failed_status_on_unexpected_runner_error(tmp_path, make_server, monkeypatch):
    _, a = make_server()
    mgr = JobManager(tmp_path)
    job = _create(mgr, [a])
    runner = _runner(job, mgr)

    def boom():
        raise OSError("disk gone")

    monkeypatch.setattr(runner, "_run_targets", boom)
    with pytest.raises(OSError):
        runner.run()
    assert mgr.load(job.id).status == FAILED
