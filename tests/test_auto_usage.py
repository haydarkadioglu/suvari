"""Tests for LLM token / cost accounting in the autonomous loop."""

import json
import shutil
from pathlib import Path

import pytest

from suvari.auto.executor import Executor
from suvari.auto.loop import AutoLoop
from suvari.auto.planner import Planner
from suvari.auto.report import write_report
from suvari.auto.state import ScanState
from suvari.auto.usage import (
    UsageRecord, UsageTracker, estimate_tokens, format_summary, human_tokens,
)

BASE = "http://127.0.0.1:9999"


# ── fake LLMs ─────────────────────────────────────────────────────────────
_PLAN_JSON = ('{"hypotheses": [], "next_action": {"hypothesis_id": "H999", '
              '"tool": "curl", "args": [], "why": "x"}}')


class UsageLLM:
    """Provider that returns an exact usage block (like OpenAI/Anthropic)."""
    model = "deepseek-chat"

    def __init__(self):
        self.last_usage = None
        self.calls = 0

    def chat(self, messages, temperature=0.1, max_tokens=900):
        self.calls += 1
        self.last_usage = {"prompt_tokens": 11, "completion_tokens": 7,
                           "total_tokens": 18}
        return _PLAN_JSON


class NoUsageLLM:
    """Provider that returns no usage block and an unpriced model name."""
    model = "mystery-local-model"

    def __init__(self):
        self.last_usage = None
        self.calls = 0

    def chat(self, messages, temperature=0.1, max_tokens=900):
        self.calls += 1
        self.last_usage = None
        return "y" * 20


# ── record / tracker / pricing ──────────────────────────────────────────
def test_estimate_tokens_char_over_four():
    assert estimate_tokens("x" * 40) == 10
    assert estimate_tokens("") == 0
    assert estimate_tokens("ab") == 1  # never zero for non-empty


def test_usage_record_cost_known_vs_unknown():
    known = UsageRecord("deepseek-chat", 1_000_000, 1_000_000, 0.0, False)
    assert known.cost_usd() == pytest.approx(0.27 + 1.10)
    unknown = UsageRecord("mystery-local-model", 100, 100, 0.0, True)
    assert unknown.cost_usd() is None


def test_tracker_totals_sum_and_flags():
    t = UsageTracker()
    t.add(UsageRecord("deepseek-chat", 100, 50, 0.1, False))
    t.add(UsageRecord("deepseek-chat", 200, 80, 0.2, True))
    tot = t.totals()
    assert tot["calls"] == 2
    assert tot["prompt_tokens"] == 300
    assert tot["completion_tokens"] == 130
    assert tot["total_tokens"] == 430
    assert tot["estimated_calls"] == 1
    assert tot["cost_known"] is True
    assert tot["cost_usd"] > 0


def test_tracker_cost_unknown_if_any_model_unpriced():
    t = UsageTracker()
    t.add(UsageRecord("deepseek-chat", 100, 50, 0.0, False))
    t.add(UsageRecord("mystery-local-model", 100, 50, 0.0, True))
    assert t.totals()["cost_known"] is False


def test_tracker_merge_totals_accumulates_across_resume():
    t = UsageTracker()
    t.merge_totals({"calls": 3, "prompt_tokens": 100, "completion_tokens": 40,
                    "estimated_calls": 1, "cost_usd": 0.01, "cost_known": True,
                    "models": ["deepseek-chat"]})
    t.add(UsageRecord("deepseek-chat", 10, 5, 0.0, False))
    tot = t.totals()
    assert tot["calls"] == 4
    assert tot["prompt_tokens"] == 110
    assert tot["completion_tokens"] == 45
    assert tot["estimated_calls"] == 1


# ── formatting ────────────────────────────────────────────────────────────
def test_human_tokens():
    assert human_tokens(980) == "980"
    assert human_tokens(12345) == "12.3k"


def test_format_summary_shapes():
    tot = {"calls": 7, "prompt_tokens": 12300, "completion_tokens": 2100,
           "total_tokens": 14400, "estimated_calls": 7, "cost_usd": 0.004,
           "cost_known": True}
    s = format_summary(tot)
    assert s == "LLM: 7 calls · 12.3k in / 2.1k out · ~$0.0040 (estimated)"
    # unknown-cost variant
    tot2 = dict(tot, cost_known=False, estimated_calls=0)
    assert "cost unknown" in format_summary(tot2)
    assert "(estimated)" not in format_summary(tot2)
    # no calls
    assert "0 calls" in format_summary({"calls": 0})


# ── planner-level accounting ────────────────────────────────────────────
def _state(tmp_path):
    return ScanState(tmp_path, BASE, ["127.0.0.1:9999"])


def test_planner_records_provider_usage():
    p = Planner(BASE, llm=UsageLLM(), dry_run=False)
    p._chat("some prompt text", max_tokens=100)
    tot = p.usage.totals()
    assert tot["calls"] == 1
    assert tot["estimated_calls"] == 0        # provider gave exact counts
    assert tot["prompt_tokens"] == 11
    assert tot["completion_tokens"] == 7
    assert tot["cost_known"] is True
    assert tot["cost_usd"] > 0


def test_planner_estimates_when_provider_gives_no_usage():
    p = Planner(BASE, llm=NoUsageLLM(), dry_run=False)
    p._chat("x" * 40)   # response is "y"*20
    tot = p.usage.totals()
    assert tot["calls"] == 1
    assert tot["estimated_calls"] == 1        # flagged as estimated
    assert tot["prompt_tokens"] == 10         # 40 chars / 4
    assert tot["completion_tokens"] == 5      # 20 chars / 4
    assert tot["cost_known"] is False         # unpriced model -> cost unknown


# ── state persistence ──────────────────────────────────────────────────────
def test_state_round_trips_usage(tmp_path):
    st = _state(tmp_path)
    st.usage = {"calls": 3, "prompt_tokens": 120, "completion_tokens": 30,
                "total_tokens": 150, "estimated_calls": 1, "cost_usd": 0.002,
                "cost_known": True, "models": ["deepseek-chat"]}
    st.save()
    loaded = ScanState.load(tmp_path)
    assert loaded.usage["calls"] == 3
    assert loaded.usage["total_tokens"] == 150
    raw = json.loads((tmp_path / "auto" / "state.json").read_text())
    assert raw["usage"]["prompt_tokens"] == 120


# ── report rendering ────────────────────────────────────────────────────
def test_report_has_llm_usage_section_estimated(tmp_path):
    st = _state(tmp_path)
    st.ensure_dirs()
    st.usage = {"calls": 7, "prompt_tokens": 12300, "completion_tokens": 2100,
                "total_tokens": 14400, "estimated_calls": 7, "cost_usd": 0.004,
                "cost_known": True, "models": ["deepseek-chat"]}
    out = write_report(st, {"stop_reason": "done"})
    body = out.read_text()
    assert "## LLM usage" in body
    assert "Calls: 7" in body
    assert "~$0.0040" in body
    assert "estimated" in body
    assert "LLM: 7 calls" in body


def test_report_usage_cost_unknown(tmp_path):
    st = _state(tmp_path)
    st.ensure_dirs()
    st.usage = {"calls": 1, "prompt_tokens": 100, "completion_tokens": 50,
                "total_tokens": 150, "estimated_calls": 0, "cost_usd": 0.0,
                "cost_known": False, "models": ["mystery-local-model"]}
    body = write_report(st, {"stop_reason": "done"}).read_text()
    assert "cost unknown" in body


# ── end-to-end through the loop (needs curl + local server) ────────────────
pytestmark = pytest.mark.skipif(
    shutil.which("curl") is None, reason="curl not installed"
)


def test_loop_populates_state_usage(vuln_server, tmp_path):
    host = vuln_server.split("//", 1)[1]
    st = ScanState(tmp_path, vuln_server, [host])
    llm = UsageLLM()
    planner = Planner(vuln_server, llm=llm, dry_run=False)
    executor = Executor([host], rate_per_min=600)
    loop = AutoLoop(st, planner, executor, max_steps=3, time_budget=30)
    result = loop.run()

    assert llm.calls >= 1
    assert st.usage["calls"] == planner.usage.totals()["calls"]
    assert st.usage["calls"] >= 1
    assert st.usage["estimated_calls"] == 0          # UsageLLM reports exactly
    assert st.usage["total_tokens"] > 0
    assert result["usage"]["calls"] == st.usage["calls"]


def test_loop_token_budget_stops(vuln_server, tmp_path):
    host = vuln_server.split("//", 1)[1]
    st = ScanState(tmp_path, vuln_server, [host])
    planner = Planner(vuln_server, llm=UsageLLM(), dry_run=False)
    executor = Executor([host], rate_per_min=600)
    # UsageLLM books 18 tokens/call; a 1-token budget trips after the first call.
    loop = AutoLoop(st, planner, executor, max_steps=50, time_budget=30,
                    max_tokens=1)
    result = loop.run()
    assert "token-budget" in result["stop_reason"]
