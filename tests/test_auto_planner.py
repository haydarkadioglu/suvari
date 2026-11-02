"""Tests for the planner: bootstrap, schema handling, fallback, interpretation."""

from suvari.auto.executor import ExecResult
from suvari.auto.planner import Planner, VECTOR_RULES, _extract_json
from suvari.auto.state import ScanState


BASE = "http://127.0.0.1:9999"


def _fresh_state(tmp_path):
    return ScanState(tmp_path, BASE, ["127.0.0.1:9999"])


class _BadLLM:
    """Always returns unparseable output."""
    def __init__(self):
        self.calls = 0

    def chat(self, **kw):
        self.calls += 1
        return "sure, let me think about that... no JSON here."


class _RaisingLLM:
    def __init__(self):
        self.calls = 0

    def chat(self, **kw):
        self.calls += 1
        raise RuntimeError("Rate limited (deepseek): Too many requests.")


class _GoodLLM:
    """Returns a valid plan selecting the second hypothesis."""
    def __init__(self, hid_provider):
        self._hid_provider = hid_provider

    def chat(self, **kw):
        hid = self._hid_provider()
        return (
            '{"hypotheses": [], "next_action": {"hypothesis_id": "%s", '
            '"tool": "curl", "args": ["-s", "%s/"], "why": "best lead"}}'
            % (hid, BASE)
        )


def test_extract_json_plain():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced():
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_json_embedded_prose():
    assert _extract_json('Here you go: {"a": 1} hope that helps') == {"a": 1}


def test_extract_json_garbage_returns_none():
    assert _extract_json("no json at all") is None


def test_bootstrap_seeds_rule_table(tmp_path):
    st = _fresh_state(tmp_path)
    Planner(BASE, dry_run=True).bootstrap(st)
    vectors = {h.vector for h in st.hypotheses.values()}
    # every static vector seeded, dynamic path-probe excluded
    assert "path-probe" not in vectors
    assert "git-exposure" in vectors
    assert "missing-security-headers" in vectors
    assert len(st.hypotheses) == len(VECTOR_RULES) - 1


def test_dry_run_select_picks_highest_posterior(tmp_path):
    st = _fresh_state(tmp_path)
    p = Planner(BASE, dry_run=True)
    p.bootstrap(st)
    # bump one hypothesis
    target = next(iter(st.hypotheses.values()))
    target.posterior = 0.95
    plan = p.select(st)
    assert plan.hypothesis.id == target.id
    assert plan.source == "deterministic"
    assert plan.tool == "curl"


def test_schema_error_falls_back_to_deterministic(tmp_path):
    st = _fresh_state(tmp_path)
    llm = _BadLLM()
    p = Planner(BASE, llm=llm, dry_run=False)
    p.bootstrap(st)              # augment call will fail to parse 3x
    plan = p.select(st)          # select call will fail to parse 3x -> fallback
    assert plan is not None
    assert plan.source == "deterministic"
    assert st.fell_back_to_deterministic is True
    assert llm.calls >= 6        # 3 for augment + 3 for select


def test_llm_exception_falls_back(tmp_path):
    st = _fresh_state(tmp_path)
    llm = _RaisingLLM()
    p = Planner(BASE, llm=llm, dry_run=False)
    p.bootstrap(st)
    plan = p.select(st)
    assert plan.source == "deterministic"
    assert st.fell_back_to_deterministic is True


def test_valid_llm_selection_used(tmp_path):
    st = _fresh_state(tmp_path)
    Planner(BASE, dry_run=True).bootstrap(st)
    first_id = next(iter(st.hypotheses.values())).id
    llm = _GoodLLM(lambda: first_id)
    p = Planner(BASE, llm=llm, dry_run=False)
    plan = p.select(st)
    assert plan.source == "llm"
    assert plan.hypothesis.id == first_id
    # execution still routed through the safe vector probe
    assert plan.tool == "curl"


def test_interpret_git_positive():
    p = Planner(BASE, dry_run=True)
    h = _hyp("git-exposure", BASE + "/.git/config")
    res = ExecResult("curl", [], ok=True, url=h.target, status=200,
                     body="[core]\nbare = false")
    out = p.interpret(h, res)
    assert out["positive"] is True
    assert out["lr"] > 1


def test_interpret_missing_headers_positive():
    p = Planner(BASE, dry_run=True)
    h = _hyp("missing-security-headers", BASE + "/")
    res = ExecResult("curl", [], ok=True, url=h.target, status=200,
                     headers={"content-type": "text/html"}, body="<html>")
    out = p.interpret(h, res)
    assert out["positive"] is True
    assert "missing" in out["detail"]


def test_interpret_headers_present_negative():
    p = Planner(BASE, dry_run=True)
    h = _hyp("missing-security-headers", BASE + "/")
    res = ExecResult("curl", [], ok=True, url=h.target, status=200,
                     headers={"content-security-policy": "default-src 'self'",
                              "x-frame-options": "DENY"}, body="<html>")
    out = p.interpret(h, res)
    assert out["positive"] is False
    assert out["lr"] < 1


def test_interpret_robots_spawns_children(tmp_path):
    st = _fresh_state(tmp_path)
    p = Planner(BASE, dry_run=True)
    h = _hyp("robots-info-leak", BASE + "/robots.txt")
    st.add_hypothesis(h)
    res = ExecResult("curl", [], ok=True, url=h.target, status=200,
                     body="User-agent: *\nDisallow: /internal/\nDisallow: /\n")
    out = p.interpret(h, res)
    assert out["positive"] is True
    assert "/internal/" in out["children"]
    assert "/" not in out["children"]  # root is not a useful lead
    spawned = p.spawn_children(st, h, out["children"])
    assert any(s.vector == "path-probe" and s.target.endswith("/internal/")
               for s in spawned)


def _hyp(vector, target):
    from suvari.auto.hypothesis import Hypothesis
    v = VECTOR_RULES[vector]
    return Hypothesis(id="H1", title=v.title, target=target, vector=vector,
                      prior=v.prior, posterior=v.prior, severity=v.severity)
