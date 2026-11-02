"""Tests for the hypothesis probability model."""

from suvari.auto.hypothesis import (
    Hypothesis, bayes_update, clamp, PROB_MIN, PROB_MAX,
    STATUS_OPEN, STATUS_CONFIRMED,
)


def test_clamp_bounds():
    assert clamp(-5.0) == PROB_MIN
    assert clamp(5.0) == PROB_MAX
    assert clamp(float("nan")) == PROB_MIN
    assert abs(clamp(0.5) - 0.5) < 1e-9


def test_bayes_supporting_evidence_raises_posterior():
    before = 0.3
    after = bayes_update(before, 25.0)
    assert after > before
    assert after <= PROB_MAX


def test_bayes_refuting_evidence_lowers_posterior():
    before = 0.5
    after = bayes_update(before, 0.08)
    assert after < before
    assert after >= PROB_MIN


def test_bayes_neutral_is_identity():
    assert abs(bayes_update(0.4, 1.0) - 0.4) < 1e-9


def test_bayes_never_reaches_certainty():
    # Even huge evidence stays strictly below 1.0 / above 0.0.
    assert bayes_update(0.99, 1e9) <= PROB_MAX
    assert bayes_update(0.01, 1e-9) >= PROB_MIN


def test_update_posterior_mutates_and_returns():
    h = Hypothesis(id="H1", title="t", target="http://x/", vector="git-exposure",
                   prior=0.2, posterior=0.2)
    out = h.update_posterior(25.0)
    assert out == h.posterior
    assert h.posterior > 0.2


def test_is_testable_respects_attempts_and_status():
    h = Hypothesis(id="H1", title="t", target="http://x/", vector="path-probe",
                   max_attempts=2)
    assert h.is_testable()
    h.attempts = 2
    assert not h.is_testable()
    h.attempts = 0
    h.status = STATUS_CONFIRMED
    assert not h.is_testable()


def test_serialization_round_trip():
    h = Hypothesis(id="H9", title="t", target="http://x/", vector="dir-listing",
                   prior=0.2, posterior=0.7, status=STATUS_OPEN, attempts=1,
                   evidence=["E001"], severity="MEDIUM")
    clone = Hypothesis.from_dict(h.to_dict())
    assert clone == h


def test_from_dict_ignores_unknown_keys():
    data = {"id": "H1", "title": "t", "target": "http://x/",
            "vector": "git-exposure", "bogus": 123}
    h = Hypothesis.from_dict(data)
    assert h.id == "H1"
    assert not hasattr(h, "bogus")
