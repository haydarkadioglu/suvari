"""
Hypothesis model for the autonomous, probability-driven scan loop.

Each hypothesis carries a prior and a posterior probability. Evidence updates
the posterior with a Bayesian log-odds update, clamped to [0.01, 0.99] so a
single observation can never drive a hypothesis to absolute certainty.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict
from typing import Optional


# Posterior is never allowed to reach 0 or 1 — keeps log-odds finite and leaves
# room for later evidence to move the estimate in either direction.
PROB_MIN = 0.01
PROB_MAX = 0.99

# Canonical statuses for a hypothesis.
STATUS_OPEN = "open"            # not yet tested (or retryable)
STATUS_CONFIRMED = "confirmed"  # evidence supports it (posterior high)
STATUS_REFUTED = "refuted"      # evidence refutes it (posterior low)
STATUS_EXHAUSTED = "exhausted"  # out of attempts, inconclusive


def clamp(p: float) -> float:
    """Clamp a probability into the open interval [PROB_MIN, PROB_MAX]."""
    if p != p:  # NaN guard
        return PROB_MIN
    return max(PROB_MIN, min(PROB_MAX, p))


def _logit(p: float) -> float:
    p = clamp(p)
    return math.log(p / (1.0 - p))


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def bayes_update(prior: float, likelihood_ratio: float) -> float:
    """Bayesian update in log-odds space.

    ``likelihood_ratio`` (LR) > 1 is supporting evidence, < 1 is refuting
    evidence, == 1 is neutral. The posterior odds equal the prior odds times
    the LR; working in log space keeps this a simple addition and avoids
    overflow. The result is clamped to [PROB_MIN, PROB_MAX].
    """
    if likelihood_ratio <= 0:
        likelihood_ratio = PROB_MIN
    return clamp(_sigmoid(_logit(prior) + math.log(likelihood_ratio)))


@dataclass
class Hypothesis:
    """A single testable belief about the target."""

    id: str
    title: str
    target: str                       # URL the test will probe
    vector: str                       # VECTOR_RULES key (e.g. "git-exposure")
    prior: float = 0.3
    posterior: float = 0.3
    status: str = STATUS_OPEN
    attempts: int = 0
    max_attempts: int = 2
    severity: str = "LOW"
    rationale: str = ""
    evidence: list = field(default_factory=list)  # evidence ids
    parent: Optional[str] = None                   # id of spawning hypothesis
    # origin-specific data, e.g. {"source": "research", "cve": ..., "kind": ...}
    meta: dict = field(default_factory=dict)

    def update_posterior(self, likelihood_ratio: float) -> float:
        """Fold one observation into the posterior and return the new value."""
        self.posterior = bayes_update(self.posterior, likelihood_ratio)
        return self.posterior

    def is_testable(self) -> bool:
        """True when the hypothesis still warrants a probe."""
        return self.status == STATUS_OPEN and self.attempts < self.max_attempts

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Hypothesis":
        allowed = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in allowed}
        return cls(**clean)
