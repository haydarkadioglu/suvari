"""
LLM token / cost accounting for the autonomous loop.

Every model call the planner makes is recorded as a :class:`UsageRecord`
(model, prompt/completion tokens, wall time, and whether the token counts came
from the provider or were *estimated*). :class:`UsageTracker` folds the records
into running totals that the loop persists into ``state.json`` and the report
renders as an "LLM usage" section.

Providers that return a ``usage`` block give exact counts; providers that do not
get a character/4 estimate flagged ``estimated=True`` so the report never claims
more precision than it has.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── price table ──────────────────────────────────────────────────────────
# USD per 1,000,000 tokens, (input, output). Keys are matched as *prefixes*
# against the model id, longest prefix first, so "gpt-4o-mini" wins over
# "gpt-4o" which wins over "gpt". Prices are list prices at time of writing and
# only ever produce an *approximate* cost — treated as best-effort, never billed.
PRICING_PER_MTOK: dict[str, tuple[float, float]] = {
    "deepseek-reasoner": (0.55, 2.19),
    "deepseek-chat": (0.27, 1.10),
    "deepseek": (0.27, 1.10),
    "claude-3-opus": (15.0, 75.0),
    "claude-3-5-haiku": (0.80, 4.0),
    "claude-3-haiku": (0.25, 1.25),
    "claude-opus": (15.0, 75.0),
    "claude-haiku": (0.80, 4.0),
    "claude": (3.0, 15.0),          # sonnet-class default
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-4": (30.0, 60.0),
    "gpt-3.5": (0.50, 1.50),
    "gpt": (2.50, 10.0),
}

CHARS_PER_TOKEN = 4  # crude estimate when a provider returns no usage block


def _price_for(model: str) -> tuple[float, float] | None:
    """Return (input, output) USD per-1M price for ``model`` or None."""
    if not model:
        return None
    m = model.lower()
    for prefix in sorted(PRICING_PER_MTOK, key=len, reverse=True):
        if m.startswith(prefix) or prefix in m:
            return PRICING_PER_MTOK[prefix]
    return None


def estimate_tokens(text: str) -> int:
    """Character/4 token estimate, never negative."""
    if not text:
        return 0
    return max(1, len(text) // CHARS_PER_TOKEN)


@dataclass
class UsageRecord:
    """One LLM call's accounting."""
    model: str
    prompt_tokens: int
    completion_tokens: int
    duration: float
    estimated: bool

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def cost_usd(self) -> float | None:
        price = _price_for(self.model)
        if price is None:
            return None
        pin, pout = price
        return (self.prompt_tokens / 1e6) * pin + (self.completion_tokens / 1e6) * pout


@dataclass
class UsageTracker:
    """Running totals over every :class:`UsageRecord` in a run.

    ``base`` carries aggregate counts restored from a prior run on resume; the
    per-run records are added on top so totals accumulate rather than restart.
    """
    records: list[UsageRecord] = field(default_factory=list)
    base: dict = field(default_factory=dict)

    def add(self, record: UsageRecord) -> None:
        self.records.append(record)

    def totals(self) -> dict:
        b = self.base or {}
        calls = len(self.records) + int(b.get("calls", 0))
        prompt = sum(r.prompt_tokens for r in self.records) + int(b.get("prompt_tokens", 0))
        completion = sum(r.completion_tokens for r in self.records) + int(b.get("completion_tokens", 0))
        estimated_calls = (sum(1 for r in self.records if r.estimated)
                           + int(b.get("estimated_calls", 0)))
        duration = sum(r.duration for r in self.records) + float(b.get("duration", 0.0))

        cost = float(b.get("cost_usd", 0.0)) if b.get("cost_known") else 0.0
        cost_known = (not b) or bool(b.get("cost_known", True))
        for r in self.records:
            c = r.cost_usd()
            if c is None:
                cost_known = False  # at least one model has no price
            else:
                cost += c
        models = sorted({r.model for r in self.records if r.model}
                        | set(b.get("models") or []))
        return {
            "calls": calls,
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
            "estimated_calls": estimated_calls,
            "cost_usd": round(cost, 6),
            "cost_known": cost_known and calls > 0,
            "duration": round(duration, 3),
            "models": models,
        }

    def merge_totals(self, saved: dict) -> None:
        """Seed the tracker with totals persisted from a prior run (resume)."""
        if saved and saved.get("calls"):
            self.base = dict(saved)


# ── formatting helpers ─────────────────────────────────────────────────────
def human_tokens(n: int) -> str:
    """12345 -> '12.3k', 980 -> '980'."""
    if n < 1000:
        return str(int(n))
    return f"{n / 1000:.1f}k"


def format_summary(totals: dict) -> str:
    """One-line CLI summary.

    e.g. ``LLM: 7 calls · 12.3k in / 2.1k out · ~$0.004 (estimated)``
    """
    calls = totals.get("calls", 0)
    if not calls:
        return "LLM: 0 calls (deterministic engine)"
    pin = human_tokens(totals.get("prompt_tokens", 0))
    pout = human_tokens(totals.get("completion_tokens", 0))
    parts = [f"LLM: {calls} calls", f"{pin} in / {pout} out"]
    if totals.get("cost_known") and totals.get("cost_usd") is not None:
        parts.append(f"~${totals['cost_usd']:.4f}")
    else:
        parts.append("cost unknown")
    line = " · ".join(parts)
    if totals.get("estimated_calls", 0):
        line += " (estimated)"
    return line
