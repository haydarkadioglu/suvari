"""
Autonomous, probability-driven scan engine.

A self-contained loop that generates hypotheses, assigns each a probability,
tests the most promising one, folds the resulting evidence back into the
probabilities (Bayes-like), and reports why it went where it did. Runs with an
LLM provider or fully deterministically via ``--dry-run``.
"""

from .hypothesis import Hypothesis, bayes_update
from .state import ScanState
from .planner import Planner
from .executor import Executor
from .loop import AutoLoop
from .report import write_report, write_job_report
from .scope import Scope, ScopeError
from .jobs import Job, JobManager, JobRunner

__all__ = [
    "Hypothesis", "bayes_update", "ScanState", "Planner",
    "Executor", "AutoLoop", "write_report", "write_job_report",
    "Scope", "ScopeError", "Job", "JobManager", "JobRunner",
]
