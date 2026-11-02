"""
Session wiring: build the loop's collaborators and run it end-to-end.

Keeps the CLI thin and gives tests a single entry point.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .executor import Executor
from .loop import AutoLoop
from .planner import Planner
from .report import write_report
from .state import ScanState

log = logging.getLogger("suvari.auto")


def _host(url: str) -> str:
    netloc = urlparse(url).netloc
    return netloc or url


def build_llm(provider: Optional[str], model: Optional[str]):
    """Construct an LLMClient, surfacing a clear error if no key is set."""
    from ..llm import LLMClient
    from ..config import load_config

    cfg = load_config()
    provider = provider or cfg.get("provider")
    model = model or cfg.get("model")
    if not provider:
        raise RuntimeError(
            "No LLM provider configured. Run `suvari.py configure`, pass "
            "--provider, or use --dry-run for the deterministic engine."
        )
    try:
        return LLMClient(provider=provider, model=model)
    except (ValueError, PermissionError) as e:
        raise RuntimeError(
            f"Cannot reach the LLM provider: {e}\n"
            f"Set the API key (suvari.py configure) or use --dry-run."
        ) from e


def run_auto(
    url: str,
    root: Path,
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    max_steps: int = 20,
    time_budget: float = 300.0,
    rate_per_min: int = 60,
    resume: bool = False,
    dry_run: bool = False,
    allow_hosts: Optional[list[str]] = None,
    safe: bool = True,
) -> dict:
    root = Path(root)
    allowed = [_host(url)] + list(allow_hosts or [])

    if resume and ScanState.exists(root):
        state = ScanState.load(root)
        log.info("resumed from %s (turn %d)", root, state.turn)
    else:
        state = ScanState(
            root, target=url, allowed_hosts=allowed,
            budget={"max_steps": max_steps, "time_budget": time_budget,
                    "rate_per_min": rate_per_min, "safe": safe},
        )
    state.ensure_dirs()

    llm = None if dry_run else build_llm(provider, model)
    planner = Planner(url, llm=llm, dry_run=dry_run)
    executor = Executor(state.allowed_hosts, rate_per_min=rate_per_min)

    loop = AutoLoop(state, planner, executor,
                    max_steps=max_steps, time_budget=time_budget)
    result = loop.run()
    report_path = write_report(state, result)
    result["report"] = str(report_path)
    result["root"] = str(root)
    return result
