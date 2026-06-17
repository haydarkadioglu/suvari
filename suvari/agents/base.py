"""
Base Agent — abstract base for all Suvari agents.
Inspired by LuaN1aoAgent's P-E-R (Planner-Executor-Reflector) framework.
"""

from typing import Optional
from datetime import timedelta
from ..llm import LLMClient
from ..workspace import Workspace
from ..tools.runner import ToolRunner


def fmt_time(seconds: float) -> str:
    """Format elapsed time: sub-second shows '0.Xs', else 'M:SS'."""
    if seconds < 1:
        return f"{seconds:.1f}s"
    return str(timedelta(seconds=int(seconds)))


class BaseAgent:
    """Base class for all Suvari agents."""

    def __init__(
        self,
        name: str,
        llm: LLMClient,
        workspace: Workspace,
        tools: ToolRunner,
        verbose: bool = False,
    ):
        self.name = name
        self.llm = llm
        self.ws = workspace
        self.tools = tools
        self.verbose = verbose

    def log(self, msg: str):
        """Show log messages. Tool operations always visible."""
        if self.verbose or msg.startswith(("  🛠️", "     ✅", "✅", "  ⏭️", "  ⚠️", "🔍", "🌐", "🧠")):
            print(f"  {msg}")

    def run(self, context: dict) -> dict:
        raise NotImplementedError
