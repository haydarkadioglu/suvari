"""
Base Agent — abstract base for all Suvari agents.
Inspired by LuaN1aoAgent's P-E-R (Planner-Executor-Reflector) framework.
"""

from typing import Optional
from ..llm import LLMClient
from ..workspace import Workspace
from ..tools.runner import ToolRunner


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
        if self.verbose:
            print(f"  [{self.name}] {msg}")

    def run(self, context: dict) -> dict:
        raise NotImplementedError
