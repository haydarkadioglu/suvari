"""
Base Agent with delegation support.
Agents can spawn sub-agents to handle specific findings.
"""

from typing import Optional, Type
from datetime import timedelta
from ..llm import LLMClient
from ..workspace import Workspace
from ..tools.runner import ToolRunner


def fmt_time(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds:.1f}s"
    return str(timedelta(seconds=int(seconds)))


class AgentManager:
    """Tracks agent delegation tree."""
    def __init__(self):
        self.agents = []

    def register(self, agent: "BaseAgent"):
        self.agents.append(agent)

    def summary(self) -> str:
        return f"{len(self.agents)} agents spawned"


class BaseAgent:
    """Base class with delegation support."""

    def __init__(
        self,
        name: str,
        llm: LLMClient,
        workspace: Workspace,
        tools: ToolRunner,
        verbose: bool = False,
        manager: Optional[AgentManager] = None,
    ):
        self.name = name
        self.llm = llm
        self.ws = workspace
        self.tools = tools
        self.verbose = verbose
        self.manager = manager or AgentManager()
        if manager:
            manager.register(self)
        self._children = []

    def log(self, msg: str):
        print(f"  {msg}")

    def debug(self, msg: str):
        if self.verbose:
            print(f"  [debug] {msg}")

    def delegate(self, agent_cls: Type["BaseAgent"], task_name: str, context: dict) -> dict:
        """Spawn a sub-agent to handle a specific task."""
        sub_ws = Workspace(f"{self.ws.path.stem}/{task_name}")
        sub_agent = agent_cls(
            name=f"{self.name}.{task_name}",
            llm=self.llm,
            workspace=sub_ws,
            tools=self.tools,
            verbose=self.verbose,
            manager=self.manager,
        )
        self._children.append(sub_agent)
        self.log(f"   spawning {task_name}...")
        result = sub_agent.run(context)
        self.log(f"   {task_name} done: {len(result.get('vulnerabilities', []))} findings")
        return result

    def run(self, context: dict) -> dict:
        raise NotImplementedError
