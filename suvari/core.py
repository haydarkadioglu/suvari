"""
P-E-R Core — Planner-Executor-Reflector framework.
Inspired by LuaN1aoAgent's P-E-R agent collaboration architecture.

Planner: decides strategy and next actions based on accumulated knowledge
Executor: runs tools and collects results
Reflector: analyzes results, classifies outcomes, provides feedback
"""

from typing import Optional, Callable
from .llm import LLMClient
from .workspace import Workspace
from .tools.runner import ToolRunner
from .prompt_loader import PromptLoader
from .state import PipelineState


PLANNER_PROMPT = """You are a penetration testing strategist (Planner). Based on the current state of the scan, decide what to do next.

Target: {target_url}
Phase: {phase}
Mode: {mode}

Completed phases: {completed}
Current knowledge: {knowledge}

## Available Tools
{tools}

## Instructions
Analyze the current state and decide the best next action.
Consider:
1. What do we know already?
2. What critical information is missing?
3. What's the highest-impact next step?
4. Are there dependencies (must check X before Y)?

Return a JSON plan:
{{
  "assessment": "Current situation summary",
  "next_action": "tool_name or phase_name",
  "priority": "high/medium/low",
  "reasoning": "Why this action",
  "estimated_impact": "What we expect to learn"
}}
"""

REFLECTOR_PROMPT = """You are a penetration testing analyst (Reflector). Analyze the results of the last action.

Target: {target_url}
Last action: {last_action}
Tool used: {tool}
Output preview: {output}

## Instructions
Analyze the output and determine:
1. Was the action successful?
2. What did we learn?
3. Any errors or anomalies?
4. What should the Planner do next?

Return JSON:
{{
  "success": true/false,
  "findings": ["List of findings from this action"],
  "error_type": null or "tool_error/timeout/permission/empty/other",
  "error_detail": "Description of any errors",
  "next_suggestion": "What to try next",
  "confidence": "high/medium/low"
}}
"""


class Planner:
    """Decides strategy and next actions."""

    def __init__(self, llm: LLMClient, tools: ToolRunner, prompt_loader: PromptLoader):
        self.llm = llm
        self.tools = tools
        self.prompts = prompt_loader
        self.knowledge = []

    def decide(self, phase: str, completed: list, last_results: dict = None) -> dict:
        """Decide the next action based on current state."""
        knowledge_text = "\n".join(self.knowledge[-5:]) if self.knowledge else "No knowledge yet"

        prompt = PLANNER_PROMPT.format(
            target_url=self.prompts.globals["target_url"],
            phase=phase,
            mode="Fast" if self.prompts.globals.get("fast") else "Full",
            completed=", ".join(completed) or "none",
            knowledge=knowledge_text[:1000],
            tools=", ".join(self.tools.available_tools().keys()) or "none",
        )

        try:
            plan = self.llm.chat_json(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )
            return plan
        except Exception as e:
            return {
                "assessment": "Fallback to default",
                "next_action": phase,
                "priority": "medium",
                "reasoning": f"AI error: {e}",
                "estimated_impact": "Unknown",
            }

    def add_knowledge(self, finding: str):
        """Add a finding to accumulated knowledge."""
        self.knowledge.append(finding)


class Reflector:
    """Analyzes results and provides feedback."""

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def analyze(self, last_action: str, tool: str, output: str, target_url: str) -> dict:
        """Analyze the output of a tool execution."""
        prompt = REFLECTOR_PROMPT.format(
            target_url=target_url,
            last_action=last_action,
            tool=tool,
            output=output[:1500],
        )

        try:
            analysis = self.llm.chat_json(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
            )
            return analysis
        except Exception as e:
            return {
                "success": bool(output and not output.startswith("(")),
                "findings": [f"Ran {tool} on {last_action}"],
                "error_type": "parse_error" if output else "empty",
                "error_detail": str(e),
                "next_suggestion": "continue with next phase",
                "confidence": "low",
            }
