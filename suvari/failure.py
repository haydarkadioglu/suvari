"""
Unified Failure Attribution — L0-L5 classification and recovery strategies.
Merged from failure.py + knowledge.py (knowledge.py is now deprecated).
"""

import re
from enum import Enum
from typing import Optional, Sequence


# HTTP 404 responses read "404 Not Found"; they are a wrong-hypothesis signal (L4),
# not a missing-tool signal (L1), so the bare "not found" signature must not
# swallow them.
_HTTP_404_RE = re.compile(r"\b404\b")


class FailureLevel(Enum):
    """L0-L5 failure severity levels (from LuaN1aoAgent)."""
    L0_OBSERVATION = 0     # Raw tool output - normal
    L1_TOOL_ERROR = 1      # Tool not found, timeout, syntax error
    L2_PREREQUISITE = 2    # Auth failed, session expired
    L3_ENVIRONMENT = 3     # WAF, rate limit, target down
    L4_HYPOTHESIS = 4      # Wrong approach/parameter
    L5_STRATEGY = 5        # Wrong attack path, need replan


# Mapping from old knowledge.py L1-L6 to new L0-L5
LEGACY_MAP = {
    "L1_TOOL_NOT_FOUND": FailureLevel.L1_TOOL_ERROR,
    "L2_PERMISSION": FailureLevel.L2_PREREQUISITE,
    "L3_UNEXPECTED_OUTPUT": FailureLevel.L4_HYPOTHESIS,
    "L4_STRATEGIC": FailureLevel.L5_STRATEGY,
    "L5_TIMEOUT": FailureLevel.L1_TOOL_ERROR,
    "L6_LLM_ERROR": FailureLevel.L1_TOOL_ERROR,
}


def _matches(haystack: str, needles: Sequence[str]) -> bool:
    """Return True when any signature in ``needles`` occurs in ``haystack``."""
    return any(needle in haystack for needle in needles)


def classify_failure(tool_name: str, output: str, duration: float) -> FailureLevel:
    """Classify a tool execution failure into an L0-L5 level.

    Signature checks run before the L0 success default, so a short or long
    failure message is never mistaken for normal output. Levels are evaluated
    strictly in order L1 -> L2 -> L3 -> L4 -> L5, and only when nothing matches
    is the L0 success default returned. The L5 duration branch sits after the
    signature checks, so a slow failure (e.g. a 403 that took 200 s) is still
    reported by its signature rather than being reclassified as L5.

    ``tool_name`` is not used for classification (only ``get_recovery_strategy``
    consumes it). ``duration`` may be ``None`` or negative and is normalised to
    ``0.0``; ``output`` may be ``None`` and is treated as an empty string.
    """
    out_text = output or ""
    out_lower = out_text.lower()
    duration = duration or 0.0
    if duration < 0:
        duration = 0.0

    # L1: Tool execution failure
    if _matches(out_lower, ["no such file", "command not found"]):
        return FailureLevel.L1_TOOL_ERROR
    # A missing binary is also reported as "<tool>: not found" (e.g. "bash: nmap: not found",
    # "host not found" from DNS helpers). Keep that signal without capturing HTTP 404
    # responses, which the L4 block below classifies as a wrong hypothesis.
    if "not found" in out_lower and not _HTTP_404_RE.search(out_lower):
        return FailureLevel.L1_TOOL_ERROR
    if out_text.startswith("(TIMEOUT"):
        return FailureLevel.L1_TOOL_ERROR
    if _matches(out_lower, ["option is unknown", "invalid option", "try 'curl --help'"]):
        return FailureLevel.L1_TOOL_ERROR
    if out_text.startswith("(error:"):
        return FailureLevel.L1_TOOL_ERROR

    # L2: Prerequisite failure
    if _matches(out_lower, ["unauthorized", "401", "403", "forbidden", "permission denied"]):
        return FailureLevel.L2_PREREQUISITE
    if _matches(out_lower, ["session expired", "authentication required", "login required"]):
        return FailureLevel.L2_PREREQUISITE

    # L3: Environment interference
    if _matches(out_lower, ["cloudflare", "waf", "rate limit", "429", "too many requests"]):
        return FailureLevel.L3_ENVIRONMENT
    if _matches(out_lower, ["connection refused", "connection timed out", "no route to host"]):
        return FailureLevel.L3_ENVIRONMENT

    # L4: Hypothesis wrong
    if _matches(out_lower, ["404", "no results", "0 found", "empty", "nothing found"]):
        return FailureLevel.L4_HYPOTHESIS

    # L5: Strategic (now reachable: only a clean run that took too long reaches here)
    if duration > 120:
        return FailureLevel.L5_STRATEGY

    # L0: Success default (no signature matched)
    return FailureLevel.L0_OBSERVATION


# Fallback tools: primary → fallback mapping
FALLBACK_MAP = {
    "nmap": ["masscan", "rustscan"],
    "gobuster": ["ffuf", "feroxbuster", "dirb"],
    "ffuf": ["feroxbuster", "gobuster"],
    "whatweb": ["httpx", "curl"],
    "wafw00f": ["curl"],  # Manual WAF detection via headers
    "dnsenum": ["dnsrecon", "fierce"],
    "dnsrecon": ["fierce", "dnsenum"],
    "theharvester": ["amass"],
}


def get_recovery_strategy(level: FailureLevel, tool_name: str) -> str:
    """Get recovery strategy based on failure level."""
    strategies = {
        FailureLevel.L0_OBSERVATION: "continue",
        FailureLevel.L1_TOOL_ERROR: f"fallback to alternative tool for {tool_name}" if tool_name in FALLBACK_MAP else "skip",
        FailureLevel.L2_PREREQUISITE: "check credentials and retry",
        FailureLevel.L3_ENVIRONMENT: "reduce speed, add delay, try alternative approach",
        FailureLevel.L4_HYPOTHESIS: "try different parameter/endpoint",
        FailureLevel.L5_STRATEGY: "replan attack path",
    }
    return strategies.get(level, "skip")


def get_fallback_tool(tool_name: str) -> Optional[str]:
    """Get fallback tool for a given tool."""
    return FALLBACK_MAP.get(tool_name, [None])[0]
