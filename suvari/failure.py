"""
Failure Attribution — L0-L5 failure classification and recovery strategies.
Adapted from LuaN1aoAgent's failure attribution model and Shannon's error handling.
"""

from enum import Enum
from typing import Optional


class FailureLevel(Enum):
    """L0-L5 failure classification (LuaN1aoAgent-inspired)."""
    L0_OBSERVATION = "L0"       # Raw tool output, no failure
    L1_TOOL_ERROR = "L1"        # Tool not found, timeout, syntax error
    L2_PREREQUISITE = "L2"      # Auth failed, session expired, dependency missing
    L3_ENVIRONMENT = "L3"       # WAF, firewall, rate limit, target down
    L4_HYPOTHESIS = "L4"        # Wrong approach, parameter not vulnerable
    L5_STRATEGY = "L5"          # Wrong attack path, dead end

    @property
    def retryable(self) -> bool:
        """Can this failure be retried?"""
        return self in (FailureLevel.L1_TOOL_ERROR, FailureLevel.L3_ENVIRONMENT)

    @property
    def requires_replan(self) -> bool:
        """Does this failure require a new plan?"""
        return self in (FailureLevel.L4_HYPOTHESIS, FailureLevel.L5_STRATEGY)


# Common error patterns and their classifications
ERROR_PATTERNS = [
    # L1: Tool errors
    (["not found", "no such file", "command not found"], FailureLevel.L1_TOOL_ERROR, "Tool not installed"),
    (["timeout", "timed out"], FailureLevel.L1_TOOL_ERROR, "Tool timed out"),
    (["syntax error", "invalid option", "unrecognized"], FailureLevel.L1_TOOL_ERROR, "Wrong arguments"),
    (["permission denied", "access denied"], FailureLevel.L1_TOOL_ERROR, "Permission denied"),
    # L2: Prerequisite failures
    (["unauthorized", "401", "login failed", "authentication failed"], FailureLevel.L2_PREREQUISITE, "Authentication required"),
    (["session expired", "token expired"], FailureLevel.L2_PREREQUISITE, "Session expired"),
    (["not installed", "could not find"], FailureLevel.L2_PREREQUISITE, "Dependency missing"),
    # L3: Environment
    (["waf", "blocked", "captcha"], FailureLevel.L3_ENVIRONMENT, "Blocked by WAF/security"),
    (["rate limit", "too many requests", "429"], FailureLevel.L3_ENVIRONMENT, "Rate limited"),
    (["connection refused", "no route to host", "dns lookup failed"], FailureLevel.L3_ENVIRONMENT, "Target unreachable"),
    (["503", "502", "500", "service unavailable"], FailureLevel.L3_ENVIRONMENT, "Target server error"),
    # L4: Wrong hypothesis
    (["no vulnerability", "not vulnerable", "false positive"], FailureLevel.L4_HYPOTHESIS, "Not vulnerable"),
    (("empty",), FailureLevel.L4_HYPOTHESIS, "No results (may be wrong approach)"),
    # L5: Strategy
    (["all attempts failed", "no progress", "stuck"], FailureLevel.L5_STRATEGY, "Dead end, need new strategy"),
]


def classify_failure(output: str, tool: str = "") -> tuple[FailureLevel, str]:
    """Classify a tool's output into a failure level.

    Returns (level, reason).
    """
    if not output or output == "(empty)":
        # Empty output could mean L4 (no vuln found) or L2 (couldn't connect)
        return FailureLevel.L4_HYPOTHESIS, "Tool returned empty results"

    out_lower = output.lower()

    for patterns, level, reason in ERROR_PATTERNS:
        for pattern in patterns:
            if pattern in out_lower:
                return level, reason

    # Check for parentheses-wrapped errors from our runner
    if output.startswith("("):
        if "timeout" in out_lower:
            return FailureLevel.L1_TOOL_ERROR, "Tool timed out"
        if "not found" in out_lower:
            return FailureLevel.L1_TOOL_ERROR, "Tool not found"
        return FailureLevel.L1_TOOL_ERROR, f"Tool error: {output[1:40]}"

    return FailureLevel.L0_OBSERVATION, "Tool ran successfully"


def get_recovery_strategy(level: FailureLevel, tool: str = "") -> dict:
    """Get recovery strategy for a failure level.

    Returns dict with action, message, and optional alternative tool.
    """
    strategies = {
        FailureLevel.L1_TOOL_ERROR: {
            "action": "retry_or_fallback",
            "message": f"Tool error, trying alternative approach",
            "fallback_tools": _get_fallback(tool),
        },
        FailureLevel.L2_PREREQUISITE: {
            "action": "fix_prerequisite",
            "message": "Prerequisite not met, attempting workaround",
            "fallback_tools": [],
        },
        FailureLevel.L3_ENVIRONMENT: {
            "action": "slow_down_or_skip",
            "message": "Environment blocking request, slowing down or skipping",
            "fallback_tools": [],
        },
        FailureLevel.L4_HYPOTHESIS: {
            "action": "try_different",
            "message": "Current approach not working, trying different method",
            "fallback_tools": _get_fallback(tool),
        },
        FailureLevel.L5_STRATEGY: {
            "action": "replan",
            "message": "Strategic dead end, need to reassess",
            "fallback_tools": [],
        },
    }
    return strategies.get(level, {
        "action": "continue",
        "message": "Unknown outcome, continuing",
        "fallback_tools": [],
    })


def _get_fallback(tool: str) -> list:
    """Get alternative tools for when a tool fails."""
    fallbacks = {
        "nmap": ["masscan", "rustscan"],
        "masscan": ["nmap"],
        "gobuster": ["ffuf", "feroxbuster", "dirb"],
        "ffuf": ["gobuster", "feroxbuster"],
        "nikto": ["nuclei"],
        "nuclei": ["nikto", "jaeles"],
        "whatweb": ["httpx", "curl"],
        "wpscan": ["nuclei"],
        "hydra": ["medusa", "patator"],
        "sqlmap": [],  # No real alternative for SQLi
        "enum4linux": ["smbmap", "rpcclient"],
        "subfinder": ["amass", "dnsenum"],
        "dnsenum": ["dnsrecon", "fierce"],
        "curl": ["httpx", "wget"],
    }
    return fallbacks.get(tool, [])
