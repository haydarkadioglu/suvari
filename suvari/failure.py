


   

from enum import Enum

from typing import Optional

class FailureLevel(Enum):

                                                            

    L0_OBSERVATION = 0

    L1_TOOL_ERROR = 1

    L2_PREREQUISITE = 2

    L3_ENVIRONMENT = 3

    L4_HYPOTHESIS = 4

    L5_STRATEGY = 5

LEGACY_MAP = {

    "L1_TOOL_NOT_FOUND": FailureLevel.L1_TOOL_ERROR,

    "L2_PERMISSION": FailureLevel.L2_PREREQUISITE,

    "L3_UNEXPECTED_OUTPUT": FailureLevel.L4_HYPOTHESIS,

    "L4_STRATEGIC": FailureLevel.L5_STRATEGY,

    "L5_TIMEOUT": FailureLevel.L1_TOOL_ERROR,

    "L6_LLM_ERROR": FailureLevel.L1_TOOL_ERROR,

}

def classify_failure(tool_name: str, output: str, duration: float) -> FailureLevel:

                                                             

    out_lower = output.lower()

    duration = duration or 0

    if not output.startswith("(") and not output.startswith("TIMEOUT"):

        if len(output) > 10:

            return FailureLevel.L0_OBSERVATION

    if any(x in out_lower for x in ["not found", "no such file", "command not found"]):

        return FailureLevel.L1_TOOL_ERROR

    if output.startswith("(TIMEOUT"):

        return FailureLevel.L1_TOOL_ERROR

    if any(x in out_lower for x in ["option is unknown", "invalid option", "try 'curl --help'"]):

        return FailureLevel.L1_TOOL_ERROR

    if any(x in out_lower for x in ["unauthorized", "401", "403", "forbidden", "permission denied"]):

        return FailureLevel.L2_PREREQUISITE

    if any(x in out_lower for x in ["session expired", "authentication required", "login required"]):

        return FailureLevel.L2_PREREQUISITE

    if any(x in out_lower for x in ["cloudflare", "waf", "rate limit", "429", "too many requests"]):

        return FailureLevel.L3_ENVIRONMENT

    if any(x in out_lower for x in ["connection refused", "connection timed out", "no route to host"]):

        return FailureLevel.L3_ENVIRONMENT

    if any(x in out_lower for x in ["404", "no results", "0 found", "empty", "nothing found"]):

        return FailureLevel.L4_HYPOTHESIS

    if duration > 120:

        return FailureLevel.L5_STRATEGY

    if output.startswith("(error:"):

        return FailureLevel.L1_TOOL_ERROR

    return FailureLevel.L0_OBSERVATION

FALLBACK_MAP = {

    "nmap": ["masscan", "rustscan"],

    "gobuster": ["ffuf", "feroxbuster", "dirb"],

    "ffuf": ["feroxbuster", "gobuster"],

    "whatweb": ["httpx", "curl"],

    "wafw00f": ["curl"],

    "dnsenum": ["dnsrecon", "fierce"],

    "dnsrecon": ["fierce", "dnsenum"],

    "theharvester": ["amass"],

}

def get_recovery_strategy(level: FailureLevel, tool_name: str) -> str:

                                                       

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

                                             

    return FALLBACK_MAP.get(tool_name, [None])[0]
