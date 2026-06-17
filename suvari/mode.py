"""
Mode — Suvari interaction & conversation system.
Interactive mode feels like chatting with a pentester, not answering prompts.
"""

from enum import Enum
from datetime import datetime


class ScanMode(Enum):
    AUTO = "auto"
    INTERACTIVE = "interactive"
    GUIDED = "guided"

    @classmethod
    def from_str(cls, s: str) -> "ScanMode":
        s = s.lower().strip()
        for m in cls:
            if m.value == s:
                return m
        return cls.AUTO

    @property
    def chat_enabled(self) -> bool:
        """Full conversational interaction?"""
        return self == ScanMode.INTERACTIVE

    @property
    def suggestions_enabled(self) -> bool:
        """Allow user hints during scan?"""
        return self in (ScanMode.INTERACTIVE, ScanMode.GUIDED)

    def __str__(self) -> str:
        return self.value


def ask_question(question: str, default: bool = True) -> bool:
    """Simple yes/no question."""
    try:
        hint = "Y/n" if default else "y/N"
        ans = input(f"  ? {question} [{hint}] ").strip().lower()
        return {"y": True, "yes": True, "n": False, "no": False}.get(ans, default)
    except (EOFError, KeyboardInterrupt):
        return default


def chat_prompt(phase: str, summary: str, suggestions_enabled: bool = True) -> str:
    """Chat-like interaction. Shows context, waits for user input.
    
    Returns the user's input string (empty if skipped).
    """
    if not suggestions_enabled:
        return ""

    try:
        print(f"\n  ═══ {phase} ═══")
        print(f"  {summary}")
        print(f"  ── Enter your suggestion or press Enter to continue ──")
        hint = input(f"  ▷ ").strip()
        if hint:
            print(f"  ✓ Got it: {hint[:120]}")
            return hint
        return ""
    except (EOFError, KeyboardInterrupt):
        return ""


def show_finding(vuln: dict, index: int = 0):
    """Display a finding."""
    sev = vuln.get("severity", "?")
    icon = {"CRITICAL": "[CRIT]", "HIGH": "[WARN]", "MEDIUM": "[INFO]", "LOW": "[INFO]", "INFO": "[INFO]"}.get(sev, "•")
    print(f"  {icon} #{index} [{sev}] {vuln.get('type', '?')} — {vuln.get('location', '')}")


def chat_after_recon(results: dict, suggestions_enabled: bool) -> str:
    """Chat after reconnaissance: show what we found, ask user."""
    if not suggestions_enabled:
        return ""

    tech = results.get("whatweb", "")[:100].replace("\n", " ")
    ports = results.get("nmap", "")
    port_lines = [l.strip() for l in ports.split("\n") if "/tcp" in l]
    port_str = ", ".join(port_lines[:4]) if port_lines else "scanning..."

    summary = (
        f"Target analysis complete.\n"
        f"  Tech: {tech}\n"
        f"  Ports: {port_str}\n"
        f"  What would you like me to focus on?"
    )
    return chat_prompt("RECON", summary, suggestions_enabled)


def chat_after_scan(results: dict, suggestions_enabled: bool) -> str:
    """Chat after scanning: show tool results, ask user."""
    if not suggestions_enabled:
        return ""

    tools_run = [k for k in results if not k.endswith("_time") and not k.endswith("_status") and not k.startswith("_")]
    statuses = {k: results.get(f"{k}_status", "?") for k in tools_run}
    summary = (
        f"Tools finished: {', '.join(tools_run)}\n"
        f"  Results: {' | '.join(f'{k}={v}' for k,v in statuses.items())}\n"
        f"  Any area to dig deeper?"
    )
    return chat_prompt("SCAN", summary, suggestions_enabled)


def chat_before_exploit(vulnerabilities: list, suggestions_enabled: bool) -> str:
    """Chat before exploitation: show findings, ask user."""
    if not suggestions_enabled:
        return ""

    summary = f"Found {len(vulnerabilities)} potential issues:"
    for i, v in enumerate(vulnerabilities[:5], 1):
        show_finding(v, i)
    if len(vulnerabilities) > 5:
        summary += f"\n  ...and {len(vulnerabilities) - 5} more"

    return chat_prompt("EXPLOIT", f"{summary}\n  Which one should I try to verify?", suggestions_enabled)
