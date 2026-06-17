"""
Mode — Suvari interaction & suggestion system.
User can give hints during scan: "check /admin for default creds", "try SQLi on search", etc.
"""

from enum import Enum


class ScanMode(Enum):
    """Scan modes for controlling user interaction."""
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
    def suggestions_enabled(self) -> bool:
        """Allow user to give hints/suggestions during scan?"""
        return self in (ScanMode.INTERACTIVE, ScanMode.GUIDED)

    def __str__(self) -> str:
        return self.value


def ask_user(question: str, default: bool = True) -> bool:
    """Ask a yes/no question. Returns True for yes, False for no."""
    try:
        hint = "Y/n" if default else "y/N"
        ans = input(f"  ? {question} [{hint}] ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        return default
    except (EOFError, KeyboardInterrupt):
        return default


def ask_suggestions(prompt: str, context: str = "") -> str:
    """Ask the user for free-form suggestions/hints.

    Returns the user's input as a string, or empty string if skipped.
    Shows current context so user knows what's been found so far.
    """
    try:
        print(f"\n  ── {prompt} ──")
        if context:
            print(f"     {context}")
        hint = input(f"  → Your suggestion (or Enter to skip): ").strip()
        if hint:
            print(f"     ✅ Got it: {hint[:100]}")
        return hint
    except (EOFError, KeyboardInterrupt):
        return ""


def show_finding(vuln: dict):
    """Display a finding in real-time."""
    sev = vuln.get("severity", "?")
    icon = {"CRITICAL": "🔥", "HIGH": "⚠️", "MEDIUM": "📌", "LOW": "ℹ️", "INFO": "ℹ️"}.get(sev, "•")
    print(f"  {icon} [{sev}] {vuln.get('type', '?')} — {vuln.get('location', '')}")


def show_recon_summary(results: dict):
    """Show a quick summary of recon findings for user context."""
    tech = results.get("whatweb", "")[:80].replace("\n", " ")
    ports = results.get("nmap", "")
    port_lines = [l.strip() for l in ports.split("\n") if "/tcp" in l]
    port_str = ", ".join(port_lines[:5]) if port_lines else "?"
    print(f"\n  📋 Scan context:")
    print(f"     Target: {results.get('_target', '?')}")
    print(f"     Tech: {tech}")
    print(f"     Ports: {port_str}")
