"""
Mode — Suvari interaction modes.

- auto: Fully automated. No questions. Best for CI/CD. Default.
- interactive: Ask user before each tool, show findings live, confirm exploits.
- guided: Smart defaults. Ask for slow/dangerous ops. Show findings as they appear.
"""

from enum import Enum


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
    def ask_before_scan(self) -> bool:
        """Ask user before running each tool?"""
        return self == ScanMode.INTERACTIVE

    @property
    def ask_if_slow(self) -> bool:
        """Ask user before tools taking >30s?"""
        return self in (ScanMode.INTERACTIVE, ScanMode.GUIDED)

    @property
    def ask_before_exploit(self) -> bool:
        """Ask user before attempting exploits?"""
        return self in (ScanMode.INTERACTIVE, ScanMode.GUIDED)

    @property
    def show_live_findings(self) -> bool:
        """Show findings in real-time as they're discovered?"""
        return self in (ScanMode.INTERACTIVE, ScanMode.GUIDED)

    @property
    def quiet(self) -> bool:
        """Minimal output, no interaction?"""
        return self == ScanMode.AUTO

    def __str__(self) -> str:
        return self.value


def ask_user(question: str, default: bool = True) -> bool:
    """Ask the user a yes/no question. Returns True for yes, False for no.
    
    Falls back to 'default' if not in an interactive terminal.
    """
    try:
        hint = "Y/n" if default else "y/N"
        ans = input(f"  ? {question} [{hint}] ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        return default  # Enter pressed -> use default
    except (EOFError, KeyboardInterrupt):
        return default


def show_finding(vuln: dict):
    """Display a finding in real-time."""
    sev = vuln.get("severity", "?")
    sev_color = {"CRITICAL": "🔥", "HIGH": "⚠️", "MEDIUM": "📌", "LOW": "ℹ️"}.get(sev, "•")
    print(f"  {sev_color} [{sev}] {vuln.get('type', '?')} — {vuln.get('location', '')}")
