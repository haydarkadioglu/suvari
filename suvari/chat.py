"""
Chat — interactive pentesting conversation via SuvariCore.
"""

from typing import Optional
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from .core import SuvariCore

console = Console()


class ChatSession:
    """Chat UI using SuvariCore for all logic."""

    def __init__(self):
        self.core = SuvariCore()
        self._session_file = None

    def run(self):
        console.print("[bold][SUVARI] — AI Pentester Assistant[/bold]")
        self._session_file = datetime.now().strftime("output/chat/session_%Y%m%d_%H%M%S.md")
        try:
            Path("output/chat").mkdir(parents=True, exist_ok=True)
            Path(self._session_file).write_text(f"# Suvari Chat\nStarted: {datetime.now().isoformat()[:19]}\n\n")
        except Exception:
            pass

        while True:
            try:
                text = Prompt.ask("[bold cyan]You[/bold cyan]")
            except (EOFError, KeyboardInterrupt):
                console.print("\nGoodbye!")
                break
            t = text.strip().lower()
            if t in ("exit", "quit", "q"):
                console.print("Goodbye!")
                break
            console.print("[dim]─" * 50 + "[/dim]")
            self._handle(text)
            console.print("[dim]─" * 50 + "[/dim]")

    def _handle(self, text: str):
        t = text.strip().lower()
        if t.startswith("scan "):
            url = text.split()[-1]
            console.print(f"  Scanning {url}...")
            r = self.core.scan(url)
            console.print(f"  Done: {r.get('path', '')}")
            return
        if t == "history" or t == "list":
            for s in self.core.list_scans()[:10]:
                console.print(f"  {s}")
            return
        if t == "report" and self.core.last_scan_dir:
            console.print(self.core.get_report(self.core.last_scan_dir))
            return

        # P-E-R via core
        response = self.core.chat(text, session_file=Path(self._session_file) if self._session_file else None)
        if response:
            console.print(response)
