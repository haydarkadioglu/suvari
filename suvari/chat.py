"""
Chat — minimal UI for SuvariCore chat.
All logic is in core.py. This is just the terminal interface.
"""

from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from .core import SuvariCore

console = Console()


def start():
    """Start interactive chat session."""
    core = SuvariCore()
    session_file = datetime.now().strftime("output/chat/session_%Y%m%d_%H%M%S.md")
    try:
        Path("output/chat").mkdir(parents=True, exist_ok=True)
        Path(session_file).write_text(f"# Suvari Chat\nStarted: {datetime.now().isoformat()[:19]}\n\n")
    except Exception:
        session_file = None

    console.print("[bold][SUVARI] Pentest Chat[/bold]")
    console.print("Type 'exit' to quit.\n")

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

        # Handle built-in commands
        if t.startswith("scan "):
            url = text.split()[-1]
            console.print(f"  Scanning {url}...")
            result = core.scan(url)
            console.print(f"  Done: {result.get('path', '')}")
        elif t in ("history", "list"):
            for s in core.list_scans()[:10]:
                console.print(f"  {s}")
        elif t == "report" and core.last_scan_dir:
            r = core.last_scan_dir / "report.md"
            if r.exists():
                console.print(r.read_text()[:2000])
        else:
            # P-E-R via core
            response = core.chat(text, session_file=Path(session_file) if session_file else None)
            if response:
                console.print(response)

        console.print("[dim]─" * 50 + "[/dim]")
