"""
Logger — writes structured logs to file + console for debugging.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


class ScanLogger:
    """Logs scan events to a file for debugging and auditing."""

    def __init__(self, workspace_path: Optional[Path] = None):
        self.log_path = None
        if workspace_path:
            workspace_path.mkdir(parents=True, exist_ok=True)
            self.log_path = workspace_path / "scan.log"

    def log(self, level: str, phase: str, message: str, data: dict = None):
        """Write a log entry."""
        entry = {
            "time": datetime.now().isoformat(),
            "level": level,
            "phase": phase,
            "message": message,
        }
        if data:
            # Truncate large data
            clean = {}
            for k, v in data.items():
                if isinstance(v, str) and len(v) > 500:
                    clean[k] = v[:500] + f"... [{len(v)} chars total]"
                else:
                    clean[k] = v
            entry["data"] = clean

        # Console (always)
        prefix = {"INFO": "  [INFO]", "WARN": "  [WARN]", "ERROR": "  [ERR]", "DEBUG": "  [SEARCH]"}.get(level, "  [LOG]")
        print(f"{prefix} [{phase}] {message}")

        # File
        if self.log_path:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

    def info(self, phase: str, message: str, data: dict = None):
        self.log("INFO", phase, message, data)

    def warn(self, phase: str, message: str, data: dict = None):
        self.log("WARN", phase, message, data)

    def error(self, phase: str, message: str, data: dict = None):
        self.log("ERROR", phase, message, data)

    def debug(self, phase: str, message: str, data: dict = None):
        self.log("DEBUG", phase, message, data)

    def tool_output(self, phase: str, tool: str, output: str):
        """Log full tool output to a separate file."""
        if self.log_path:
            tool_log = self.log_path.parent / f"{phase}_{tool}.log"
            with open(tool_log, "w") as f:
                f.write(output)
