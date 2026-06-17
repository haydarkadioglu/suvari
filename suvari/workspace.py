"""
Workspace — scan output directory management.
"""

from pathlib import Path
from datetime import datetime
import re
import json


class Workspace:
    """Scan workspace — all output is organized here."""

    def __init__(self, name: str, custom_path: Path = None):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)[:40]
        self.path = custom_path or Path("output") / f"{timestamp}_{safe_name}"
        self.path.mkdir(parents=True, exist_ok=True)
        (self.path / "recon").mkdir(exist_ok=True)
        (self.path / "scans").mkdir(exist_ok=True)

        self._meta = {
            "target": name,
            "started_at": timestamp,
            "phases": [],
        }

    def save_result(self, phase: str, tool: str, data: str):
        """Save a tool's output to the workspace."""
        out = self.path / phase / f"{tool}.txt"
        out.write_text(data)
        if phase not in [p["phase"] for p in self._meta["phases"]]:
            self._meta["phases"].append({"phase": phase, "tools": []})
        for p in self._meta["phases"]:
            if p["phase"] == phase and tool not in p["tools"]:
                p["tools"].append(tool)
        self._save_meta()

    def save_json(self, phase: str, name: str, data: dict):
        """Save JSON data to the workspace."""
        out = self.path / phase / f"{name}.json"
        out.write_text(json.dumps(data, indent=2))

    def get_path(self, phase: str, tool: str) -> Path:
        return self.path / phase / f"{tool}.txt"

    def _save_meta(self):
        meta_path = self.path / "meta.json"
        meta_path.write_text(json.dumps(self._meta, indent=2))

    def get_phase_output(self, phase: str) -> str:
        """Combine all output files from a phase into one string."""
        phase_dir = self.path / phase
        if not phase_dir.exists():
            return ""
        parts = []
        for f in sorted(phase_dir.glob("*.txt")):
            parts.append(f"=== {f.stem} ===\n{f.read_text()}")
        return "\n\n".join(parts)

    @property
    def target(self) -> str:
        return self._meta["target"]
