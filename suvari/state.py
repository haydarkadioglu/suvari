"""
State / Checkpoint — saves and loads pipeline progress for resume support.
Inspired by Shannon's workspace resume capability.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional


CHECKPOINT_FILE = "checkpoint.json"


class PipelineState:
    """Tracks pipeline progress across phases for resume capability."""

    def __init__(self, workspace_path: Path):
        self.path = workspace_path / CHECKPOINT_FILE
        self._state = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            data = json.loads(self.path.read_text())
            # Validate structure
            if "completed_phases" not in data:
                data["completed_phases"] = []
            if "current_phase" not in data:
                data["current_phase"] = None
            return data
        return {
            "target_url": "",
            "started_at": datetime.now().isoformat(),
            "completed_phases": [],
            "current_phase": None,
            "error": None,
        }

    def save(self):
        """Write state to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._state, indent=2))

    def start(self, target_url: str):
        """Initialize state for a new scan."""
        self._state["target_url"] = target_url
        self._state["started_at"] = datetime.now().isoformat()
        self._state["completed_phases"] = []
        self._state["current_phase"] = None
        self._state["error"] = None
        self.save()

    def phase_start(self, phase: str):
        """Mark a phase as started."""
        self._state["current_phase"] = phase
        self.save()

    def phase_complete(self, phase: str):
        """Mark a phase as completed."""
        if phase not in self._state["completed_phases"]:
            self._state["completed_phases"].append(phase)
        self._state["current_phase"] = None
        self.save()

    def set_error(self, error: str):
        """Record an error."""
        self._state["error"] = error
        self.save()

    def is_completed(self, phase: str) -> bool:
        """Check if a phase was already completed."""
        return phase in self._state["completed_phases"]

    def has_partial_run(self) -> bool:
        """Check if there's a previous incomplete scan in this workspace."""
        return len(self._state.get("completed_phases", [])) > 0

    def resume_from(self, phases: list) -> list:
        """Return phases that still need to run (skip completed ones)."""
        completed = self._state.get("completed_phases", [])
        return [p for p in phases if p[0] not in completed]

    @property
    def completed(self) -> list:
        return self._state.get("completed_phases", [])

    @property
    def target_url(self) -> str:
        return self._state.get("target_url", "")

    def __repr__(self):
        done = ", ".join(self._state.get("completed_phases", [])) or "none"
        return f"<PipelineState phases_done={done}>"
