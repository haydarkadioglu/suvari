"""
Findings Bus — real-time pub/sub for agent communication.
Agents publish findings as they discover them; other agents consume immediately.
"""

import threading
import json
from typing import Callable, Optional
from datetime import datetime


class FindingsBus:
    """Thread-safe pub/sub bus for agent findings."""

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[Callable]] = {}
        self._all_findings: list[dict] = []
        self._events = {"finding": threading.Event()}

    def publish(self, agent: str, finding: dict):
        """Publish a finding from an agent."""
        finding["_agent"] = agent
        finding["_ts"] = datetime.now().isoformat()
        with self._lock:
            self._all_findings.append(finding)
            self._events["finding"].set()
            self._events["finding"] = threading.Event()  # Reset for next
        # Notify subscribers
        for key, callbacks in self._subscribers.items():
            if key == "*" or self._matches(key, finding):
                for cb in callbacks:
                    try:
                        cb(agent, finding)
                    except Exception:
                        pass

    def subscribe(self, key: str, callback: Callable):
        """Subscribe to findings matching key (e.g. 'cve', 'port', 'vuln')."""
        with self._lock:
            self._subscribers.setdefault(key, []).append(callback)

    def wait_for_finding(self, timeout: float = 10) -> Optional[dict]:
        """Wait for the next finding (blocking)."""
        self._events["finding"].wait(timeout)
        with self._lock:
            if self._all_findings:
                return self._all_findings[-1]
        return None

    def get_all(self, agent: Optional[str] = None) -> list:
        """Get all findings, optionally filtered by agent."""
        with self._lock:
            if agent:
                return [f for f in self._all_findings if f.get("_agent") == agent]
            return list(self._all_findings)

    def _matches(self, key: str, finding: dict) -> bool:
        """Check if a finding matches a subscription key."""
        ftype = str(finding.get("type", "")).lower()
        fseverity = str(finding.get("severity", "")).lower()
        fagent = str(finding.get("_agent", "")).lower()
        return key in ftype or key in fseverity or key in fagent

    def summary(self) -> str:
        """Get a summary of all findings."""
        with self._lock:
            agents = set(f.get("_agent", "?") for f in self._all_findings)
            return f"{len(self._all_findings)} findings from {len(agents)} agents ({', '.join(agents)})"
