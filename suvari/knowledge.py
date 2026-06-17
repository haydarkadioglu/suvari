"""
Knowledge — lightweight knowledge graph and failure attribution.
Inspired by PentAGI's graph store and LuaN1aoAgent's failure attribution.

Uses in-memory NetworkX graph (no SQLite/Neo4j needed for lightweight use).
"""

from enum import Enum
from typing import Optional, Any

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


class FailureLevel(Enum):
    """Failure classification levels (LuaN1aoAgent-inspired)."""
    L1_TOOL_NOT_FOUND = "tool_not_found"      # Tool not installed
    L2_PERMISSION = "permission_denied"        # No permission to run
    L3_NETWORK_TIMEOUT = "network_timeout"     # Connection/timeout issues
    L4_LLM_ERROR = "llm_error"                 # LLM hallucination/parse error
    L5_EMPTY_RESULT = "empty_result"           # Tool ran but nothing found
    L6_UNKNOWN = "unknown"                     # Unclassified


class KnowledgeGraph:
    """Lightweight graph for tracking hosts, services, vulnerabilities.
    
    Nodes represent entities (host, port, service, vuln, tool).
    Edges represent relationships (runs_on, has_vuln, scanned_by).
    
    Uses NetworkX if available, otherwise a simple dict-based fallback.
    """

    def __init__(self):
        if HAS_NETWORKX:
            self._graph = nx.MultiDiGraph()
            self._using_nx = True
        else:
            self._nodes = {}  # id -> data
            self._edges = []  # (from_id, to_id, relation, data)
            self._using_nx = False

    def add_node(self, node_id: str, node_type: str, **attrs):
        """Add or update a node."""
        attrs["type"] = node_type
        if self._using_nx:
            if node_id not in self._graph:
                self._graph.add_node(node_id, **attrs)
            else:
                for k, v in attrs.items():
                    self._graph.nodes[node_id][k] = v
        else:
            if node_id not in self._nodes:
                self._nodes[node_id] = attrs
            else:
                self._nodes[node_id].update(attrs)

    def add_edge(self, from_id: str, to_id: str, relation: str, **attrs):
        """Add a relationship between two nodes."""
        attrs["relation"] = relation
        if self._using_nx:
            self._graph.add_edge(from_id, to_id, **attrs)
        else:
            self._edges.append((from_id, to_id, relation, attrs))

    def add_host(self, host: str):
        """Record a host."""
        self.add_node(f"host:{host}", "host", host=host)

    def add_port(self, host: str, port: int, service: str = ""):
        """Record an open port on a host."""
        port_id = f"port:{host}:{port}"
        self.add_node(port_id, "port", port=port, service=service)
        self.add_edge(f"host:{host}", port_id, "has_port")

    def add_service(self, host: str, port: int, name: str, version: str = ""):
        """Record a service running on a port."""
        service_id = f"service:{host}:{port}:{name}"
        self.add_node(service_id, "service", name=name, version=version)
        self.add_edge(f"port:{host}:{port}", service_id, "runs")

    def add_vuln(self, location: str, vuln_type: str, severity: str, description: str = ""):
        """Record a vulnerability finding."""
        vuln_id = f"vuln:{vuln_type}:{hash(location)}"
        self.add_node(vuln_id, "vulnerability",
                      type=vuln_type, severity=severity,
                      location=location, description=description[:100])
        self.add_edge(f"host:{location.split('/')[0]}" if "/" in location else "target",
                      vuln_id, "has_vuln")

    def get_hosts(self) -> list:
        """List all discovered hosts."""
        if self._using_nx:
            return [n for n, d in self._graph.nodes(data=True) if d.get("type") == "host"]
        return [n for n, d in self._nodes.items() if d.get("type") == "host"]

    def get_vulns(self) -> list:
        """List all vulnerabilities."""
        if self._using_nx:
            return [{"id": n, **d}
                    for n, d in self._graph.nodes(data=True)
                    if d.get("type") == "vulnerability"]
        return [{"id": n, **d} for n, d in self._nodes.items() if d.get("type") == "vulnerability"]

    def summary(self) -> str:
        """Get a text summary of the graph."""
        if self._using_nx:
            hosts = len(self.get_hosts())
            vulns = len(self.get_vulns())
            edges = self._graph.number_of_edges()
            nodes = self._graph.number_of_nodes()
        else:
            hosts = len([n for n in self._nodes.values() if n.get("type") == "host"])
            vulns = len([n for n in self._nodes.values() if n.get("type") == "vulnerability"])
            nodes = len(self._nodes)
            edges = len(self._edges)
        return f"Graph: {nodes} nodes, {edges} edges, {hosts} hosts, {vulns} vulns"

    def to_dict(self) -> dict:
        """Export to serializable dict."""
        if self._using_nx:
            nodes = [{"id": n, **d} for n, d in self._graph.nodes(data=True)]
            edges = [{"from": u, "to": v, **d}
                     for u, v, d in self._graph.edges(data=True)]
        else:
            nodes = [{"id": n, **d} for n, d in self._nodes.items()]
            edges = [{"from": u, "to": v, **d} for u, v, _, d in self._edges]
        return {"nodes": nodes, "edges": edges}


def classify_failure(error_msg: str, tool_name: str = "") -> FailureLevel:
    """Classify a failure into a level for adaptive retry."""
    err = error_msg.lower()
    if not error_msg or error_msg.startswith("(empty)"):
        return FailureLevel.L5_EMPTY_RESULT
    if "not found" in err or "no such" in err:
        return FailureLevel.L1_TOOL_NOT_FOUND
    if "permission" in err or "denied" in err or "forbidden" in err:
        return FailureLevel.L2_PERMISSION
    if "timeout" in err or "timed out" in err or "connection" in err:
        return FailureLevel.L3_NETWORK_TIMEOUT
    if "parse" in err or "json" in err or "hallucinat" in err:
        return FailureLevel.L4_LLM_ERROR
    return FailureLevel.L6_UNKNOWN


def get_failure_strategy(level: FailureLevel) -> str:
    """Get the recommended recovery strategy for a failure level."""
    strategies = {
        FailureLevel.L1_TOOL_NOT_FOUND: "Install the tool or use alternative",
        FailureLevel.L2_PERMISSION: "Run with elevated privileges or check file permissions",
        FailureLevel.L3_NETWORK_TIMEOUT: "Increase timeout or retry with longer delay",
        FailureLevel.L4_LLM_ERROR: "Simplify the prompt or retry with lower temperature",
        FailureLevel.L5_EMPTY_RESULT: "Accept result (empty is valid), move to next phase",
        FailureLevel.L6_UNKNOWN: "Report error and continue with next available action",
    }
    return strategies.get(level, "Unknown failure, skipping")
