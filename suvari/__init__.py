"""
Suvari — AI-powered black-box web pentester.
"""

from .cli import app
from .llm import LLMClient
from .workspace import Workspace
from .tools.runner import ToolRunner
from .orchestrator import SuvariOrchestrator
from .agents.base import BaseAgent, AgentManager
from .agents.scanner import ScannerAgent
from .agents.recon import ReconAgent
from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .agents.bugbounty import BugBountyAgent
from .attack_chain import AttackChain
from .chain import CausalChain, CausalStep
from .failure import FailureLevel, classify_failure, get_recovery_strategy
from .browser import BrowserAgent
from .jwt_analysis import analyze_jwt
from .cve_intel import query_cve_api, extract_versions

__all__ = [
    "app", "LLMClient", "Workspace", "ToolRunner",
    "SuvariOrchestrator",
    "BaseAgent", "AgentManager",
    "ScannerAgent", "ReconAgent", "AnalyzerAgent",
    "ExploiterAgent", "BugBountyAgent",
    "AttackChain", "CausalChain", "CausalStep",
    "FailureLevel", "classify_failure", "get_recovery_strategy",
    "BrowserAgent", "analyze_jwt", "query_cve_api", "extract_versions",
]
