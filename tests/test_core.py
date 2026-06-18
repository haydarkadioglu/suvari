# Suvari test suite
# Run with: pytest -v tests/
"""
Tests for Suvari core modules.
"""

import pytest


class TestFailure:
    """Test failure attribution."""

    def test_classify_success(self):
        from suvari.failure import classify_failure, FailureLevel
        level = classify_failure("curl", "HTTP/2 200\nserver: nginx", 0.5)
        assert level == FailureLevel.L0_OBSERVATION

    def test_classify_tool_not_found(self):
        from suvari.failure import classify_failure, FailureLevel
        level = classify_failure("nmap", "(error: command not found)", 0.1)
        assert level == FailureLevel.L1_TOOL_ERROR

    def test_classify_permission(self):
        from suvari.failure import classify_failure, FailureLevel
        level = classify_failure("curl", "403 Forbidden", 0.3)
        assert level == FailureLevel.L2_PREREQUISITE

    def test_classify_cloudflare(self):
        from suvari.failure import classify_failure, FailureLevel
        level = classify_failure("nmap", "CloudFlare detected", 1.0)
        assert level == FailureLevel.L3_ENVIRONMENT

    def test_classify_404(self):
        from suvari.failure import classify_failure, FailureLevel
        level = classify_failure("curl", "HTTP/1.1 404 Not Found", 0.2)
        assert level == FailureLevel.L4_HYPOTHESIS


class TestWorkspace:
    """Test workspace operations."""

    def test_create(self, tmp_path):
        from suvari.workspace import Workspace
        ws = Workspace("test-scan", tmp_path)
        assert ws.path.exists()
        assert (ws.path / "recon").exists()
        assert (ws.path / "scans").exists()

    def test_save_result(self, tmp_path):
        from suvari.workspace import Workspace
        ws = Workspace("test-result", tmp_path)
        ws.save_result("scans", "nmap", "port 80 open")
        f = ws.path / "scans" / "nmap.txt"
        assert f.exists()
        assert f.read_text() == "port 80 open"

    def test_save_json(self, tmp_path):
        from suvari.workspace import Workspace
        ws = Workspace("test-json", tmp_path)
        ws.save_json("analysis", "test", {"key": "value"})
        f = ws.path / "analysis" / "test.json"
        assert f.exists()
        import json
        assert json.loads(f.read_text()) == {"key": "value"}


class TestAttackChain:
    """Test attack chain discovery."""

    def test_empty_findings(self):
        from suvari.attack_chain import AttackChain
        chain = AttackChain()
        result = chain.discover([])
        assert result == []

    def test_cors_chain(self):
        from suvari.attack_chain import AttackChain
        chain = AttackChain()
        findings = [
            {"type": "CORS Misconfiguration", "severity": "HIGH"},
            {"type": "Session Cookie", "severity": "MEDIUM"},
            {"type": "Login Form", "severity": "INFO"},
        ]
        result = chain.discover(findings)
        cors_chains = [c for c in result if "CORS" in c["chain"]]
        assert len(cors_chains) > 0

    def test_env_db_chain(self):
        from suvari.attack_chain import AttackChain
        chain = AttackChain()
        findings = [
            {"type": ".env File Exposure", "severity": "CRITICAL"},
            {"type": "Open Database Port", "severity": "HIGH"},
        ]
        result = chain.discover(findings)
        db_chains = [c for c in result if "Database" in c["chain"]]
        assert len(db_chains) > 0
