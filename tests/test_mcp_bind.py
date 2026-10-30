"""S-03: the MCP server binds loopback by default and keeps DNS-rebinding protection on."""

import inspect
import logging
from pathlib import Path

import pytest

from suvari import mcp_server
from suvari.mcp_server import (
    build_transport_security,
    default_host,
    default_port,
    is_loopback_host,
    mcp,
    run_server,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
LOOPBACK_HOSTS = ("127.0.0.1:*", "localhost:*", "[::1]:*")
LOOPBACK_ORIGINS = ("http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*")


def test_run_server_defaults_to_loopback():
    assert inspect.signature(run_server).parameters["host"].default == "127.0.0.1"


def test_default_host_is_loopback_when_env_unset(monkeypatch):
    monkeypatch.delenv("MCP_HOST", raising=False)
    assert default_host() == "127.0.0.1"


def test_default_host_falls_back_to_loopback_when_env_empty(monkeypatch):
    monkeypatch.setenv("MCP_HOST", "")
    assert default_host() == "127.0.0.1"


def test_env_overrides_host_and_port(monkeypatch):
    monkeypatch.setenv("MCP_HOST", "10.1.2.3")
    monkeypatch.setenv("MCP_PORT", "9000")
    assert default_host() == "10.1.2.3"
    assert default_port() == 9000


def test_default_port_when_env_unset(monkeypatch):
    monkeypatch.delenv("MCP_PORT", raising=False)
    assert default_port() == 8000


def test_transport_security_for_loopback_host():
    settings = build_transport_security("127.0.0.1")
    assert settings.enable_dns_rebinding_protection is True
    assert settings.allowed_hosts == list(LOOPBACK_HOSTS)
    assert settings.allowed_origins == list(LOOPBACK_ORIGINS)


@pytest.mark.parametrize("host", ["0.0.0.0", "10.1.2.3", "example.com"])
def test_transport_security_for_non_loopback_host(host):
    settings = build_transport_security(host)
    assert settings.enable_dns_rebinding_protection is True
    assert set(LOOPBACK_HOSTS) <= set(settings.allowed_hosts)
    assert set(LOOPBACK_ORIGINS) <= set(settings.allowed_origins)
    assert f"{host}:*" in settings.allowed_hosts
    assert f"http://{host}:*" in settings.allowed_origins


def test_transport_security_allows_non_standard_loopback_address():
    settings = build_transport_security("127.0.0.5")
    assert "127.0.0.5:*" in settings.allowed_hosts
    assert "http://127.0.0.5:*" in settings.allowed_origins


def test_transport_security_brackets_ipv6_host():
    settings = build_transport_security("2001:db8::1")
    assert "[2001:db8::1]:*" in settings.allowed_hosts
    assert "http://[2001:db8::1]:*" in settings.allowed_origins


def test_transport_security_does_not_duplicate_loopback_patterns():
    for host in ("localhost", "::1"):
        assert build_transport_security(host).allowed_hosts == list(LOOPBACK_HOSTS)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("::1", True),
        ("[::1]", True),
        ("127.0.0.5", True),
        ("0.0.0.0", False),
        ("::", False),
        ("10.1.2.3", False),
        ("example.com", False),
        ("127.0.0.1.example.com", False),
        ("", False),
    ],
)
def test_is_loopback_host(host, expected):
    assert is_loopback_host(host) is expected


def test_module_level_mcp_keeps_dns_rebinding_protection():
    settings = mcp.settings.transport_security
    assert settings.enable_dns_rebinding_protection is True
    assert set(LOOPBACK_HOSTS) <= set(settings.allowed_hosts)
    assert set(LOOPBACK_ORIGINS) <= set(settings.allowed_origins)


@pytest.mark.parametrize("path", ["suvari_mcp.py", "suvari/mcp_server.py"])
def test_entry_points_have_no_wildcard_default(path):
    assert 'default="0.0.0.0"' not in (REPO_ROOT / path).read_text()


@pytest.fixture
def stubbed_run(monkeypatch):
    """Stop run_server before it starts uvicorn and undo its global changes."""
    monkeypatch.setattr(mcp, "run", lambda transport: None)
    for name in ("host", "port", "transport_security"):
        monkeypatch.setattr(mcp.settings, name, getattr(mcp.settings, name))
    server_logger = logging.getLogger("mcp.server.server")
    monkeypatch.setattr(server_logger, "info", server_logger.info)
    mcp_logger = logging.getLogger("mcp")
    level = mcp_logger.level
    yield
    mcp_logger.setLevel(level)
    if hasattr(mcp, "_orig_log"):
        del mcp._orig_log


def test_run_server_warns_and_allows_host_on_network_bind(stubbed_run, caplog):
    with caplog.at_level(logging.WARNING, logger=mcp_server.logger.name):
        run_server(host="10.1.2.3", port=8000)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "REACHABLE FROM THE NETWORK" in warnings[0]
    assert "NO AUTHENTICATION" in warnings[0]
    assert "10.1.2.3:*" in mcp.settings.transport_security.allowed_hosts
    assert mcp.settings.transport_security.enable_dns_rebinding_protection is True


def test_run_server_is_quiet_on_loopback_bind(stubbed_run, caplog):
    with caplog.at_level(logging.WARNING, logger=mcp_server.logger.name):
        run_server()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert mcp.settings.host == "127.0.0.1"


@pytest.mark.parametrize(
    ("host", "expected"),
    [("0.0.0.0", True), ("::", True), ("[::]", True), ("127.0.0.1", False),
     ("10.1.2.3", False), ("localhost", False)],
)
def test_is_wildcard_host(host, expected):
    assert mcp_server.is_wildcard_host(host) is expected


def test_run_server_warns_about_host_validation_on_wildcard_bind(stubbed_run, caplog):
    with caplog.at_level(logging.WARNING, logger=mcp_server.logger.name):
        run_server(host="0.0.0.0", port=8000)
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(messages) == 2
    assert "REACHABLE FROM THE NETWORK" in messages[0]
    assert "421 Invalid Host header" in messages[1]
