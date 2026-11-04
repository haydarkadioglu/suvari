"""S-08: MCP tool calls are logged where they run, without patching mcp's logger."""

import logging

import pytest

from suvari import mcp_server
from suvari.mcp_server import mcp, run_server


class StubRunner:
    def __init__(self, error: Exception | None = None):
        self.error = error

    def available_tools(self):
        return {"curl": "transfer a URL"}

    def run(self, cmd, timeout=120):
        if self.error is not None:
            raise self.error
        return "stub output"


@pytest.fixture
def stub_runner(monkeypatch):
    stub = StubRunner()
    monkeypatch.setattr(mcp_server, "_get_runner", lambda: stub)
    return stub


def test_tool_call_logs_info_and_returns_output(stub_runner, caplog):
    fn = mcp_server._make_tool_fn("curl")
    with caplog.at_level(logging.INFO, logger="suvari.mcp"):
        out = fn(target="http://example.test")

    assert out == "[curl] http://example.test\n\nstub output"
    infos = [r for r in caplog.records
             if r.name == "suvari.mcp" and r.levelno == logging.INFO]
    assert len(infos) == 1
    assert "curl" in infos[0].getMessage()
    assert "http://example.test" in infos[0].getMessage()


def test_tool_failure_logs_one_warning_and_keeps_error_text(stub_runner, caplog):
    stub_runner.error = RuntimeError("binary crashed")
    fn = mcp_server._make_tool_fn("curl")
    with caplog.at_level(logging.INFO, logger="suvari.mcp"):
        out = fn(target="http://example.test")

    assert out == "[curl] error: binary crashed"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "curl" in warnings[0].getMessage()
    assert "binary crashed" in warnings[0].getMessage()


@pytest.fixture
def stubbed_run(monkeypatch):
    """Stop run_server before it starts uvicorn and undo its global changes."""
    monkeypatch.setattr(mcp_server.uvicorn, "run", lambda app, **kwargs: None)
    monkeypatch.setattr(mcp, "_session_manager", None)
    monkeypatch.delenv("SUVARI_MCP_TOKEN", raising=False)
    for name in ("host", "port", "transport_security"):
        monkeypatch.setattr(mcp.settings, name, getattr(mcp.settings, name))
    calls = []
    monkeypatch.setattr(mcp_server, "configure_logging",
                        lambda *a, **k: calls.append((a, k)))
    yield calls


def test_run_server_does_not_monkeypatch_mcp_logger(stubbed_run):
    run_server(host="127.0.0.1", port=8000)

    assert not hasattr(mcp, "_orig_log")
    # An instance-level ``info`` attribute would shadow Logger.info
    assert "info" not in vars(logging.getLogger("mcp.server.server"))
    assert stubbed_run == [(("info",), {})]


def test_configure_logging_is_still_importable_from_mcp_server():
    from suvari.logging_setup import configure_logging
    assert mcp_server.__dict__["configure_logging"] is configure_logging
