"""Packaging and bootstrap tests for the suvari project.

These verify that a clean checkout is importable, the MCP SDK is pinned to the
1.x API the code targets, and the MCP server registers tools and logs its
readiness line.
"""

import importlib
import importlib.metadata
import logging
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent


def test_suvari_importable() -> None:
    import suvari

    assert suvari.__name__ == "suvari"


def test_mcp_sdk_is_v1() -> None:
    import mcp

    version = getattr(mcp, "__version__", None)
    if version is None:
        version = importlib.metadata.version("mcp")
    major = int(version.split(".")[0])
    assert major < 2


def test_requirements_pins_mcp_below_2() -> None:
    requirements = (_REPO_ROOT / "requirements.txt").read_text()
    pattern = re.compile(r"^mcp>=1\.\d+,\s*<2$")
    matches = [line for line in requirements.splitlines() if pattern.match(line.strip())]
    assert matches, "requirements.txt must pin mcp to the 1.x API (mcp>=1.N,<2)"


def test_fastmcp_server_registers_tools() -> None:
    import suvari.mcp_server as mcp_server

    if not mcp_server.all_tools:
        pytest.skip("host has no security tools available")
    assert len(mcp_server.all_tools) >= 1
    for name in mcp_server.all_tools:
        assert isinstance(name, str) and name


def test_mcp_ready_message_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    import suvari.mcp_server as mcp_server

    with caplog.at_level(logging.INFO, logger="suvari.mcp"):
        importlib.reload(mcp_server)

    assert any(
        record.getMessage().startswith("MCP ready:") for record in caplog.records
    )
