"""Shared fixtures for the auto-loop tests."""

import importlib.util
from pathlib import Path

import pytest

_FIXTURE = Path(__file__).parent / "fixtures" / "vuln_server.py"


def _load_vuln_server():
    spec = importlib.util.spec_from_file_location("vuln_server", _FIXTURE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def vuln_server():
    """Start the deliberately-vulnerable localhost server for the session."""
    mod = _load_vuln_server()
    httpd, base_url, _thread = mod.serve(0)
    yield base_url
    httpd.shutdown()


@pytest.fixture()
def make_server():
    """Factory: start extra vuln servers (``port=0`` = ephemeral) for one test."""
    mod = _load_vuln_server()
    started = []

    def _make(port: int = 0):
        httpd, base_url, _ = mod.serve(port)
        started.append(httpd)
        return httpd, base_url

    yield _make
    for httpd in started:
        httpd.shutdown()
        httpd.server_close()
