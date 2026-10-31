"""S-04: the MCP server requires a bearer token and refuses unauthenticated network binds."""

import asyncio
import json
import logging

import pytest
from starlette.testclient import TestClient

from suvari import mcp_server
from suvari.mcp_server import (
    BearerTokenMiddleware,
    mcp,
    resolve_token,
    run_server,
    validate_bind,
)

TOKEN = "s3cret"
TOKEN_ENV = "SUVARI_MCP_TOKEN"


class _FakeApp:
    """Inner ASGI app that records whether it was reached."""

    def __init__(self) -> None:
        self.called = False
        self.scope = None

    async def __call__(self, scope, receive, send) -> None:
        self.called = True
        self.scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _http_scope(*headers) -> dict:
    return {"type": "http", "headers": list(headers), "client": ("127.0.0.1", 1234)}


def _call(scope: dict) -> tuple[_FakeApp, list[dict]]:
    """Run ``scope`` through the middleware; return the inner app and the sent messages."""
    inner = _FakeApp()
    sent = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(BearerTokenMiddleware(inner, TOKEN)(scope, receive, send))
    return inner, sent


def _assert_rejected(inner: _FakeApp, sent: list[dict]) -> None:
    assert inner.called is False
    assert sent[0]["status"] == 401


# ── resolve_token ──────────────────────────────────────────────────────────


def test_resolve_token_argument_wins_over_env(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "from-env")
    assert resolve_token("from-arg") == "from-arg"


def test_resolve_token_reads_env(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "from-env")
    assert resolve_token() == "from-env"


def test_resolve_token_treats_blank_as_disabled(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "   ")
    assert resolve_token("  ") is None
    assert resolve_token() is None


def test_resolve_token_is_none_when_unset(monkeypatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    assert resolve_token() is None


# ── validate_bind ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_bind_without_token_is_allowed(host):
    validate_bind(host, None)


@pytest.mark.parametrize("host", ["10.1.2.3", "0.0.0.0", "::", "example.com", ""])
def test_non_loopback_bind_without_token_is_rejected(host):
    with pytest.raises(ValueError) as excinfo:
        validate_bind(host, None)
    assert "--token" in str(excinfo.value)
    assert TOKEN_ENV in str(excinfo.value)


def test_non_loopback_bind_with_token_is_allowed():
    validate_bind("10.1.2.3", TOKEN)


# ── BearerTokenMiddleware ──────────────────────────────────────────────────


def test_missing_authorization_header_returns_401():
    _assert_rejected(*_call(_http_scope()))


def test_wrong_token_returns_401():
    _assert_rejected(*_call(_http_scope((b"authorization", b"Bearer wrong"))))


def test_prefix_of_token_returns_401():
    _assert_rejected(*_call(_http_scope((b"authorization", b"Bearer s3cre"))))


def test_scheme_without_token_returns_401():
    _assert_rejected(*_call(_http_scope((b"authorization", b"Bearer "))))


def test_non_bearer_scheme_returns_401():
    _assert_rejected(*_call(_http_scope((b"authorization", b"Basic s3cret"))))


def test_correct_token_reaches_the_wrapped_app():
    inner, sent = _call(_http_scope((b"authorization", b"Bearer s3cret")))
    assert inner.called is True
    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"ok"


@pytest.mark.parametrize("scheme", [b"bearer", b"BEARER", b"BeArEr"])
def test_bearer_scheme_is_case_insensitive(scheme):
    inner, _ = _call(_http_scope((b"authorization", scheme + b" s3cret")))
    assert inner.called is True


def test_header_name_is_case_insensitive():
    inner, _ = _call(_http_scope((b"Authorization", b"Bearer s3cret")))
    assert inner.called is True


def test_401_response_has_www_authenticate_header():
    _, sent = _call(_http_scope())
    headers = dict(sent[0]["headers"])
    assert headers[b"www-authenticate"] == b'Bearer realm="suvari"'
    assert headers[b"content-type"] == b"application/json"
    assert json.loads(sent[1]["body"]) == {
        "error": "unauthorized",
        "detail": "missing or invalid bearer token",
    }


def test_rejection_is_logged_once_without_the_presented_token(caplog):
    with caplog.at_level(logging.WARNING, logger="suvari.mcp"):
        _call(_http_scope((b"authorization", b"Bearer not-the-token")))
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert "127.0.0.1" in caplog.text
    assert "not-the-token" not in caplog.text


def test_lifespan_scope_passes_through():
    scope = {"type": "lifespan"}
    inner, _ = _call(scope)
    assert inner.called is True
    assert inner.scope is scope


def test_empty_token_is_rejected_at_construction():
    with pytest.raises(ValueError):
        BearerTokenMiddleware(_FakeApp(), "")


# ── Integration ────────────────────────────────────────────────────────────


@pytest.fixture
def served_apps(monkeypatch):
    """Record what run_server hands to uvicorn and undo its global changes."""
    apps = []
    monkeypatch.setattr(mcp_server.uvicorn, "run", lambda app, **kwargs: apps.append(app))
    monkeypatch.setattr(mcp, "_session_manager", None)
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    for name in ("host", "port", "transport_security"):
        monkeypatch.setattr(mcp.settings, name, getattr(mcp.settings, name))
    server_logger = logging.getLogger("mcp.server.server")
    monkeypatch.setattr(server_logger, "info", server_logger.info)
    mcp_logger = logging.getLogger("mcp")
    level = mcp_logger.level
    yield apps
    mcp_logger.setLevel(level)
    if hasattr(mcp, "_orig_log"):
        del mcp._orig_log


def test_streamable_http_app_requires_the_token(monkeypatch):
    # The session manager only runs once per instance, so this test gets its own
    monkeypatch.setattr(mcp, "_session_manager", None)
    app = BearerTokenMiddleware(mcp.streamable_http_app(), TOKEN)
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }
    accept = {"Accept": "application/json, text/event-stream"}
    # DNS-rebinding protection rejects TestClient's default "testserver" Host
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        rejected = client.post("/mcp", json=payload, headers=accept)
        accepted = client.post(
            "/mcp", json=payload, headers={**accept, "Authorization": f"Bearer {TOKEN}"}
        )
    assert rejected.status_code == 401
    assert accepted.status_code == 200


def test_run_server_refuses_network_bind_without_token(served_apps):
    with pytest.raises(ValueError, match="--token"):
        run_server(host="10.1.2.3")
    assert served_apps == []


def test_run_server_serves_wrapped_app_with_token(served_apps, capsys):
    run_server(host="10.1.2.3", token=TOKEN)
    assert isinstance(served_apps[0], BearerTokenMiddleware)
    assert "(auth: bearer token)" in capsys.readouterr().out
    # The app must be built after the bind address is added to the allowed hosts
    assert "10.1.2.3:*" in mcp.session_manager.security_settings.allowed_hosts


def test_run_server_reads_token_from_env(served_apps, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    run_server(host="10.1.2.3")
    assert isinstance(served_apps[0], BearerTokenMiddleware)


def test_run_server_serves_bare_app_on_loopback_without_token(served_apps, capsys):
    run_server()
    assert not isinstance(served_apps[0], BearerTokenMiddleware)
    assert "auth:" not in capsys.readouterr().out
