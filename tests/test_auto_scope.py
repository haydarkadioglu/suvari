"""Scope parsing and enforcement — no network except a loopback canary."""

import ipaddress

import pytest

from suvari.auto.executor import Executor, RateLimiter
from suvari.auto.scope import (
    Scope, ScopeError, expand_target, expand_targets, read_spec_file,
)


def _no_dns(host):
    raise AssertionError(f"DNS must not be queried for {host!r}")


# ── target parsing ───────────────────────────────────────────────────────

def test_url_target_keeps_scheme_port_and_path():
    [t] = expand_target("https://Example.com/app/")
    assert t.url == "https://example.com/app/"
    assert (t.host, t.port) == ("example.com", 443)
    [t] = expand_target("http://10.0.0.1:8080")
    assert t.url == "http://10.0.0.1:8080/" and t.port == 8080


def test_host_port_and_bare_ip():
    [t] = expand_target("127.0.0.1:8091")
    assert t.url == "http://127.0.0.1:8091/"
    assert t.key == "127.0.0.1_8091"
    [t] = expand_target("intranet.local:8443")
    assert t.url == "https://intranet.local:8443/"
    [t] = expand_target("1.2.3.4")
    assert t.url == "http://1.2.3.4/" and t.port == 80


def test_cidr_expands_to_host_addresses():
    ts = expand_target("192.168.1.0/30")
    assert [t.host for t in ts] == ["192.168.1.1", "192.168.1.2"]
    assert len(expand_target("192.168.1.0/24")) == 254
    assert [t.host for t in expand_target("10.9.9.9/32")] == ["10.9.9.9"]


def test_ip_range_full_and_short_form():
    full = expand_target("10.0.0.5-10.0.0.20")
    assert len(full) == 16
    assert full[0].host == "10.0.0.5" and full[-1].host == "10.0.0.20"
    short = expand_target("10.0.0.5-20")
    assert [t.host for t in short] == [t.host for t in full]
    with pytest.raises(ScopeError):
        expand_target("10.0.0.20-10.0.0.5")


def test_ipv6_target():
    [t] = expand_target("[::1]:8080")
    assert t.url == "http://[::1]:8080/" and t.host == "::1"


def test_invalid_inputs_rejected():
    for bad in ("ftp://host/", "10.0.0.0/33", "host:99999", "bad host!", "http://"):
        with pytest.raises(ScopeError):
            expand_target(bad)


def test_expand_targets_dedupes_and_reads_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# lab hosts\n127.0.0.1:8091\n\n127.0.0.1:8093  # trainer\n127.0.0.1:8091\n")
    specs = read_spec_file(f)
    assert specs == ["127.0.0.1:8091", "127.0.0.1:8093", "127.0.0.1:8091"]
    ts = expand_targets(specs)
    assert [t.port for t in ts] == [8091, 8093]


# ── large scope ──────────────────────────────────────────────────────────

def test_wider_than_slash24_is_refused_without_flag():
    with pytest.raises(ScopeError, match="allow-large-scope"):
        expand_target("10.0.0.0/23")
    with pytest.raises(ScopeError, match="allow-large-scope"):
        Scope(["10.0.0.0/16"], resolver=_no_dns)
    with pytest.raises(ScopeError, match="allow-large-scope"):
        expand_target("10.0.0.1-10.0.1.10")


def test_large_scope_allowed_with_flag_and_warns(caplog):
    with caplog.at_level("WARNING"):
        ts = expand_target("10.0.0.0/23", allow_large=True)
    assert len(ts) == 510
    assert "large scope" in caplog.text
    s = Scope(["10.0.0.0/16"], allow_large=True, resolver=_no_dns)
    assert s.is_allowed("10.0.200.1")


# ── membership ───────────────────────────────────────────────────────────

def test_cidr_scope_in_and_out_without_dns():
    s = Scope(["192.168.1.0/24"], resolver=_no_dns)
    assert s.is_allowed("192.168.1.77")
    assert s.is_allowed("http://192.168.1.77:8080/admin")   # CIDR: any port
    assert not s.is_allowed("192.168.2.1")
    assert not s.is_allowed("http://10.0.0.1/")


def test_port_bound_entries():
    s = Scope(["127.0.0.1:8091", "http://127.0.0.1:8093/"], resolver=_no_dns)
    assert s.is_allowed("http://127.0.0.1:8091/x")
    assert s.is_allowed("http://127.0.0.1:8093/")
    assert not s.is_allowed("http://127.0.0.1:8092/")
    assert not s.is_allowed("http://127.0.0.1/")


def test_range_scope():
    s = Scope(["10.0.0.5-10.0.0.20"], resolver=_no_dns)
    assert s.is_allowed("10.0.0.5") and s.is_allowed("10.0.0.20")
    assert not s.is_allowed("10.0.0.4") and not s.is_allowed("10.0.0.21")


def test_hostname_entry_and_dns_resolution():
    calls = []

    def resolver(host):
        calls.append(host)
        return {"printer.lan": ["192.168.1.5"], "evil.example": ["8.8.8.8"]}.get(host, [])

    s = Scope(["https://app.example.com", "192.168.1.0/24"], resolver=resolver)
    # listed by name: no DNS needed, port implied by the scheme
    assert s.is_allowed("https://app.example.com/login")
    assert not s.is_allowed("http://app.example.com:8080/")
    assert calls == ["app.example.com"]  # the off-port check fell through to DNS
    # unlisted name resolving into an allowed network
    assert s.is_allowed("http://printer.lan/")
    # unlisted name resolving outside
    reason = s.check("http://evil.example/")
    assert reason and "outside scope" in reason
    # unresolvable
    assert not s.is_allowed("http://nowhere.invalid/")


def test_non_http_scheme_is_out_of_scope():
    s = Scope(["127.0.0.1"], resolver=_no_dns)
    assert not s.is_allowed("file:///etc/passwd")
    assert not s.is_allowed("gopher://127.0.0.1/")


# ── enforcement in the executor ──────────────────────────────────────────

def test_executor_never_sends_out_of_scope(make_server):
    canary, canary_url = make_server()
    scope = Scope(["127.0.0.1:1"], resolver=_no_dns)  # canary port not included
    port = int(canary_url.rsplit(":", 1)[1])
    # even with the canary host:port as the executor's own host, the job scope wins
    ex = Executor([f"127.0.0.1:{port}"], scope=scope, limiter=RateLimiter(6000))
    res = ex.http_probe(canary_url + "/")
    assert res.ok is False and "out-of-scope" in res.error
    ok, why = ex.tcp_reachable(canary_url + "/")
    assert not ok and "out-of-scope" in why
    assert canary.hits == []
    assert [b["source"] for b in scope.blocked] == ["http_probe", "reachability"]
    assert ex.limiter.count == 0  # refused requests do not consume budget


def test_rate_limiter_is_global_and_enforces_budget():
    now = [0.0]
    slept = []

    def sleep(d):
        slept.append(d)
        now[0] += d

    lim = RateLimiter(rate_per_min=60, max_requests=3, clock=lambda: now[0], sleep=sleep)
    assert lim.acquire() and lim.acquire() and lim.acquire()
    assert not lim.acquire()
    assert lim.exhausted() and lim.count == 3
    assert slept == [1.0, 1.0]
