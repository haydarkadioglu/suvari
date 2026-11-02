"""Tests for known-vulnerability research (suvari.auto.research). No network."""

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from suvari.auto import research as R

FIX = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIX / name).read_text())


class FakeNet:
    """Routes GETs to fixtures; records every URL; can fail or rate-limit."""

    def __init__(self, nvd=None, kev=None, ghsa=None):
        self.nvd = nvd if nvd is not None else _load("nvd_sample.json")
        self.kev = kev if kev is not None else _load("kev_sample.json")
        self.ghsa = ghsa if ghsa is not None else _load("ghsa_sample.json")
        self.urls = []
        self.queue = []      # pre-canned (status, headers, body) responses
        self.offline = False

    def __call__(self, url, timeout):
        self.urls.append(url)
        if self.offline:
            raise OSError("network unreachable")
        if self.queue:
            return self.queue.pop(0)
        if url.startswith(R.KEV_URL):
            return 200, {}, json.dumps(self.kev).encode()
        if url.startswith(R.GHSA_URL):
            return 200, {}, json.dumps(self.ghsa).encode()
        if url.startswith(R.NVD_URL):
            return 200, {}, json.dumps(self.nvd).encode()
        return 404, {}, b""

    def count(self, prefix):
        return sum(1 for u in self.urls if u.startswith(prefix))


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def _researcher(tmp_path, net, clock=None, **kw):
    clock = clock or Clock()
    return R.Researcher(cache_dir=tmp_path / "cache", fetch=net, clock=clock,
                        monotonic=clock, sleep=clock.sleep, **kw)


# ── parsers ───────────────────────────────────────────────────────────────
def test_parse_nvd_extracts_fields_and_drops_rejected():
    cves = {c["id"]: c for c in R.parse_nvd(_load("nvd_sample.json"))}
    assert "CVE-2099-0001" not in cves                     # Rejected record
    mw = cves["CVE-2025-29927"]
    assert mw["cvss"] == 9.1 and mw["severity"] == "CRITICAL"
    assert mw["privileges_required"] == "NONE"
    assert mw["summary"].startswith("Next.js is a React framework")
    assert mw["source"] == "nvd" and mw["references"]
    assert {"product": "next.js", "vendor": "vercel",
            "start_incl": "15.0.0", "end_excl": "15.2.3"} in mw["ranges"]
    # another product's keyword hit keeps its own product name
    assert {r["product"] for r in cves["CVE-2021-21310"]["ranges"]} == {"next-auth"}


def test_parse_range_string_variants():
    assert R.parse_range_string(">= 13.0.0, < 13.5.8") == {
        "start_incl": "13.0.0", "end_excl": "13.5.8"}
    assert R.parse_range_string("<= 16.4.0") == {"end_incl": "16.4.0"}
    assert R.parse_range_string("= 1.2.3") == {"exact": "1.2.3"}
    assert R.parse_range_string("") == {}


def test_parse_ghsa_uses_cve_id_when_present():
    advs = R.parse_ghsa(_load("ghsa_sample.json"))
    ids = [a["id"] for a in advs]
    assert "CVE-2026-103004" in ids                # cve_id preferred
    assert "GHSA-673q-mjm6-r5xr" in ids            # no CVE yet -> GHSA id
    a = advs[0]
    assert a["cvss"] == 9.5 and a["severity"] == "CRITICAL"
    assert a["ranges"][0]["product"] == "next"
    assert a["privileges_required"] == "NONE"


# ── KEV ───────────────────────────────────────────────────────────────────
def test_kev_matching_marks_exploited_in_wild():
    cves = R.parse_nvd(_load("nvd_sample.json"))
    assert not any(c["exploited_in_wild"] for c in cves)    # fixture strips NVD's flag
    n = R.mark_kev(cves, R.index_kev(_load("kev_sample.json")))
    flagged = [c["id"] for c in cves if c["exploited_in_wild"]]
    assert flagged == ["CVE-2025-55182"] and n == 1


def test_research_applies_kev_and_downloads_feed_once(tmp_path):
    net = FakeNet()
    r = _researcher(tmp_path, net)
    res = r.research("nextjs")
    assert [c["id"] for c in res.cves if c["exploited_in_wild"]] == ["CVE-2025-55182"]
    r.research("nginx")
    assert net.count(R.KEV_URL) == 1


# ── queries ───────────────────────────────────────────────────────────────
def test_nvd_query_uses_cpe_when_known_and_keyword_otherwise(tmp_path):
    net = FakeNet()
    r = _researcher(tmp_path, net, sources=("nvd",))
    r.research("nextjs", "15.1.0")
    q = parse_qs(urlparse(net.urls[-1]).query)
    assert q["virtualMatchString"] == ["cpe:2.3:a:*:next.js:15.1.0"]
    assert q["resultsPerPage"] == ["20"]
    r.research("firebase")
    q = parse_qs(urlparse(net.urls[-1]).query)
    assert q["keywordSearch"] == ["firebase"]


def test_nvd_fetches_last_page_for_newest_records(tmp_path):
    page = _load("nvd_sample.json")
    page["totalResults"] = 45
    net = FakeNet(nvd=page)
    r = _researcher(tmp_path, net, sources=("nvd",))
    res = r.research("nextjs")
    nvd_urls = [u for u in net.urls if u.startswith(R.NVD_URL)]
    assert len(nvd_urls) == 2
    assert parse_qs(urlparse(nvd_urls[1]).query)["startIndex"] == ["25"]
    assert res.total_found == 45
    # newest first
    pub = [c["published"] for c in res.cves]
    assert pub == sorted(pub, reverse=True)


def test_unknown_tech_returns_empty_without_requests(tmp_path):
    net = FakeNet()
    res = _researcher(tmp_path, net).research("cloudflare")
    assert res.cves == [] and "no research profile" in res.error
    assert net.urls == []


def test_ghsa_source_merges_and_dedupes(tmp_path):
    net = FakeNet()
    r = _researcher(tmp_path, net, sources=("nvd", "ghsa"))
    res = r.research("nextjs")
    ids = [c["id"] for c in res.cves]
    assert len(ids) == len(set(ids))
    assert "GHSA-673q-mjm6-r5xr" in ids and "CVE-2025-29927" in ids
    q = parse_qs(urlparse(next(u for u in net.urls if u.startswith(R.GHSA_URL))).query)
    assert q == {"ecosystem": ["npm"], "affects": ["next"], "per_page": ["20"]}


# ── cache ─────────────────────────────────────────────────────────────────
def test_cache_hit_within_ttl_and_refetch_after_expiry(tmp_path):
    net, clock = FakeNet(), Clock()
    r = _researcher(tmp_path, net, clock, sources=("nvd",), ttl=86400)
    first = r.research("nextjs", "15.1.0")
    assert not first.from_cache and len(net.urls) == 1
    files = list((tmp_path / "cache").glob("*.json"))
    assert len(files) == 1 and len(files[0].stem) == 40          # sha1 name

    clock.t += 3600
    second = r.research("nextjs", "15.1.0")
    assert second.from_cache and len(net.urls) == 1
    assert [c["id"] for c in second.cves] == [c["id"] for c in first.cves]

    clock.t += 86400
    third = r.research("nextjs", "15.1.0")
    assert not third.from_cache and len(net.urls) == 2


# ── 429 / rate limits / budget ──────────────────────────────────────────────
def test_429_is_retried_after_retry_after(tmp_path):
    net, clock = FakeNet(), Clock()
    net.queue = [(429, {"Retry-After": "7"}, b""), (429, {}, b"")]
    r = _researcher(tmp_path, net, clock, sources=("nvd",))
    res = r.research("nextjs")
    assert res.cves and not res.error
    assert clock.slept == [7.0, 12.0]                # Retry-After, then 6s*2^1 backoff
    assert net.count(R.NVD_URL) == 3


def test_persistent_429_fails_open(tmp_path):
    net, clock = FakeNet(), Clock()
    net.queue = [(429, {}, b"")] * 10
    res = _researcher(tmp_path, net, clock, sources=("nvd",)).research("nextjs")
    assert res.cves == [] and "rate limited" in res.error


def test_nvd_window_limiter_allows_five_per_30s():
    clock = Clock(0.0)
    lim = R.WindowLimiter(5, 30.0, clock, clock.sleep)
    for _ in range(5):
        lim.acquire()
    assert clock.slept == []
    lim.acquire()
    assert clock.slept == [30.0]


def test_request_budget_is_enforced(tmp_path):
    net = FakeNet()
    r = _researcher(tmp_path, net, sources=("nvd",), max_requests=1)
    assert r.research("nextjs").cves
    res = r.research("nginx")
    assert res.cves == [] and "budget exhausted" in res.error
    assert r.requests_made == 1 and len(net.urls) == 1


# ── offline ────────────────────────────────────────────────────────────────
def test_offline_without_cache_fails_open(tmp_path):
    net = FakeNet()
    net.offline = True
    res = _researcher(tmp_path, net).research("nextjs", "15.1.0")
    assert res.cves == [] and not res.from_cache
    assert "network unreachable" in res.error


def test_offline_with_expired_cache_serves_stale(tmp_path):
    net, clock = FakeNet(), Clock()
    r = _researcher(tmp_path, net, clock, sources=("nvd",), ttl=60)
    fresh = r.research("nextjs")
    clock.t += 3600
    net.offline = True
    stale = _researcher(tmp_path, net, clock, sources=("nvd",), ttl=60).research("nextjs")
    assert stale.from_cache and stale.stale and "network unreachable" in stale.error
    assert [c["id"] for c in stale.cves] == [c["id"] for c in fresh.cves]


def test_kev_offline_uses_empty_index(tmp_path):
    net = FakeNet()
    net.offline = True
    assert _researcher(tmp_path, net).kev_index() == {}


def test_result_roundtrip():
    rr = R.ResearchResult("nginx", "1.24.0", cves=[{"id": "CVE-1"}], from_cache=True)
    assert R.ResearchResult.from_dict(rr.to_dict()) == rr


def test_from_config_reads_research_block():
    r = R.from_config({"sources": ["nvd"], "max_results": 5, "cache_ttl": 10})
    assert r.sources == ("nvd",) and r.max_results == 5 and r.ttl == 10
    assert r.max_requests == R.MAX_REQUESTS_PER_JOB


@pytest.mark.parametrize("bad", ["nvd", "kev"])
def test_only_get_requests_are_made(tmp_path, bad, monkeypatch):
    """The default fetcher builds GET requests only."""
    seen = []

    class Resp:
        status, headers = 200, {}
        def read(self):
            return b"{}"
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        seen.append(req.get_method())
        return Resp()

    monkeypatch.setattr(R.urllib.request, "urlopen", fake_urlopen)
    R._default_fetch(R.NVD_URL if bad == "nvd" else R.KEV_URL, 5)
    assert seen == ["GET"]
