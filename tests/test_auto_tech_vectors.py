"""Tests for the technology-aware hypothesis bank (suvari.auto.tech_vectors)."""

from suvari.auto.executor import ExecResult
from suvari.auto.tech_vectors import (
    detect_tech, firebase_context, vectors_for, generic_vectors, scope_hosts,
    TECH_RULE_BY_KEY,
)

BASE = "http://127.0.0.1:9999"


def _res(body="", headers=None, status=200):
    return ExecResult("curl", [], ok=True, url=BASE + "/", status=status,
                      headers=headers or {}, body=body)


# ── detection ───────────────────────────────────────────────────────────
def test_detect_nextjs_from_body_path():
    res = _res(body='<script src="/_next/static/chunks/main.js"></script>')
    assert "nextjs" in detect_tech([res])


def test_detect_nextjs_from_powered_by_header():
    res = _res(headers={"x-powered-by": "Next.js"})
    assert "nextjs" in detect_tech([res])


def test_detect_netlify_from_headers():
    res = _res(headers={"server": "Netlify", "x-nf-request-id": "abc123"})
    assert "netlify" in detect_tech([res])


def test_detect_firebase_from_body():
    res = _res(body='databaseURL: "https://demo.firebaseio.com"')
    assert "firebase" in detect_tech([res])


def test_detect_firebase_from_firebasejs_cdn():
    res = _res(body='<script src="https://www.gstatic.com/firebasejs/9.0/firebase-app.js">')
    assert "firebase" in detect_tech([res])


def test_detect_multiple_stacks_and_known_servers():
    res = _res(
        body='/_next/static and firestore.googleapis.com',
        headers={"server": "nginx", "x-powered-by": "Express"},
    )
    tech = detect_tech([res])
    assert {"nextjs", "firebase", "nginx", "express"} <= tech


def test_detect_nothing_on_blank():
    assert detect_tech([_res()]) == set()
    assert detect_tech([]) == set()
    assert detect_tech([None]) == set()


# ── firebase context extraction ───────────────────────────────────────────
def test_firebase_context_extracts_project_and_bucket():
    body = ('const cfg = {apiKey:"AIzaSyA0123456789abcdefghijklmnop",'
            'projectId:"my-cool-app",storageBucket:"my-cool-app.appspot.com",'
            'databaseURL:"https://my-cool-app-default-rtdb.firebaseio.com"};')
    ctx = firebase_context([_res(body=body)])
    assert ctx["project"] == "my-cool-app"
    assert ctx["bucket"] == "my-cool-app.appspot.com"
    assert ctx["apikey_seen"] is True


def test_firebase_context_defaults_bucket_from_project():
    ctx = firebase_context([_res(body='projectId: "solo-proj"')])
    assert ctx["project"] == "solo-proj"
    assert ctx["bucket"] == "solo-proj.appspot.com"


# ── vector generation ──────────────────────────────────────────────────────
def test_vectors_for_firebase_produces_seven_curl_probes():
    specs = vectors_for("firebase", BASE)
    assert len(specs) == 7
    assert all(s.probe == "curl" for s in specs)
    # every generated vector is a known, registered rule
    assert all(s.vector in TECH_RULE_BY_KEY for s in specs)
    vectors = {s.vector for s in specs}
    assert {
        "firebase-init-exposure", "firebase-config-leak", "firebase-rtdb-open",
        "firestore-open", "firebase-storage-open", "firebase-identity-config",
        "firebase-files-exposure",
    } == vectors


def test_vectors_for_firebase_uses_detected_project():
    ctx = {"project": "acme-prod", "bucket": "acme-prod.appspot.com"}
    specs = vectors_for("firebase", BASE, ctx)
    rtdb = next(s for s in specs if s.vector == "firebase-rtdb-open")
    assert "acme-prod-default-rtdb.firebaseio.com" in rtdb.target
    fs = next(s for s in specs if s.vector == "firestore-open")
    assert "projects/acme-prod/databases" in fs.target
    store = next(s for s in specs if s.vector == "firebase-storage-open")
    assert "acme-prod.appspot.com" in store.target


def test_vectors_for_firebase_priors_in_band():
    for s in vectors_for("firebase", BASE):
        assert 0.25 <= s.prior <= 0.5


def test_vectors_for_nextjs_netlify_wordpress():
    assert {s.vector for s in vectors_for("nextjs", BASE)} == {
        "nextjs-sourcemap", "nextjs-data", "nextjs-api"}
    assert {s.vector for s in vectors_for("netlify", BASE)} == {
        "netlify-functions", "netlify-identity", "netlify-config"}
    assert {s.vector for s in vectors_for("wordpress", BASE)} == {
        "wp-users", "wp-xmlrpc", "wp-login"}


def test_vectors_for_unknown_tech_is_empty():
    assert vectors_for("cloudflare", BASE) == []


def test_generic_vectors_always_four():
    specs = generic_vectors(BASE)
    assert {s.vector for s in specs} == {
        "sitemap-leak", "security-txt", "dotenv-exposure", "server-status"}
    assert all(s.target.startswith(BASE) for s in specs)


# ── scope ───────────────────────────────────────────────────────────────
def test_scope_hosts_firebase_with_project():
    hosts = scope_hosts({"firebase"}, {"project": "acme-prod"})
    assert "firestore.googleapis.com" in hosts
    assert "firebasestorage.googleapis.com" in hosts
    assert "identitytoolkit.googleapis.com" in hosts
    assert "acme-prod-default-rtdb.firebaseio.com" in hosts


def test_scope_hosts_without_firebase_is_empty():
    assert scope_hosts({"nextjs"}, {}) == []
