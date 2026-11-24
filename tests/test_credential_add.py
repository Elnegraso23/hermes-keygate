"""Tests for controlled credential creation (keygate_lib.add_entry, create-policy,
plugin keygate_credential_add / keygate_alias_add, and keygate-sync web APIs).
"""
from __future__ import annotations

import hashlib
import http.client
import importlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import threading
import types
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "sync") not in sys.path:
    sys.path.insert(0, str(ROOT / "sync"))

import keygate_lib as kg  # noqa: E402


def _make_vault(tmp_path: Path):
    """Create a real keyfile-only .kdbx in tmp_path (never touches real vault)."""
    db = tmp_path / "hermes.kdbx"
    kf = tmp_path / "agent.key"
    kf.write_bytes(os.urandom(128))
    os.chmod(kf, 0o600)
    p = subprocess.run(
        ["keepassxc-cli", "db-create", "--set-key-file", str(kf), "-q", str(db)],
        capture_output=True, text=True, timeout=30,
    )
    assert p.returncode == 0, f"db-create failed: {p.stderr}"
    os.chmod(db, 0o600)
    return str(db), str(kf)


def _sha256(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ------------------------------------------------------- keygate_lib tests ---

def test_add_entry_happy_path_and_no_secret_in_output(tmp_path):
    db, kf = _make_vault(tmp_path)
    before_hash = _sha256(db)

    res = kg.add_entry(
        db, kf,
        alias="github-agent-1",
        origin="https://github.com/login",
        username="agent@example.com",
        generate=True,
        length=24,
    )
    assert res["success"] is True
    assert res["created"] is True
    assert res["rotated"] is False
    assert res["alias"] == "github-agent-1"
    assert res["origin"] == "https://github.com"
    assert res["identifier"] == "agent@example.com"
    assert res["generated"] is True
    assert res["length"] == 24

    # Vault updated, 0600 preserved, backup created, hash changed
    assert _sha256(db) != before_hash
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(kf).st_mode) == 0o600
    baks = list(tmp_path.glob("hermes.kdbx.*.bak"))
    assert len(baks) == 1
    assert stat.S_IMODE(os.stat(baks[0]).st_mode) == 0o600

    # Entry verifiable via keepassxc-cli
    assert "github-agent-1" in kg.list_entries(db, kf)
    pw = kg.show_field(db, kf, "github-agent-1", "password")
    assert pw and len(pw) == 24
    # Secret MUST NOT appear in result payload
    assert pw not in json.dumps(res)


def test_add_entry_with_nested_group(tmp_path):
    db, kf = _make_vault(tmp_path)
    res = kg.add_entry(
        db, kf,
        alias="social-bot-1",
        origin="https://example.org",
        username="bot@example.org",
        group="Agents/Social",
    )
    assert res["success"] is True
    assert res["entry_path"] == "Agents/Social/social-bot-1"
    resolved, err = kg.resolve_entry(db, kf, "social-bot-1")
    assert err is None
    assert resolved == "Agents/Social/social-bot-1"


def test_add_entry_duplicate_and_rotate(tmp_path):
    db, kf = _make_vault(tmp_path)
    r1 = kg.add_entry(db, kf, alias="dup-1", origin="https://example.com", username="u@example.com")
    assert r1["success"] is True
    pw1 = kg.show_field(db, kf, "dup-1", "password")

    # Duplicate with rotate=False -> alias_exists
    r2 = kg.add_entry(db, kf, alias="dup-1", origin="https://example.com", username="u@example.com")
    assert r2["success"] is False
    assert r2["error_type"] == "alias_exists"

    # Rotate with mismatched origin -> domain_mismatch
    r3 = kg.add_entry(
        db, kf, alias="dup-1", origin="https://evil.example.com",
        username="u@example.com", rotate=True,
    )
    assert r3["success"] is False
    assert r3["error_type"] == "domain_mismatch"
    assert kg.show_field(db, kf, "dup-1", "password") == pw1

    # Rotate with matching origin -> new password
    r4 = kg.add_entry(
        db, kf, alias="dup-1", origin="https://example.com",
        username="u@example.com", rotate=True,
    )
    assert r4["success"] is True
    assert r4["rotated"] is True
    assert r4["created"] is False
    pw2 = kg.show_field(db, kf, "dup-1", "password")
    assert pw2 and pw2 != pw1
    assert pw2 not in json.dumps(r4)


def test_add_entry_invalid_inputs(tmp_path):
    db, kf = _make_vault(tmp_path)
    bad_orig = kg.add_entry(db, kf, alias="ok-1", origin="javascript:alert(1)", username="u@e.com")
    assert bad_orig["success"] is False and bad_orig["error_type"] == "invalid_origin"

    bad_userinfo = kg.add_entry(db, kf, alias="ok-1", origin="https://good.com@evil.com", username="u@e.com")
    assert bad_userinfo["success"] is False and bad_userinfo["error_type"] == "invalid_origin"

    bad_alias = kg.add_entry(db, kf, alias="bad/alias", origin="https://example.com", username="u@e.com")
    assert bad_alias["success"] is False and bad_alias["error_type"] == "invalid_alias"

    bad_trash = kg.add_entry(db, kf, alias="Recycle Bin", origin="https://example.com", username="u@e.com")
    assert bad_trash["success"] is False and bad_trash["error_type"] == "invalid_alias"


def test_create_policy_persistence_and_email_validation(tmp_path):
    home = tmp_path / ".hermes"
    pol = kg.load_create_policy(home)
    assert pol["mode"] == "ask"
    assert pol["default_email"] == ""

    updated, err = kg.set_create_policy(home, mode="auto", default_email="hermes@example.com")
    assert err is None
    assert updated["mode"] == "auto"
    assert updated["default_email"] == "hermes@example.com"
    assert stat.S_IMODE(os.stat(kg.create_policy_path(home)).st_mode) == 0o600

    reloaded = kg.load_create_policy(home)
    assert reloaded["mode"] == "auto"
    assert reloaded["default_email"] == "hermes@example.com"

    # Invalid mode / email rejected
    _, err_m = kg.set_create_policy(home, mode="yolo")
    assert err_m
    _, err_e = kg.set_create_policy(home, default_email="not-an-email")
    assert err_e


# --------------------------------------------------- plugin handler tests ---

def _load_plugin_tools(monkeypatch, home: Path, db: str, kf: str, approval_return="accept",
                       cron=False):
    """Load __init__.py with lightweight stubs for Hermes runtime modules."""
    monkeypatch.setenv("HOME", str(home.parent))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("KEYGATE_DB", db)
    monkeypatch.setenv("KEYGATE_KEYFILE", kf)

    # Minimal stubs for Hermes runtime imports
    agent_mod = types.ModuleType("agent")
    ss_mod = types.ModuleType("agent.secret_sources")
    base_mod = types.ModuleType("agent.secret_sources.base")
    base_mod.ErrorKind = types.SimpleNamespace(
        NOT_CONFIGURED="not_configured", AUTH_FAILED="auth_failed",
        AUTH_EXPIRED="auth_expired", BINARY_MISSING="binary_missing",
        REF_INVALID="ref_invalid",
    )
    base_mod.FetchResult = object
    base_mod.SecretSource = object
    base_mod.is_valid_env_name = lambda s: True
    base_mod.run_secret_cli = lambda *a, **kw: None
    monkeypatch.setitem(sys.modules, "agent", agent_mod)
    monkeypatch.setitem(sys.modules, "agent.secret_sources", ss_mod)
    monkeypatch.setitem(sys.modules, "agent.secret_sources.base", base_mod)

    hc_mod = types.ModuleType("hermes_constants")
    hc_mod.get_hermes_home = lambda: str(home)
    monkeypatch.setitem(sys.modules, "hermes_constants", hc_mod)

    approval_calls = []
    tools_mod = types.ModuleType("tools")
    ap_mod = types.ModuleType("tools.approval_prompt")

    def _req_consent(q, body, surface="", title=""):
        approval_calls.append({"q": q, "body": body, "surface": surface, "title": title})
        return approval_return

    ap_mod.request_elicitation_consent = _req_consent
    ac_mod = types.ModuleType("tools.approval_context")
    ac_mod.get_current_session_key = lambda: "sess-1"
    ac_mod._get_session_platform = lambda: "telegram"
    ac_mod._is_cron_approval_context = lambda: cron
    ac_mod._is_single_query_approval_context = lambda: False
    ac_mod._is_gateway_approval_context = lambda: True
    ac_mod._is_interactive_cli = lambda: False
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval_prompt", ap_mod)
    monkeypatch.setitem(sys.modules, "tools.approval_context", ac_mod)

    spec = importlib.util.spec_from_file_location("kg_plugin_test", str(ROOT / "__init__.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class _Ctx:
        def __init__(self):
            self.tools = {}

        def register_tool(self, **kw):
            self.tools[kw["name"]] = kw["handler"]

        def register_secret_source(self, s):
            pass

        def register_skill(self, n, p):
            pass

    ctx = _Ctx()
    mod.register(ctx)
    return ctx.tools, approval_calls


def test_plugin_credential_add_happy_path_and_lookup(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    db, kf = _make_vault(tmp_path)
    tools, calls = _load_plugin_tools(monkeypatch, home, db, kf, approval_return="accept")

    out = json.loads(tools["keygate_credential_add"]({
        "alias": "moodle-agent-1",
        "origin": "https://moodle.example.edu/login",
        "username": "student@example.edu",
    }))
    assert out["success"] is True
    assert out["created"] is True
    assert out["alias"] == "moodle-agent-1"
    assert out["origin"] == "https://moodle.example.edu"
    assert out["indexed"] is True
    assert out["autofill_enabled"] is False
    assert len(calls) == 1  # asked once in default 'ask' mode

    # Lookup resolves immediately
    lk = json.loads(tools["keygate_lookup"]({"origin": "https://moodle.example.edu"}))
    assert lk["success"] is True
    assert any(a["alias"] == "moodle-agent-1" for a in lk["aliases"])

    # Generated password never appears in tool output or audit log
    pw = kg.show_field(db, kf, "moodle-agent-1", "password")
    assert pw and len(pw) == 24
    assert pw not in json.dumps(out)
    audit_txt = (home / kg.AUDIT_NAME).read_text(encoding="utf-8")
    assert pw not in audit_txt


def test_plugin_rejects_password_param_and_denied_and_sealed_and_audit_fail(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    db, kf = _make_vault(tmp_path)
    tools, calls = _load_plugin_tools(monkeypatch, home, db, kf, approval_return="decline")

    # 1) Passing a password param is ALWAYS policy_blocked and never echoed
    secret_attempt = "SuperSecretAttempt-999!"
    r_pw = json.loads(tools["keygate_credential_add"]({
        "alias": "nope-1", "origin": "https://example.com",
        "username": "u@e.com", "password": secret_attempt,
    }))
    assert r_pw["success"] is False and r_pw["error_type"] == "policy_blocked"
    assert secret_attempt not in json.dumps(r_pw)

    # 2) Approval denied -> approval_denied, DB untouched
    r_deny = json.loads(tools["keygate_credential_add"]({
        "alias": "deny-1", "origin": "https://example.com", "username": "u@e.com",
    }))
    assert r_deny["success"] is False and r_deny["error_type"] == "approval_denied"
    assert "deny-1" not in kg.list_entries(db, kf)

    # 3) Vault sealed -> vault_sealed
    sealed_dir = tmp_path / ".keygate-vault"
    sealed_dir.mkdir()
    (sealed_dir / kg.SEALED_DB_NAME).write_bytes(b"gpg")
    r_sealed = json.loads(tools["keygate_credential_add"]({
        "alias": "seal-1", "origin": "https://example.com", "username": "u@e.com",
    }))
    assert r_sealed["success"] is False and r_sealed["error_type"] == "vault_sealed"
    (sealed_dir / kg.SEALED_DB_NAME).unlink()

    # 4) Failed audit -> aborts write (fail-closed)
    tools_ok, _ = _load_plugin_tools(monkeypatch, home, db, kf, approval_return="accept")
    monkeypatch.setattr(kg, "audit", lambda *a, **kw: (_ for _ in ()).throw(kg.AuditError("disk full")) if kw.get("strict") else None)
    r_aud = json.loads(tools_ok["keygate_credential_add"]({
        "alias": "aud-1", "origin": "https://example.com", "username": "u@e.com",
    }))
    assert r_aud["success"] is False and r_aud["error_type"] == "audit_unavailable"
    assert "aud-1" not in kg.list_entries(db, kf)


def test_plugin_auto_policy_default_email_and_deprecated_wrapper(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    db, kf = _make_vault(tmp_path)
    kg.set_create_policy(home, mode="auto", default_email="hermes-auto@example.com")

    tools, calls = _load_plugin_tools(monkeypatch, home, db, kf, approval_return="accept")

    # Auto mode: creates without prompting, uses default_email when username omitted
    r1 = json.loads(tools["keygate_credential_add"]({
        "alias": "auto-acct-1",
        "origin": "https://auto.example.com",
    }))
    assert r1["success"] is True
    assert r1["identifier"] == "hermes-auto@example.com"
    assert len(calls) == 0  # no prompt in auto mode for new creation

    # Rotate ALWAYS asks approval even in auto mode (Decision 4)
    r2 = json.loads(tools["keygate_alias_add"]({
        "alias": "auto-acct-1",
        "origin": "https://auto.example.com",
        "rotate": True,
    }))
    assert r2["success"] is True
    assert r2["rotated"] is True
    assert r2["deprecated"] is True
    assert r2["replacement"] == "keygate_credential_add"
    assert len(calls) == 1

    # Disabled mode blocks creation
    kg.set_create_policy(home, mode="disabled")
    r3 = json.loads(tools["keygate_credential_add"]({
        "alias": "auto-acct-2",
        "origin": "https://auto2.example.com",
    }))
    assert r3["success"] is False and r3["error_type"] == "policy_blocked"


# ---------------------------------------------- keygate-sync web API tests ---

@pytest.fixture()
def sync_srv(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes_home = home / ".hermes"
    hermes_home.mkdir(parents=True)
    db, kf = _make_vault(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("KEYGATE_DB", db)
    monkeypatch.setenv("KEYGATE_KEYFILE", kf)
    monkeypatch.setenv("KEYGATE_BIND", "127.0.0.1")
    monkeypatch.setenv("KEYGATE_PORT", "0")
    ks = importlib.reload(importlib.import_module("keygate_sync"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ks.Handler)
    port = httpd.server_address[1]
    ks._ALLOWED_HOSTS = ks._build_allowed_hosts("127.0.0.1", port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    pw = "clave-sync-prueba-1234"
    ks.set_password_once(hermes_home, pw)
    try:
        yield ks, port, hermes_home, db, kf, pw
    finally:
        httpd.shutdown()
        httpd.server_close()


def _req(port, method, path, body=None, pw=None, csrf=True):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = {"Host": f"127.0.0.1:{port}"}
    if pw:
        hdrs["Authorization"] = f"Bearer {pw}"
    if csrf:
        hdrs["Origin"] = f"http://127.0.0.1:{port}"
        hdrs["Sec-Fetch-Site"] = "same-origin"
    payload = None
    if body is not None:
        hdrs["Content-Type"] = "application/json"
        payload = json.dumps(body)
    c.request(method, path, payload, hdrs)
    r = c.getresponse()
    raw = r.read()
    resp_hdrs = dict(r.getheaders())
    c.close()
    return r.status, json.loads(raw.decode("utf-8")), resp_hdrs


def test_web_create_policy_entry_and_oneshot_reveal(sync_srv):
    ks, port, hermes_home, db, kf, pw = sync_srv

    # 1) Configure create-policy + default_email via web API
    st, j, _ = _req(port, "POST", "/api/create-policy",
                    {"mode": "auto", "default_email": "hermes@web.example"}, pw=pw)
    assert st == 200 and j["success"] is True
    assert j["mode"] == "auto" and j["default_email"] == "hermes@web.example"

    st_g, j_g, _ = _req(port, "GET", "/api/create-policy", pw=pw)
    assert st_g == 200 and j_g["mode"] == "auto" and j_g["default_email"] == "hermes@web.example"

    # 2) Create entry in generate mode (username falls back to default_email)
    st_e, j_e, _ = _req(port, "POST", "/api/entry", {
        "alias": "web-gen-1",
        "origin": "https://service.example.com/signin",
        "mode": "generate",
    }, pw=pw)
    assert st_e == 200 and j_e["success"] is True
    assert j_e["identifier"] == "hermes@web.example"
    assert "password" not in j_e
    tok = j_e["reveal_token"]
    assert tok

    # 3) Reveal one-shot token: succeeds once with Cache-Control: no-store, then 410 Gone
    st_r1, j_r1, hdrs_r1 = _req(port, "POST", "/api/entry/reveal", {"token": tok}, pw=pw)
    assert st_r1 == 200 and j_r1["success"] is True
    revealed_pw = j_r1["password"]
    assert revealed_pw and len(revealed_pw) == 24
    assert "no-store" in (hdrs_r1.get("Cache-Control") or "").lower()

    st_r2, _, _ = _req(port, "POST", "/api/entry/reveal", {"token": tok}, pw=pw)
    assert st_r2 == 410

    # Password never appears in audit log
    audit_txt = (hermes_home / kg.AUDIT_NAME).read_text(encoding="utf-8")
    assert revealed_pw not in audit_txt

    # 4) Manual mode (Route C) for existing credential, auth/CSRF required
    manual_pw = "ManualExistingPass!2026"
    st_unauth, _, _ = _req(port, "POST", "/api/entry", {
        "alias": "web-man-1", "origin": "https://man.example.com",
        "username": "me@man.example.com", "mode": "manual", "password": manual_pw,
    }, pw=None)
    assert st_unauth == 401

    st_m, j_m, _ = _req(port, "POST", "/api/entry", {
        "alias": "web-man-1", "origin": "https://man.example.com",
        "username": "me@man.example.com", "mode": "manual", "password": manual_pw,
    }, pw=pw)
    assert st_m == 200 and j_m["success"] is True
    assert manual_pw not in json.dumps(j_m)
    assert kg.show_field(db, kf, "web-man-1", "password") == manual_pw
    assert manual_pw not in (hermes_home / kg.AUDIT_NAME).read_text(encoding="utf-8")
