"""Security regressions for keygate-sync (F5 CSRF / bootstrap, F6 Host).

Runs the real ThreadingHTTPServer on an ephemeral port with a throwaway HOME,
so the assertions are HTTP-level, not mocks. No Hermes runtime needed.
"""
import http.client
import importlib
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sync"))


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".hermes").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("KEYGATE_DB", str(tmp_path / "vault.kdbx"))
    monkeypatch.setenv("KEYGATE_KEYFILE", str(tmp_path / "vault.key"))
    monkeypatch.setenv("KEYGATE_BIND", "127.0.0.1")
    monkeypatch.setenv("KEYGATE_PORT", "0")
    ks = importlib.reload(importlib.import_module("keygate_sync"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ks.Handler)
    port = httpd.server_address[1]
    ks._ALLOWED_HOSTS = ks._build_allowed_hosts("127.0.0.1", port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield ks, port, home
    finally:
        httpd.shutdown()
        httpd.server_close()


def _post(port, body, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Content-Type": "application/json", "Host": f"127.0.0.1:{port}"}
    hdrs.update(headers)
    c.request("POST", "/api/set-password", json.dumps(body), hdrs)
    r = c.getresponse()
    payload = r.read()
    c.close()
    return r.status, payload


def test_post_without_origin_or_sfs_is_rejected(srv):
    ks, port, _ = srv
    status, body = _post(port, {"password": "clave-de-prueba-123"}, {})
    assert status == 403
    assert b"CSRF" in body or b"csrf" in body


def test_cross_origin_is_rejected(srv):
    ks, port, _ = srv
    status, _ = _post(port, {"password": "clave-de-prueba-123"},
                      {"Origin": "https://evil.com", "Sec-Fetch-Site": "cross-site"})
    assert status == 403


def test_same_origin_without_bootstrap_is_rejected(srv):
    ks, port, _ = srv
    status, body = _post(port, {"password": "clave-de-prueba-123"},
                         {"Origin": f"http://127.0.0.1:{port}",
                          "Sec-Fetch-Site": "same-origin"})
    assert status == 403
    assert b"bootstrap" in body


def test_bootstrap_code_is_single_use(srv):
    ks, port, home = srv
    code = ks.bootstrap_ensure(home / ".hermes", show=False)
    assert code
    ok_headers = {"Origin": f"http://127.0.0.1:{port}", "Sec-Fetch-Site": "same-origin"}
    status, _ = _post(port, {"password": "clave-de-prueba-123", "bootstrap": code}, ok_headers)
    assert status == 200
    # code consumed: file gone, endpoint dead
    assert not (home / ".hermes" / "keygate-sync-bootstrap").exists()
    status2, body2 = _post(port, {"password": "otra-clave-123456", "bootstrap": code}, ok_headers)
    assert status2 == 403
    assert b"already set" in body2


def test_bootstrap_compare_is_exact(srv):
    ks, port, home = srv
    ks.bootstrap_ensure(home / ".hermes", show=False)
    status, _ = _post(port, {"password": "clave-de-prueba-123", "bootstrap": "adivinanza"},
                      {"Origin": f"http://127.0.0.1:{port}", "Sec-Fetch-Site": "same-origin"})
    assert status == 403


def test_duplicate_host_header_is_rejected(srv):
    ks, port, _ = srv
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", f"127.0.0.1:{port}")
    c.putheader("Host", "evil.com")
    c.endheaders()
    r = c.getresponse()
    r.read()
    c.close()
    assert r.status == 403


def test_single_valid_host_still_serves_the_page(srv):
    ks, port, _ = srv
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
    r = c.getresponse()
    body = r.read()
    c.close()
    assert r.status == 200
    assert b"keygate-sync" in body


def test_server_header_does_not_leak_versions(srv):
    """ZAP Low: `Server: keygate-sync/0.2 Python/3.14` facilita fingerprinting."""
    ks, port, _ = srv
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
    r = c.getresponse()
    r.read()
    server = r.getheader("Server") or ""
    c.close()
    assert not any(ch.isdigit() for ch in server), server
    assert "Python" not in server, server
