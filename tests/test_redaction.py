"""Redaction + ref parsing invariants (no Hermes imports: runs anywhere)."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import keygate_lib as kg


def test_redact_user_email():
    assert kg.redact_user("juan@x.com") == "j***@x.com"
    assert kg.redact_user("") == "***"


def test_redact_label_hides_middle():
    assert kg.redact_label("Banco-personal") == "B************l"


def test_redact_origin_keeps_tld():
    assert kg.redact_origin("https://ejemplo.com/login") == "e******.com"


def test_kpx_ref_ok():
    assert kg.parse_kpx_ref("kpx://gh-agent-1/password") == ("gh-agent-1", "password")
    assert kg.parse_kpx_ref("kpx://a/user") == ("a", "username")


def test_kpx_ref_bad():
    assert kg.parse_kpx_ref("kpx://a") is None
    assert kg.parse_kpx_ref("op://v/i/f") is None
    assert kg.parse_kpx_ref("kpx://a/evil") is None


def test_secret_never_in_search_shape():
    # search returns alias+hint only; hint must not contain a password-looking value
    h = kg.hint_for("Banco", "juan@x.com")
    assert "s3cret" not in h and "@x.com" in h and "j***" in h
    assert kg.hint_for("Banco", "") == "B***o"


def test_normalize_origin_blocks_phishing_and_userinfo():
    assert kg.normalize_origin("https://accounts.google.com/signin?x=1") == "https://accounts.google.com"
    assert kg.normalize_origin("https://example.com:443/login") == "https://example.com"
    assert kg.normalize_origin("http://example.com:80/a") == "http://example.com"
    assert kg.normalize_origin("https://example.com:8443/a") == "https://example.com:8443"
    # Reject userinfo spoofing (https://good.com@evil.com)
    assert kg.normalize_origin("https://google.com@evil.com/login") == ""
    assert kg.normalize_origin("https://user:pass@example.com") == ""
    assert kg.normalize_origin("javascript:alert(1)") == ""
    # Strict equality: never substring match
    assert kg.origins_match("https://google.com/login", "https://google.com") is True
    assert kg.origins_match("https://google.com", "https://google.com.evil.com") is False
    assert kg.origins_match("https://accounts.google.com", "https://google.co") is False
    assert kg.origins_match("https://example.com", "http://example.com") is False
    assert kg.origins_match("https://example.com:8443", "https://example.com") is False


def test_session_ensure_valid_on_create():
    r1 = kg.session_ensure("example.com", ttl_seconds=60)
    assert r1["valid"] is True and r1["created"] is True
    r2 = kg.session_ensure("example.com", ttl_seconds=60)
    assert r2["valid"] is True and r2["created"] is False and r2["handle"] == r1["handle"]
    assert kg.session_invalidate("example.com") is True
