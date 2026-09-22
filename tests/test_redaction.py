"""Redaction + ref parsing invariants (no Hermes imports: runs anywhere)."""
import sys
sys.path.insert(0, "/home/black/hermes-keygate")
import keygate_lib as kg


def test_redact_user_email():
    assert kg.redact_user("juan@x.com") == "j***@x.com"
    assert kg.redact_user("") == "***"


def test_redact_label_hides_middle():
    assert kg.redact_label("Banco-personal") == "B************l"


def test_redact_origin_keeps_tld():
    assert kg.redact_origin("https://ejemplo.com/login") == "e*******.com"


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
