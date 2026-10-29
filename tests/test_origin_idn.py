"""H13: IDN/punycode, control chars and scheme separation in normalize_origin."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import keygate_lib as kg


def test_cyrillic_homograph_is_punycoded_and_never_matches():
    homograph = kg.normalize_origin("https://\u0430pple.com")   # '\u0430' = a cirílica
    assert homograph == "https://xn--pple-43d.com", homograph
    assert homograph != kg.normalize_origin("https://apple.com")


def test_scheme_is_never_downgraded():
    assert kg.normalize_origin("http://apple.com") != kg.normalize_origin("https://apple.com")
    assert kg.normalize_origin("http://apple.com") == "http://apple.com"
    assert kg.normalize_origin("https://apple.com") == "https://apple.com"


def test_control_chars_and_whitespace_rejected():
    for bad in ("https://a b.com", "https://apple.com\x00.evil.com",
                "https://apple\t.com", "https://apple.com/\x7f"):
        assert kg.normalize_origin(bad) == "", bad
    # Edge whitespace is stripped (keepassxc-cli output often has a newline);
    # it cannot change the host, so this is canonicalization, not a bypass.
    assert kg.normalize_origin("https://apple.com\n") == "https://apple.com"


def test_empty_labels_and_bad_lengths_rejected():
    for bad in ("https://evil..com", "https://.evil.com"):
        assert kg.normalize_origin(bad) == "", bad
    # Trailing dots are DNS-equivalent: canonicalized to the bare host.
    assert kg.normalize_origin("https://evil.com..") == "https://evil.com"
    long_label = "a" * 64
    assert kg.normalize_origin(f"https://{long_label}.com") == ""


def test_trailing_dot_and_default_ports_normalized():
    assert kg.normalize_origin("https://apple.com.") == "https://apple.com"
    assert kg.normalize_origin("https://apple.com:443") == "https://apple.com"
    assert kg.normalize_origin("http://apple.com:80") == "http://apple.com"
    assert kg.normalize_origin("https://apple.com:8443") == "https://apple.com:8443"


def test_userinfo_and_non_http_rejected():
    assert kg.normalize_origin("https://apple.com@evil.com") == ""
    assert kg.normalize_origin("file:///etc/passwd") == ""
    assert kg.normalize_origin("javascript:alert(1)") == ""


def test_ipv6_literal_kept_bracketed():
    assert kg.normalize_origin("https://[::1]:8443") == "https://[::1]:8443"
