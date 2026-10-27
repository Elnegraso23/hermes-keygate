"""Per-alias auto-fill policy: normalization + exact-origin matching.

No Hermes imports, no vault: runs anywhere (CI included).
"""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import keygate_lib as kg


class NormalizeOrigin(unittest.TestCase):
    def test_keeps_scheme_host_port(self):
        self.assertEqual(kg.normalize_origin("https://Accounts.Google.com/login?x=1"),
                         "https://accounts.google.com")
        self.assertEqual(kg.normalize_origin("http://127.0.0.1:8479/"),
                         "http://127.0.0.1:8479")

    def test_drops_path_and_trailing_slash(self):
        self.assertEqual(kg.normalize_origin("https://a.example/"), "https://a.example")
        self.assertEqual(kg.normalize_origin("https://a.example/deep/path"),
                         "https://a.example")

    def test_rejects_non_http_and_garbage(self):
        for bad in ("", "ftp://a.example", "javascript:alert(1)", "a.example", None):
            self.assertEqual(kg.normalize_origin(bad), "")


class PolicyStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / ".hermes"

    def tearDown(self):
        self.tmp.cleanup()

    def test_absent_file_means_no_policy(self):
        self.assertFalse(kg.autofill_allows(self.home, "alias", "https://a.example"))

    def test_enable_then_exact_match_only(self):
        kg.set_autofill(self.home, "alias", "https://a.example", True)
        self.assertTrue(kg.autofill_allows(self.home, "alias", "https://a.example"))
        self.assertTrue(kg.autofill_allows(self.home, "alias", "https://A.example/login"))
        self.assertFalse(kg.autofill_allows(self.home, "alias", "https://b.example"))
        self.assertFalse(kg.autofill_allows(self.home, "alias", "https://sub.a.example"))
        self.assertFalse(kg.autofill_allows(self.home, "alias", "http://a.example"))
        self.assertFalse(kg.autofill_allows(self.home, "otro", "https://a.example"))

    def test_file_is_0600(self):
        kg.set_autofill(self.home, "alias", "https://a.example", True)
        mode = stat.S_IMODE(kg.autofill_path(self.home).stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_disable_removes_policy(self):
        kg.set_autofill(self.home, "alias", "https://a.example", True)
        kg.set_autofill(self.home, "alias", "", False)
        self.assertFalse(kg.autofill_allows(self.home, "alias", "https://a.example"))
        self.assertEqual(kg.load_autofill(self.home).get("policies"), {})

    def test_corrupt_file_fails_closed(self):
        path = kg.autofill_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        self.assertFalse(kg.autofill_allows(self.home, "alias", "https://a.example"))

    def test_invalid_origin_is_not_stored(self):
        kg.set_autofill(self.home, "alias", "not-an-origin", True)
        self.assertFalse(kg.autofill_allows(self.home, "alias", "not-an-origin"))


if __name__ == "__main__":
    unittest.main()
