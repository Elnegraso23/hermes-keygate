"""Alias page: Basic-auth password storage and policy toggling.

Guarantees under test:
  * only a PBKDF2 hash is stored; the plaintext password never lands on disk
  * meta file is 0600
  * enabling auto-fill writes a policy with source=web; disabling removes it
  * url_for always carries the configured port

No Hermes imports and no network: the HTTP layer is exercised separately by
scripts/keygate-alias-page --selftest.
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import keygate_lib as kg  # noqa: E402
import keygate_web as kw  # noqa: E402


class TestAliasPage(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self._old = os.environ.get("HERMES_HOME")
        os.environ["HERMES_HOME"] = self.home

    def tearDown(self):
        if self._old is None:
            os.environ.pop("HERMES_HOME", None)
        else:
            os.environ["HERMES_HOME"] = self._old

    def test_password_is_hashed_only(self):
        kw.set_password("correct horse battery")
        raw = Path(self.home, "keygate-web.meta.json").read_text(encoding="utf-8")
        self.assertNotIn("correct horse battery", raw)
        meta = json.loads(raw)
        self.assertIn("salt", meta)
        self.assertIn("hash", meta)

    def test_meta_mode_0600(self):
        kw.set_password("another long secret")
        mode = stat.S_IMODE(os.stat(Path(self.home, "keygate-web.meta.json")).st_mode)
        self.assertEqual(mode, 0o600)

    def test_check_password(self):
        kw.set_password("right-password-123")
        self.assertTrue(kw.check_password("owner", "right-password-123"))
        self.assertFalse(kw.check_password("owner", "wrong-password-123"))
        self.assertFalse(kw.check_password("owner", ""))

    def test_check_password_without_meta(self):
        self.assertFalse(kw.check_password("owner", "anything"))

    def test_toggle_enable_and_disable(self):
        kg.index_put(self.home, "Google", "https://accounts.google.com")
        self.assertTrue(kw.apply_toggle("Google", True))
        pol = kg.load_autofill(self.home)["policies"]
        self.assertIn("Google", pol)
        self.assertTrue(pol["Google"]["enabled"])
        self.assertEqual(pol["Google"]["source"], "web")
        self.assertEqual(pol["Google"]["origin"], "https://accounts.google.com")

        self.assertTrue(kw.apply_toggle("Google", False))
        self.assertNotIn("Google", kg.load_autofill(self.home)["policies"])

    def test_toggle_unknown_alias_fails(self):
        self.assertFalse(kw.apply_toggle("Nope", True))
        self.assertFalse(kw.apply_toggle("", True))

    def test_rows_merge_index_and_policies(self):
        kg.index_put(self.home, "Moodle", "https://moodle.example.mx")
        kg.set_autofill(self.home, "Google", "https://accounts.google.com", True)
        rows = {r["alias"]: r for r in kw.alias_rows()}
        self.assertEqual(rows["Moodle"]["enabled"], False)
        self.assertEqual(rows["Google"]["enabled"], True)
        self.assertEqual(rows["Google"]["origin"], "https://accounts.google.com")

    def test_url_for_uses_port(self):
        kw.set_password("some-password-here")
        meta = json.loads(Path(self.home, "keygate-web.meta.json").read_text(encoding="utf-8"))
        url = kw.url_for("Google")
        self.assertIn(str(meta["port"]), url)
        self.assertTrue(url.endswith("/?alias=Google"))


if __name__ == "__main__":
    unittest.main()
