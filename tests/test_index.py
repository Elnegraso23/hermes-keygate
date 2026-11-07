"""Secret-free alias index: origin -> alias resolution.

Guarantees under test:
  * index_put stores the origin and the alias only (no password, no identifier)
  * matching is exact (scheme + host); http vs https and suffix attacks fail
  * the file is 0600 and readable as JSON

No Hermes imports: runs anywhere (CI included).
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


class TestIndex(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()

    def test_put_get_roundtrip(self):
        kg.index_put(self.home, "Google", "https://accounts.google.com/login?x=1")
        self.assertEqual(kg.index_get(self.home, "https://accounts.google.com"), ["Google"])
        # path/query are not part of the origin
        self.assertEqual(kg.index_get(self.home, "https://accounts.google.com/signin/v2"),
                         ["Google"])

    def test_no_secret_or_identifier_stored(self):
        kg.index_put(self.home, "Moodle", "https://moodle.example.mx")
        raw = (Path(self.home) / "keygate-index.json").read_text(encoding="utf-8")
        data = json.loads(raw)
        entry = data["aliases"]["Moodle"]
        self.assertEqual(set(entry), {"origin", "updated"})
        self.assertNotIn("password", raw.lower())
        self.assertNotIn("identifier", raw.lower())

    def test_file_mode_0600(self):
        kg.index_put(self.home, "X", "https://x.example")
        mode = stat.S_IMODE(os.stat(Path(self.home) / "keygate-index.json").st_mode)
        self.assertEqual(mode, 0o600)

    def test_strict_origin_matching(self):
        kg.index_put(self.home, "Google", "https://accounts.google.com")
        # different scheme
        self.assertEqual(kg.index_get(self.home, "http://accounts.google.com"), [])
        # suffix attack
        self.assertEqual(kg.index_get(self.home, "https://accounts.google.com.evil.io"), [])
        # prefix attack
        self.assertEqual(kg.index_get(self.home, "https://evil.io/accounts.google.com"), [])
        # unknown origin
        self.assertEqual(kg.index_get(self.home, "https://nope.example"), [])

    def test_put_rejects_bad_origin(self):
        self.assertEqual(kg.index_put(self.home, "X", "not-a-url"), {})
        self.assertEqual(kg.index_get(self.home, "https://x.example"), [])

    def test_put_overwrites_same_alias(self):
        kg.index_put(self.home, "A", "https://old.example")
        kg.index_put(self.home, "A", "https://new.example")
        self.assertEqual(kg.index_get(self.home, "https://old.example"), [])
        self.assertEqual(kg.index_get(self.home, "https://new.example"), ["A"])

    def test_empty_index_is_safe(self):
        self.assertEqual(kg.index_get(self.home, "https://anything.example"), [])
        self.assertEqual(kg.load_index(self.home)["aliases"], {})


if __name__ == "__main__":
    unittest.main()
