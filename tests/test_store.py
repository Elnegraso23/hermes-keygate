"""keygate's own encrypted store: key-only or key + passphrase.

Guarantees under test:
  * key mode: ciphertext + 0600 key file, roundtrip works
  * passphrase mode: key file removed, wrong passphrase rejected, correct one opens
  * no plaintext secret ever appears in the ciphertext or the meta file
  * rotating to passphrase preserves the items; removing it preserves them too

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

import keygate_vault as kv  # noqa: E402

try:  # cryptography es opcional: sólo lo necesita store_mode=mirror
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

PASS = "correct horse battery staple"
SECRET = "DUMMY-SECRET-NOT-REAL"


@unittest.skipUnless(HAVE_CRYPTO, "cryptography no instalado (extra opcional)")
class TestStore(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        kv.init(self.home)

    def tearDown(self):
        kv.lock(self.home)

    def _add(self):
        kv.add_item(self.home, label="keygate:Demo", origin="https://example.com",
                    identifier="user@example.com", identifier_type="email",
                    password=SECRET, otp_secret="JBSWY3DPEHPK3PXP")

    def test_key_mode_roundtrip(self):
        self._add()
        self.assertEqual(kv.status(self.home)["mode"], "key")
        self.assertEqual(kv.get_secret(self.home, "keygate:Demo")["password"], SECRET)

    def test_ciphertext_has_no_plaintext(self):
        self._add()
        raw = Path(self.home, "keygate-vault.enc").read_bytes()
        self.assertNotIn(SECRET.encode(), raw)
        meta = Path(self.home, "keygate-vault.meta.json").read_text(encoding="utf-8")
        self.assertNotIn(SECRET, meta)

    def test_files_are_0600(self):
        self._add()
        for name in ("keygate-vault.enc", "keygate-vault.key", "keygate-vault.meta.json"):
            mode = stat.S_IMODE(os.stat(Path(self.home, name)).st_mode)
            self.assertEqual(mode, 0o600, f"{name} no es 0600")

    def test_list_never_returns_secret(self):
        self._add()
        row = kv.list_items(self.home)[0]
        self.assertNotIn("password", row)
        self.assertNotIn("otp_secret", row)
        self.assertEqual(row["label"], "keygate:Demo")
        self.assertTrue(row["has_otp"])

    def test_passphrase_removes_keyfile_and_requires_it(self):
        self._add()
        kv.set_passphrase(self.home, PASS)
        self.assertFalse(Path(self.home, "keygate-vault.key").exists())
        kv.lock(self.home)
        with self.assertRaises(PermissionError):
            kv.get_secret(self.home, "keygate:Demo")
        with self.assertRaises(PermissionError):
            kv.get_secret(self.home, "keygate:Demo", passphrase="wrong passphrase")
        self.assertEqual(kv.get_secret(self.home, "keygate:Demo", passphrase=PASS)["password"],
                         SECRET)

    def test_rotation_preserves_items(self):
        self._add()
        kv.set_passphrase(self.home, PASS)
        self.assertEqual(kv.get_secret(self.home, "keygate:Demo")["password"], SECRET)
        kv.remove_passphrase(self.home, PASS)
        self.assertTrue(Path(self.home, "keygate-vault.key").exists())
        self.assertEqual(kv.get_secret(self.home, "keygate:Demo")["password"], SECRET)

    def test_meta_keeps_no_secret_material(self):
        self._add()
        kv.set_passphrase(self.home, PASS)
        meta = json.loads(Path(self.home, "keygate-vault.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["mode"], "passphrase")
        self.assertIn("salt", meta)
        self.assertNotIn("key", meta)
        self.assertNotIn(PASS, json.dumps(meta))

    def test_remove_item(self):
        self._add()
        self.assertTrue(kv.remove_item(self.home, "keygate:Demo"))
        self.assertEqual(kv.list_items(self.home), [])


if __name__ == "__main__":
    unittest.main()
