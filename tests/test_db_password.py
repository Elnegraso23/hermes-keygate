"""DB master password: keyfile-only vs keyfile+password (optional at install).

Guarantees under test:
  * kxc_auth() adds --no-password ONLY when no master password is configured
  * the password never appears in argv, only on stdin
  * a DB created with keyfile+password really rejects --no-password and the
    wrong password, and opens with the right one fed on stdin
    (integration test; skipped when keepassxc-cli is unavailable)

No Hermes imports: runs anywhere (CI included).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import keygate_lib as kg  # noqa: E402

PASSWORD = "testpass-not-a-real-one"


class TestAuthFlags(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.pop(kg.DB_PASSWORD_ENV, None)

    def tearDown(self):
        os.environ.pop(kg.DB_PASSWORD_ENV, None)
        if self._old is not None:
            os.environ[kg.DB_PASSWORD_ENV] = self._old

    def test_keyfile_only_keeps_no_password(self):
        self.assertFalse(kg.db_uses_password())
        self.assertEqual(kg.kxc_auth("/k/key"), ["-k", "/k/key", "--no-password"])

    def test_password_mode_drops_no_password(self):
        os.environ[kg.DB_PASSWORD_ENV] = PASSWORD
        self.assertTrue(kg.db_uses_password())
        self.assertEqual(kg.kxc_auth("/k/key"), ["-k", "/k/key"])

    def test_empty_value_is_treated_as_absent(self):
        os.environ[kg.DB_PASSWORD_ENV] = ""
        self.assertFalse(kg.db_uses_password())
        self.assertIn("--no-password", kg.kxc_auth("/k/key"))

    def test_password_never_in_argv(self):
        os.environ[kg.DB_PASSWORD_ENV] = PASSWORD
        self.assertNotIn(PASSWORD, " ".join(kg.kxc_auth("/k/key")))


@unittest.skipUnless(shutil.which("keepassxc-cli"), "keepassxc-cli no instalado")
class TestRealDatabase(unittest.TestCase):
    """End-to-end against a throwaway DB with keyfile + master password."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.kf = self.dir / "k.key"
        self.kf.write_bytes(b"k" * 64)
        os.chmod(self.kf, 0o600)
        self.db = self.dir / "db.kdbx"
        proc = subprocess.run(
            ["keepassxc-cli", "db-create", "--set-key-file", str(self.kf), "-p", str(self.db)],
            input=f"{PASSWORD}\n{PASSWORD}\n", capture_output=True, text=True, timeout=60)
        if not self.db.exists():
            self.skipTest(f"db-create falló: {proc.stderr[:120]}")
        self._old = os.environ.pop(kg.DB_PASSWORD_ENV, None)

    def tearDown(self):
        os.environ.pop(kg.DB_PASSWORD_ENV, None)
        if self._old is not None:
            os.environ[kg.DB_PASSWORD_ENV] = self._old
        shutil.rmtree(self.dir, ignore_errors=True)

    def _ls(self, flags):
        return subprocess.run(
            ["keepassxc-cli", "ls", *flags, "-q", str(self.db)],
            input=f"{PASSWORD}\n", capture_output=True, text=True, timeout=30)

    def test_no_password_flag_is_rejected(self):
        proc = self._ls(["-k", str(self.kf), "--no-password"])
        self.assertNotEqual(proc.returncode, 0,
                            "una DB con contraseña maestra no debe abrir con --no-password")

    def test_wrong_password_is_rejected(self):
        proc = subprocess.run(
            ["keepassxc-cli", "ls", "-k", str(self.kf), "-q", str(self.db)],
            input="definitely-wrong\n", capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)

    def test_right_password_opens_via_env(self):
        os.environ[kg.DB_PASSWORD_ENV] = PASSWORD
        self.assertIn("-k", kg.kxc_auth(str(self.kf)))
        proc = self._ls(kg.kxc_auth(str(self.kf)))
        self.assertEqual(proc.returncode, 0, proc.stderr[:200])


if __name__ == "__main__":
    unittest.main()
