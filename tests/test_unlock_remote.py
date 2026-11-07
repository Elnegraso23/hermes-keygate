"""Modo `remote unlock` (opt-in): descifrar el vault sellado a tmpfs con TTL.

No toca el vault real: crea blobs gpg desechables en un HOME temporal.
"""
import importlib
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sync"))
import keygate_lib as kg  # noqa: E402

PW = "clave-de-prueba-123"


@pytest.fixture()
def sealed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".hermes").mkdir(parents=True)
    shm = tmp_path / "shm"
    shm.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("KEYGATE_SHM", str(shm))
    v = home / ".keygate-vault"
    v.mkdir()
    for name, data in (("hermes.kdbx", b"DBDATA"), ("agent.key", b"KEYSECRET")):
        raw = tmp_path / (name + ".raw")
        raw.write_bytes(data)
        subprocess.run(
            ["gpg", "--batch", "--yes", "--quiet", "--symmetric",
             "--cipher-algo", "AES256", "--pinentry-mode", "loopback",
             "--passphrase-fd", "0", "-o", str(v / (name + ".gpg")), str(raw)],
            input=PW.encode(), check=True)
    return home


def _ks():
    return importlib.import_module("keygate_sync")


def test_unlock_writes_tmpfs_and_state(sealed):
    ks = _ks()
    ok, err, exp = ks.unlock_vault(PW)
    assert ok, err
    live = kg.live_paths()
    assert live, "no quedó estado de sesión"
    db, key = live
    assert Path(db).read_bytes() == b"DBDATA"
    assert Path(key).read_bytes() == b"KEYSECRET"
    assert exp > time.time()
    kg.live_shred()
    assert kg.live_paths() is None


def test_wrong_passphrase_leaves_vault_closed(sealed):
    ks = _ks()
    ok, err, _ = ks.unlock_vault("no-es-la-clave")
    assert not ok
    assert err == "wrong passphrase"
    assert kg.live_paths() is None


def test_not_sealed(sealed, tmp_path, monkeypatch):
    ks = _ks()
    monkeypatch.setenv("HOME", str(tmp_path / "otro"))
    ok, err, _ = ks.unlock_vault(PW)
    assert not ok and err == "vault not sealed"


def test_expired_state_is_ignored(sealed):
    ok, err, _ = _ks().unlock_vault(PW)
    assert ok, err
    db, key = kg.live_paths()
    kg.live_set(db, key, -10)  # ya caducado
    assert kg.live_paths() is None


def test_unlock_mode_defaults_off(monkeypatch):
    ks = _ks()
    monkeypatch.delenv("KEYGATE_UNLOCK", raising=False)
    assert ks.unlock_mode() == "off"
    monkeypatch.setenv("KEYGATE_UNLOCK", "remote")
    assert ks.unlock_mode() == "remote"
