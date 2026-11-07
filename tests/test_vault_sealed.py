"""Estado 'vault sellado': el agente detecta que no puede hacer fill y NO lo
intenta; la passphrase solo la teclea la persona en `keygate-vault open`.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import keygate_lib as kg  # noqa: E402


def test_vault_not_sealed_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert kg.vault_sealed() is False


def test_vault_sealed_when_blob_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    d = tmp_path / ".keygate-vault"
    d.mkdir()
    (d / kg.SEALED_DB_NAME).write_bytes(b"ciphertext")
    assert kg.vault_sealed() is True


def test_vault_sealed_ignores_unreadable_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".keygate-vault").write_text("soy un archivo, no un directorio")
    assert kg.vault_sealed() is False


def test_missing_keyfile_counts_as_locked(tmp_path):
    """Sin keyfile y sin vault sellado, db_locked debe decir 'locked'."""
    db = tmp_path / "hermes.kdbx"
    db.write_bytes(b"x")
    assert kg.db_locked(str(db), str(tmp_path / "no-existe.key")) is True


# --- política de relleno automático (fill_policy) ---

def test_fill_policy_defaults_to_ask():
    assert kg.fill_policy_auto({}) is False
    assert kg.fill_policy_auto({"fill_policy": "ask"}) is False


def test_fill_policy_auto_only_when_asked():
    assert kg.fill_policy_auto({"fill_policy": "auto"}) is True
    assert kg.fill_policy_auto({"fill_policy": " AUTO "}) is True


def test_fill_policy_ignores_garbage():
    assert kg.fill_policy_auto({"fill_policy": 123}) is False
    assert kg.fill_policy_auto(None) is False
