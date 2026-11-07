"""keygate_vault — encrypted store owned by keygate (optional passphrase).

Two modes, chosen at install time:

  key         Fernet key in a 0600 file next to the ciphertext (fast, no prompt)
  passphrase  Fernet key derived with scrypt from a passphrase the user types;
              nothing usable is left on disk

The passphrase is NEVER passed through a tool argument or the chat: it is read
by this CLI with getpass (or by the web page over a local session). A successful
unlock is cached in memory only, for CACHE_TTL seconds.

Files (all 0600, under ~/.hermes/):
  keygate-vault.meta.json   mode + KDF parameters + salt (no secrets)
  keygate-vault.enc         Fernet ciphertext of the item list
  keygate-vault.key         present only in `key` mode

The module deliberately does not import Hermes internals: it must survive a
Hermes upgrade.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

CACHE_TTL = 900  # seconds an unlocked key lives in memory
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

_cache: dict = {"key": None, "expires": 0.0, "home": None}


def _home(home=None) -> Path:
    if home is None:
        return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
    return Path(home)


def paths(home=None) -> dict:
    h = _home(home)
    return {
        "meta": h / "keygate-vault.meta.json",
        "enc": h / "keygate-vault.enc",
        "key": h / "keygate-vault.key",
    }


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read_meta(home=None) -> dict:
    fp = paths(home)["meta"]
    if not fp.exists():
        return {}
    try:
        return json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        return {}


def status(home=None) -> dict:
    meta = _read_meta(home)
    p = paths(home)
    return {
        "initialised": bool(meta),
        "mode": meta.get("mode"),
        "items": len(_raw_items(home, allow_locked=True) or []),
        "ciphertext": p["enc"].exists(),
        "keyfile": p["key"].exists(),
        "unlocked": bool(_cached_key(home)),
        "cache_ttl_seconds": CACHE_TTL,
    }


# --------------------------------------------------------------- key handling ---

def _cached_key(home=None) -> Optional[bytes]:
    if _cache["key"] and _cache["expires"] > time.time() and _cache["home"] == str(_home(home)):
        return _cache["key"]
    return None


def _derive(passphrase: str, salt: bytes, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P) -> bytes:
    import hashlib
    dk = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                        n=n, r=r, p=p, dklen=32, maxmem=132 * 1024 * 1024)
    return base64.urlsafe_b64encode(dk)


def _put_cache(home, key: bytes) -> None:
    _cache.update({"key": key, "expires": time.time() + CACHE_TTL,
                   "home": str(_home(home))})


def lock(home=None) -> None:
    _cache.update({"key": None, "expires": 0.0, "home": None})


def _fernet(home, passphrase: Optional[str] = None, create: bool = False):
    from cryptography.fernet import Fernet
    meta = _read_meta(home)
    if not meta:
        if not create:
            return None
        return None
    mode = meta.get("mode")
    if mode == "key":
        kp = paths(home)["key"]
        if not kp.exists():
            raise RuntimeError("vault key file missing (mode=key)")
        return Fernet(kp.read_bytes())
    # passphrase mode
    key = _cached_key(home)
    if key is None:
        if passphrase is None:
            raise PermissionError("vault is locked: passphrase required")
        salt = base64.b64decode(meta["salt"])
        key = _derive(passphrase, salt, meta.get("n", SCRYPT_N),
                      meta.get("r", SCRYPT_R), meta.get("p", SCRYPT_P))
        # prove it before caching
        try:
            Fernet(key).decrypt(paths(home)["enc"].read_bytes())
        except Exception:
            raise PermissionError("wrong passphrase")
        _put_cache(home, key)
    return Fernet(key)


def init(home=None, passphrase: Optional[str] = None, force: bool = False) -> dict:
    from cryptography.fernet import Fernet
    p = paths(home)
    if p["meta"].exists() and not force:
        return {"success": False, "error": "vault already initialised", **status(home)}
    if passphrase:
        salt = os.urandom(16)
        key = _derive(passphrase, salt)
        meta = {"version": 1, "mode": "passphrase", "salt": base64.b64encode(salt).decode(),
                "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                "created": int(time.time())}
        _atomic_write(p["meta"], json.dumps(meta, indent=2).encode())
        if p["key"].exists():
            p["key"].unlink()
    else:
        key = Fernet.generate_key()
        meta = {"version": 1, "mode": "key", "created": int(time.time())}
        _atomic_write(p["key"], key)
        _atomic_write(p["meta"], json.dumps(meta, indent=2).encode())
    _atomic_write(p["enc"], Fernet(key).encrypt(json.dumps(
        {"version": 1, "items": {}}).encode()))
    _put_cache(home, key)
    return {"success": True, **status(home)}


def set_passphrase(home=None, passphrase: Optional[str] = None,
                   old: Optional[str] = None) -> dict:
    """Add (or change) the passphrase, re-encrypting everything in place."""
    from cryptography.fernet import Fernet
    p = paths(home)
    if not p["meta"].exists():
        return {"success": False, "error": "vault not initialised"}
    items = _read_all(home, passphrase=old)
    salt = os.urandom(16)
    key = _derive(passphrase or "", salt)
    meta = {"version": 1, "mode": "passphrase", "salt": base64.b64encode(salt).decode(),
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "created": _read_meta(home).get("created", int(time.time())),
            "rotated": int(time.time())}
    _atomic_write(p["enc"], Fernet(key).encrypt(json.dumps(items).encode()))
    _atomic_write(p["meta"], json.dumps(meta, indent=2).encode())
    if p["key"].exists():
        p["key"].unlink()
    _put_cache(home, key)
    return {"success": True, **status(home)}


def remove_passphrase(home=None, passphrase: Optional[str] = None) -> dict:
    from cryptography.fernet import Fernet
    p = paths(home)
    items = _read_all(home, passphrase=passphrase)
    key = Fernet.generate_key()
    _atomic_write(p["key"], key)
    _atomic_write(p["enc"], Fernet(key).encrypt(json.dumps(items).encode()))
    _atomic_write(p["meta"], json.dumps(
        {"version": 1, "mode": "key", "created": _read_meta(home).get("created", int(time.time())),
         "rotated": int(time.time())}, indent=2).encode())
    _put_cache(home, key)
    return {"success": True, **status(home)}


# ------------------------------------------------------------------- items ---

def _read_all(home=None, passphrase: Optional[str] = None) -> dict:
    p = paths(home)
    if not p["enc"].exists():
        return {"version": 1, "items": {}}
    f = _fernet(home, passphrase=passphrase)
    if f is None:
        return {"version": 1, "items": {}}
    return json.loads(f.decrypt(p["enc"].read_bytes()).decode())


def _raw_items(home=None, allow_locked: bool = False) -> list:
    try:
        return list(_read_all(home).get("items", {}).values())
    except PermissionError:
        return [] if allow_locked else (_ for _ in ()).throw(
            PermissionError("vault is locked: run `python3 keygate_vault.py unlock`"))


def _write_all(home, data: dict) -> None:
    p = paths(home)
    f = _fernet(home)
    if f is None:
        raise PermissionError("vault not initialised")
    _atomic_write(p["enc"], f.encrypt(json.dumps(data).encode()))


def _new_id() -> str:
    return "kgv_" + base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip("=")


def list_items(home=None) -> list:
    """Metadata only — never passwords or identifiers."""
    out = []
    for it in _raw_items(home, allow_locked=True):
        out.append({"id": it.get("id"), "label": it.get("label"),
                    "origin": it.get("origin"),
                    "identifier_type": it.get("identifier_type"),
                    "has_otp": bool(it.get("otp_secret")),
                    "updated": it.get("updated")})
    return sorted(out, key=lambda x: (x.get("label") or ""))


def add_item(home=None, label: str = "", origin: str = "", identifier: str = "",
             identifier_type: str = "username", password: str = "",
             otp_secret: str = "") -> dict:
    if not label or not origin:
        raise ValueError("label and origin are required")
    data = _read_all(home)
    items = data.setdefault("items", {})
    for existing in list(items.values()):
        if existing.get("label") == label:
            del items[existing["id"]]
    iid = _new_id()
    items[iid] = {"id": iid, "label": label, "origin": origin,
                  "identifier": identifier, "identifier_type": identifier_type,
                  "password": password, "otp_secret": otp_secret,
                  "created": int(time.time()), "updated": int(time.time())}
    _write_all(home, data)
    return {"id": iid, "label": label, "origin": origin}


def get_secret(home=None, label: str = "", passphrase: Optional[str] = None) -> dict:
    for it in _read_all(home, passphrase=passphrase).get("items", {}).values():
        if it.get("label") == label or it.get("id") == label:
            return it
    return {}


def remove_item(home=None, label: str = "") -> bool:
    data = _read_all(home)
    items = data.setdefault("items", {})
    for iid, it in list(items.items()):
        if it.get("label") == label or iid == label:
            del items[iid]
            _write_all(home, data)
            return True
    return False


# --------------------------------------------------------------------- CLI ---

def _cli(argv) -> int:
    cmd = argv[1] if len(argv) > 1 else "status"
    home = None
    args = [a for a in argv[2:] if not a.startswith("--")]
    flags = {a for a in argv[2:] if a.startswith("--")}

    if cmd == "status":
        print(json.dumps(status(home), indent=2))
        return 0
    if cmd == "list":
        print(json.dumps(list_items(home), indent=2))
        return 0
    if cmd == "init":
        pw = None
        if "--passphrase" in flags:
            pw = getpass.getpass("keygate vault passphrase: ")
            if pw != getpass.getpass("confirm: "):
                print("mismatch"); return 2
            if len(pw) < 12:
                print("passphrase too short (12+ chars)"); return 2
        print(json.dumps(init(home, passphrase=pw,
                              force="--force" in flags), indent=2))
        return 0
    if cmd == "unlock":
        pw = getpass.getpass("keygate vault passphrase: ")
        try:
            _fernet(home, passphrase=pw)
        except PermissionError as exc:
            print(f"failed: {exc}"); return 1
        print(json.dumps({"unlocked": True, "ttl": CACHE_TTL}))
        return 0
    if cmd == "set-passphrase":
        old = None if _read_meta(home).get("mode") == "key" else getpass.getpass("current passphrase: ")
        pw = getpass.getpass("new passphrase: ")
        if pw != getpass.getpass("confirm: "):
            print("mismatch"); return 2
        if len(pw) < 12:
            print("passphrase too short (12+ chars)"); return 2
        print(json.dumps(set_passphrase(home, pw, old), indent=2))
        return 0
    if cmd == "remove-passphrase":
        old = None if _read_meta(home).get("mode") == "key" else getpass.getpass("current passphrase: ")
        print(json.dumps(remove_passphrase(home, old), indent=2))
        return 0
    if cmd == "delete":
        if not args:
            print("usage: delete <label>"); return 2
        print(json.dumps({"removed": remove_item(home, args[0])}))
        return 0
    if cmd == "lock":
        lock(home)
        print(json.dumps({"unlocked": False}))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
