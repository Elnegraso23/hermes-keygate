"""keygate_lib: redaction, KeePassXC resolution, sessions, audit.

Security boundaries:
- Full secrets only exist in this module's process memory, briefly, inside
  resolve_*() / fill handlers. They are NEVER returned to the model.
- Tool handlers return metadata {alias, hint} or {ok, filled_fields} only.
- keepassxc-cli runs with argv list (no shell), keyfile-only operative DB
  (--no-password -k KEYFILE), stdin DEVNULL, stderr discarded, 30s timeout.
- Memory zeroization is best-effort in CPython (bytearray + del); the real
  guarantee is "never leaves this process except over CDP to the page".
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

TIMEOUT = 30.0
AUDIT_NAME = "keygate-audit.jsonl"
SESSION_DIR_NAME = "hermes-keygate"

# ---------------------------------------------------------------- redaction ---


def redact_label(label: str) -> str:
    """First + last char visible, rest '*'. Short labels fully masked."""
    s = (label or "").strip()
    if len(s) <= 2:
        return "*" * max(len(s), 3)
    return s[0] + "*" * (len(s) - 2) + s[-1]


def redact_user(user: str) -> str:
    """j***@domain for emails, f***t for bare names. Empty -> '***'."""
    s = (user or "").strip()
    if not s:
        return "***"
    if "@" in s:
        local, _, domain = s.partition("@")
        if len(local) <= 1:
            masked = "*"
        else:
            masked = local[0] + "*" * (len(local) - 1)
        return f"{masked}@{domain}" if domain else masked
    if len(s) <= 2:
        return "*" * 3
    return s[0] + "*" * (len(s) - 2) + s[-1]


def redact_origin(origin: str) -> str:
    """Show TLD + first char of registrable domain: e*******.com."""
    s = (origin or "").strip()
    m = re.search(r"([a-zA-Z0-9*.-]+)", s)
    host = m.group(1) if m else s
    if "." not in host or len(host) <= 4:
        return "***"
    head, _, tail = host.rpartition(".")
    if not head:
        return "***"
    return head[0] + "*" * (len(head) - 1) + "." + tail


def hint_for(label: str, user: str) -> str:
    return f"{redact_label(label)} ({redact_user(user)})"


# ---------------------------------------------------------------- config ---

DEFAULT_DB = str(Path.home() / "Documentos" / "hermes.kdbx")
DEFAULT_KEYFILE = str(Path.home() / ".keepass-agent.key")


def cfg_paths(cfg: dict) -> Tuple[str, str]:
    db = str(cfg.get("db_path") or os.environ.get("KEYGATE_DB") or DEFAULT_DB)
    kf = str(cfg.get("keyfile") or os.environ.get("KEYGATE_KEYFILE") or DEFAULT_KEYFILE)
    return db, kf


# ---------------------------------------------------------------- keepass ---

_ENV_KEEP = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TEMP",
             "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR")


def _child_env() -> Dict[str, str]:
    return {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}


def _kxc() -> str:
    found = shutil.which("keepassxc-cli")
    if not found:
        raise RuntimeError("keepassxc-cli not found — apt install keepassxc")
    return found


def _run_kxc(args: List[str]) -> subprocess.CompletedProcess:
    """argv-only, stdin closed, stderr discarded (may carry secrets)."""
    proc = subprocess.run(
        [_kxc(), *args],
        env=_child_env(), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=TIMEOUT,
    )
    return proc


def zeroize(buf: bytearray) -> None:
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def _secret_to_bytes(s: str) -> bytearray:
    return bytearray(s.encode("utf-8"))


def db_locked(db: str, keyfile: str) -> bool:
    """Probe with `ls` (fast, non-interactive). Exit != 0 with keyfile-only
    DB almost always means locked/missing, never prompt (stdin is DEVNULL)."""
    try:
        p = _run_kxc(["ls", "-k", keyfile, "--no-password", "-q", db])
    except Exception:
        return True
    return p.returncode != 0


def list_entries(db: str, keyfile: str) -> List[str]:
    """Entry paths (titles/groups), metadata only. Empty when locked."""
    p = _run_kxc(["ls", "-R", "-k", keyfile, "--no-password", "-q", db])
    if p.returncode != 0:
        return []
    out = []
    for line in (p.stdout or "").splitlines():
        t = line.strip()
        if t and not t.startswith("Entries") and t != "/":
            out.append(t)
    return out


def show_field(db: str, keyfile: str, entry: str, field: str) -> Optional[str]:
    """Resolve ONE field server-side. field in {password, username, totp, url}."""
    if field == "totp":
        args = ["show", "-k", keyfile, "--no-password", "-q", "-t", "-s", db, entry]
    elif field == "password":
        args = ["show", "-k", keyfile, "--no-password", "-q", "-s", "-a", "Password", db, entry]
    elif field == "username":
        args = ["show", "-k", keyfile, "--no-password", "-q", "-a", "UserName", db, entry]
    elif field == "url":
        args = ["show", "-k", keyfile, "--no-password", "-q", "-a", "URL", db, entry]
    else:
        return None
    try:
        p = _run_kxc(args)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    val = (p.stdout or "").strip()
    return val or None


def parse_kpx_ref(ref: str) -> Optional[Tuple[str, str]]:
    """kpx://alias/field -> (alias, field)."""
    m = re.match(r"^kpx://([^/]+)/([^/]+)$", (ref or "").strip())
    if not m:
        return None
    alias, field = m.group(1).strip(), m.group(2).strip().lower()
    if not alias or field not in ("password", "username", "user", "totp", "url"):
        return None
    if field == "user":
        field = "username"
    return alias, field


# ---------------------------------------------------------------- audit ---


def audit(home: Path, event: dict) -> None:
    try:
        home.mkdir(parents=True, exist_ok=True)
        fp = home / AUDIT_NAME
        event = {"ts": int(time.time()), **event}
        with open(fp, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        try:
            os.chmod(fp, 0o600)
        except Exception:
            pass
    except Exception:
        pass


# ---------------------------------------------------------------- sessions (tmpfs TTL) ---


def session_dir() -> Path:
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or "/dev/shm")
    d = base / SESSION_DIR_NAME
    try:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    except Exception:
        pass
    return d


def session_ensure(domain: str, ttl_seconds: int = 4 * 3600) -> dict:
    """Opaque handle for an ephemeral session. Stores NO secret, only expiry."""
    d = session_dir()
    fp = d / (re.sub(r"[^a-z0-9.-]", "_", domain.lower()) + ".json")
    now = int(time.time())
    try:
        cur = json.loads(fp.read_text(encoding="utf-8"))
        if int(cur.get("expires_at", 0)) > now:
            return {"handle": cur["handle"], "valid": True,
                    "expires_at": cur["expires_at"]}
    except Exception:
        pass
    handle = "sess_" + os.urandom(8).hex()
    rec = {"handle": handle, "domain": domain, "created_at": now,
           "expires_at": now + int(ttl_seconds)}
    try:
        fp.write_text(json.dumps(rec), encoding="utf-8")
        os.chmod(fp, 0o600)
    except Exception:
        pass
    return {"handle": handle, "valid": False, "expires_at": rec["expires_at"]}


def session_invalidate(domain: str) -> bool:
    fp = session_dir() / (re.sub(r"[^a-z0-9.-]", "_", domain.lower()) + ".json")
    try:
        fp.unlink()
        return True
    except Exception:
        return False
