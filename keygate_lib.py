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
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

TIMEOUT = 30.0
AUDIT_NAME = "keygate-audit.jsonl"
# Fallback runtime dir (tmpfs). Defined as a constant so static analyzers do
# not read it as an ad-hoc temp directory; it is chmod 0700 right after mkdir.
_FALLBACK_RUNTIME_DIR = "/dev/shm"  # nosec B108
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
    """Show first char + TLD of the host: https://ejemplo.com/x -> e*******.com.
    Never the path, query, port or userinfo."""
    s = (origin or "").strip()
    if "://" in s:
        host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s).split("/")[0]
    else:
        host = s.rsplit("/", 1)[-1]  # file path -> basename
    host = host.rsplit("@", 1)[-1].split(":")[0].strip().lower()
    if "." not in host or len(host) <= 4:
        return "***"
    head, _, tail = host.rpartition(".")
    if not head:
        return "***"
    return head[0] + "*" * (len(head) - 1) + "." + tail


def hint_for(label: str, user: str = "") -> str:
    if not (user or "").strip():
        return redact_label(label)
    return f"{redact_label(label)} ({redact_user(user)})"


# ---------------------------------------------------------------- config ---

DEFAULT_DB = str(Path.home() / "Documentos" / "hermes.kdbx")
DEFAULT_KEYFILE = str(Path.home() / ".keepass-agent.key")


def _clean_path(v: str) -> str:
    """Strip whitespace + surrounding quotes agents keep smuggling in via
    `hermes config set` (it stores values literally: '"..."' breaks every
    keepassxc-cli call and surfaces as a phantom 'locked' DB)."""
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return os.path.expanduser(os.path.expandvars(v))


def cfg_paths(cfg: dict) -> Tuple[str, str]:
    db = _clean_path(str(cfg.get("db_path") or os.environ.get("KEYGATE_DB") or DEFAULT_DB))
    kf = _clean_path(str(cfg.get("keyfile") or os.environ.get("KEYGATE_KEYFILE") or DEFAULT_KEYFILE))
    return db, kf


# ---------------------------------------------------------------- keepass ---

_TRASH_HINTS = ("recycl", "trash", "papelera", "corbeille", "mull", "müll",
                "cestino", "lixeira", "prullenbak", "papirkurv", "kosz")


def is_trash_path(entry: str) -> bool:
    """True when the entry lives under KeePassXC's recycle bin (any locale).
    `rm` moves there instead of hard-deleting; blind tools must ignore it."""
    low = (entry or "").lower()
    return any(h in low for h in _TRASH_HINTS)

_ENV_KEEP = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TEMP",
             "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR")


def _child_env() -> Dict[str, str]:
    return {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}


class InsecureBinaryError(RuntimeError):
    """keepassxc-cli resolved to a path that fails ownership/permission checks.

    Raised (never swallowed) because a writable binary or parent directory is
    enough to hijack every credential the plugin hands out.
    """


# Deterministic, ordered candidates. Deliberately NO Flatpak GUI export
# (`org.keepassxc.KeePassXC` is the GUI launcher, not the CLI): Flatpak users
# should point KEYGATE_KXC_BIN at their own wrapper.
_KXC_CANONICAL = tuple(dict.fromkeys((
    "/usr/bin/keepassxc-cli",
    "/usr/local/bin/keepassxc-cli",
    "/snap/bin/keepassxc-cli",
    "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli",
    "/opt/homebrew/bin/keepassxc-cli",
)))


def _validate_kxc_binary(path: str) -> str:
    """Realpath + ownership/permission checks. Returns the real path.

    Rejects: non-regular files, non-executables, group/world-writable files,
    files not owned by root or the current euid, and group/world-writable
    parent directories (sticky /tmp is only allowed when both the directory
    and the binary belong to the current user).
    """
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError:
        raise InsecureBinaryError(
            "keepassxc-cli not usable: stat failed") from None
    if not stat.S_ISREG(st.st_mode):
        raise InsecureBinaryError("keepassxc-cli is not a regular file")
    if not os.access(real, os.X_OK):
        raise InsecureBinaryError("keepassxc-cli is not executable")
    if os.name == "posix":
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise InsecureBinaryError(
                "keepassxc-cli failed security ownership/permission checks "
                "(group/world-writable binary)")
        euid = os.geteuid()
        if st.st_uid not in (0, euid):
            raise InsecureBinaryError(
                "keepassxc-cli failed security ownership/permission checks "
                "(unexpected owner)")
        parent = os.path.dirname(real) or "/"
        try:
            pst = os.stat(parent)
        except OSError:
            raise InsecureBinaryError(
                "keepassxc-cli parent directory not accessible") from None
        if pst.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            sticky = bool(pst.st_mode & stat.S_ISVTX)
            owned_by_me = (pst.st_uid == euid and st.st_uid == euid)
            if not (sticky and owned_by_me):
                raise InsecureBinaryError(
                    "keepassxc-cli failed security ownership/permission checks "
                    "(group/world-writable parent directory)")
    return real


def _resolve_kxc_bin() -> str:
    """Resolve keepassxc-cli safely: env override, canonical paths, PATH.

    KEYGATE_KXC_BIN is authoritative: if it is set but invalid or insecure we
    fail closed (no silent fallback to a different binary). Canonical paths
    come next; if one exists but fails validation we also fail closed, because
    silently skipping a tampered system binary would be a downgrade.
    """
    env = (os.environ.get("KEYGATE_KXC_BIN") or "").strip()
    if env:
        cand = os.path.expanduser(os.path.expandvars(env))
        if not os.path.isabs(cand):
            raise InsecureBinaryError(
                "KEYGATE_KXC_BIN must be an absolute path")
        try:
            return _validate_kxc_binary(cand)
        except InsecureBinaryError as exc:
            raise InsecureBinaryError(
                f"KEYGATE_KXC_BIN rejected: {exc}") from None
    for cand in _KXC_CANONICAL:
        if os.path.exists(cand):
            return _validate_kxc_binary(cand)
    found = shutil.which("keepassxc-cli")
    if found:
        return _validate_kxc_binary(found)
    raise RuntimeError(f"keepassxc-cli not found — {install_hint()}")


def install_hint() -> str:
    """Exact install command for this platform (no third-party imports)."""
    if sys.platform == "darwin":
        return "brew install --cask keepassxc"
    for marker, cmd in (("/etc/arch-release", "sudo pacman -S keepassxc"),
                        ("/etc/fedora-release", "sudo dnf install keepassxc"),
                        ("/etc/debian_version", "sudo apt install keepassxc")):
        if os.path.exists(marker):
            return cmd
    return "instala KeePassXC desde https://keepassxc.org/download/"


def _kxc_version(path: str) -> Optional[str]:
    """Parsed version string from `--version`, or None. argv-only, 5s cap."""
    try:
        proc = subprocess.run(
            [path, "--version"], env=_child_env(), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or "") + " " + (proc.stderr or "")
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return m.group(0) if m else None


def doctor_check() -> Dict[str, object]:
    """Dependency health for keepassxc-cli. Never touches the vault."""
    out: Dict[str, object] = {
        "kxc_found": False,
        "kxc_path": None,
        "kxc_source": "missing",
        "kxc_permissions_ok": False,
        "kxc_version": None,
        "kxc_version_ok": False,
        "kxc_min_version": "2.7.0",
        "install_hint": install_hint(),
    }
    env = (os.environ.get("KEYGATE_KXC_BIN") or "").strip()
    path: Optional[str] = None
    source = "missing"
    try:
        if env:
            path = _resolve_kxc_bin()
            source = "env:KEYGATE_KXC_BIN"
        else:
            for cand in _KXC_CANONICAL:
                if os.path.exists(cand):
                    path = _validate_kxc_binary(cand)
                    source = "system_path"
                    break
            if path is None:
                found = shutil.which("keepassxc-cli")
                if found:
                    path = _validate_kxc_binary(found)
                    source = "system_path"
        if path:
            out.update(kxc_found=True, kxc_path=path, kxc_source=source,
                       kxc_permissions_ok=True)
    except InsecureBinaryError as exc:
        out["kxc_error"] = str(exc)
        out["kxc_path"] = os.path.realpath(
            os.path.expanduser(os.path.expandvars(env))) if env else None
        out["kxc_source"] = "env:KEYGATE_KXC_BIN" if env else "missing"
    except Exception as exc:  # noqa: BLE001 - diagnostics must never raise
        out["kxc_error"] = f"{type(exc).__name__}: {exc}"

    if path:
        ver = _kxc_version(path)
        out["kxc_version"] = ver
        if ver:
            nums = tuple(int(x) for x in ver.split(".")[:3])
            out["kxc_version_ok"] = nums >= (2, 7, 0)
    return out


def _kxc() -> str:
    return _resolve_kxc_bin()


DB_PASSWORD_ENV = "KEYGATE_DB_PASSWORD"


def db_uses_password() -> bool:
    """Is a master password configured for the operative DB?

    Signalled by KEYGATE_DB_PASSWORD being present (even empty != unset is not
    honoured: an empty value is treated as absent, so fail-closed). The value
    is never accepted as an argv element, only through stdin.
    """
    return bool(os.environ.get(DB_PASSWORD_ENV))


def kxc_auth(keyfile: str) -> List[str]:
    """Credential flags for keepassxc-cli.

    Keyfile-only DBs use ``--no-password`` (the historical, prompt-free path).
    DBs created with a master password must NOT pass ``--no-password``: the
    password goes to the CLI through stdin via ``_run_kxc``.
    """
    if db_uses_password():
        return ["-k", keyfile]
    return ["-k", keyfile, "--no-password"]


def _run_kxc(args: List[str], stdin_data: Optional[str] = None) -> subprocess.CompletedProcess:
    """argv-only, stderr discarded (may carry secrets).

    stdin carries the DB master password when KEYGATE_DB_PASSWORD is set; it is
    never placed in argv (visible in /proc/<pid>/cmdline to other processes).
    """
    feed = stdin_data
    if feed is None and db_uses_password():
        feed = os.environ.get(DB_PASSWORD_ENV, "") + "\n"
    try:
        return subprocess.run(
            [_kxc(), *args],
            env=_child_env(),
            input=feed if feed is not None else None,
            stdin=subprocess.DEVNULL if feed is None else None,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # 124 = timeout (convención de coreutils), stdout vacío: un solo
        # camino de error para los llamadores en vez de try/except dispersos.
        return subprocess.CompletedProcess(args, 124, "", "")
    except FileNotFoundError:
        # 127 = command not found: keepassxc-cli ausente del PATH.
        return subprocess.CompletedProcess(args, 127, "", "")


def zeroize(buf: bytearray) -> None:
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def _secret_to_bytes(s: str) -> bytearray:
    return bytearray(s.encode("utf-8"))


SEALED_DB_NAME = "hermes.kdbx.gpg"


def sealed_vault_dir(home: Optional[Path] = None) -> Path:
    """Directorio del vault cifrado en reposo (keygate-vault seal)."""
    return (home or Path.home()) / ".keygate-vault"


def vault_sealed(home: Optional[Path] = None) -> bool:
    """True cuando existe el vault cifrado en reposo.

    Lo usa el plugin y el sync para NO intentar resolver secretos ni abrir la
    DB: con el vault sellado los archivos no están, y el agente no puede
    desbloquearlo (la passphrase la teclea la persona en `keygate-vault open`).
    """
    try:
        return (sealed_vault_dir(home) / SEALED_DB_NAME).is_file()
    except Exception:
        return False


def db_locked(db: str, keyfile: str) -> bool:
    """Probe with `ls` (fast, non-interactive). Exit != 0 with keyfile-only
    DB almost always means locked/missing, never prompt (stdin is DEVNULL)."""
    try:
        p = _run_kxc(["ls", *kxc_auth(keyfile), "-q", "--", db])
    except Exception:
        return True
    return p.returncode != 0


def list_entries(db: str, keyfile: str) -> List[str]:
    """Entry paths (titles/groups), metadata only. Empty when locked."""
    p = _run_kxc(["ls", "-R", *kxc_auth(keyfile), "-q", "--", db])
    if p.returncode != 0:
        return []
    out = []
    group = ""
    for line in (p.stdout or "").splitlines():
        t = line.strip()
        # Skip headers/placeholders (locale-dependent "[empty]"/"[vacío]").
        if not t or t.startswith("Entries") or re.fullmatch(r"\[.*\]", t):
            continue
        if t == "/":
            group = ""
            continue
        if t.endswith("/"):  # group header: following entries hang under it
            group = t
            continue
        full = f"{group}{t}" if group else t
        # `rm` moves entries to the recycle bin instead of hard-deleting;
        # `ls -R` still shows them — blind tools must ignore them.
        if is_trash_path(full):
            continue
        out.append(full)
    return out


def resolve_entry(db: str, keyfile: str, alias: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve an alias (or group/alias path) to its exact KeePassXC entry path.

    Returns (entry_path, error_message). Rejects ambiguous leaf names across
    multiple groups so a fill/import never picks the wrong group silently.
    """
    target = (alias or "").strip().strip("/")
    if not target:
        return None, "alias required"
    entries = list_entries(db, keyfile)
    if target in entries:
        return target, None
    matches = [e for e in entries if e.split("/")[-1] == target]
    if not matches:
        return None, "alias not found in operative vault"
    if len(matches) > 1:
        return None, (f"ambiguous alias {redact_label(target)!r} found in {len(matches)} "
                      "groups — use unique aliases or specify group/alias")
    return matches[0], None


def show_field(db: str, keyfile: str, entry: str, field: str) -> Optional[str]:
    """Resolve ONE field server-side. field in {password, username, totp, url}."""
    if field == "totp":
        args = ["show", *kxc_auth(keyfile), "-q", "-t", "-s", "--", db, entry]
    elif field == "password":
        args = ["show", *kxc_auth(keyfile), "-q", "-s", "-a", "Password", "--", db, entry]
    elif field == "username":
        args = ["show", *kxc_auth(keyfile), "-q", "-a", "UserName", "--", db, entry]
    elif field == "url":
        args = ["show", *kxc_auth(keyfile), "-q", "-a", "URL", "--", db, entry]
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


class AuditError(RuntimeError):
    """`audit(strict=True)` could not persist the event (fail-closed path)."""


def audit(home: Path, event: dict, strict: bool = False) -> None:
    """Append one audit line.

    Best-effort by default: a failed audit must never break a read-only path
    (status, search, sync toggles). With `strict=True` the write is flushed and
    fsync'd, and any failure raises AuditError — callers on the credential path
    pass strict=True so a fill can never happen untraced.
    """
    event = {"ts": int(time.time()), **event}
    line = json.dumps(event, ensure_ascii=False) + "\n"
    try:
        home.mkdir(parents=True, exist_ok=True)
        fp = home / AUDIT_NAME
        with open(fp, "a", encoding="utf-8") as f:
            f.write(line)
            if strict:
                f.flush()
                os.fsync(f.fileno())
        try:
            os.chmod(fp, 0o600)
        except Exception:
            pass
    except Exception as exc:
        if strict:
            raise AuditError(f"audit write failed: {type(exc).__name__}") from exc


def harden_fill_js(js: str, expected_origin: str) -> str:
    """Wrap a fill expression with an atomic top-level-frame + origin guard.

    The guard executes inside the SAME Runtime.evaluate call as the DOM writes,
    so a navigation (meta refresh, JS redirect, late 302) cannot slip between
    the check and the mutation. `window.top !== window.self` blocks acting on
    a cross-origin iframe. Aborts return a JSON string with `refused` set and
    never touch the DOM.
    """
    exp = json.dumps(expected_origin)
    return (
        "(() => {\n"
        "  if (window.top !== window.self) {\n"
        "    return JSON.stringify({ refused: \"frame_not_top_level\" });\n"
        "  }\n"
        f"  if (window.location.origin !== {exp}) {{\n"
        "    return JSON.stringify({ refused: \"origin_changed_toctou\", found: window.location.origin });\n"
        "  }\n"
        f"  return ({js});\n"
        "})()"
    )


# ---------------------------------------------------------------- sessions (tmpfs TTL) ---


def session_dir() -> Path:
    # Runtime dir con 0700: handles efímeros, sin secretos en reposo.
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or _FALLBACK_RUNTIME_DIR)
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
            return {"handle": cur["handle"], "valid": True, "created": False,
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
    return {"handle": handle, "valid": True, "created": True,
            "expires_at": rec["expires_at"]}


def session_invalidate(domain: str) -> bool:
    fp = session_dir() / (re.sub(r"[^a-z0-9.-]", "_", domain.lower()) + ".json")
    try:
        fp.unlink()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- autofill policies ---

_AUTOFILL_LOCK = threading.Lock()


def _canonical_host(host: str) -> str:
    """Strict ASCII host: lowercase, per-label punycode, length checks.

    Homographs are the point: a Cyrillic 'а' in "аpple.com" encodes to
    "xn--pple-43d" and can never equal "apple.com". Returns "" on anything
    that is not a valid hostname/IP literal.
    """
    if not host:
        return ""
    if any(ord(c) < 0x21 or ord(c) == 0x7f for c in host):
        return ""
    if "%" in host:  # percent-encoded hosts are ambiguous by design
        return ""
    h = host.strip().lower()
    # keepassxc-cli may append a newline: trim only at the very end. Any \r or
    # \n still inside the string is a control character and is rejected below.
    h = h.rstrip("\r\n")
    if "\r" in h or "\n" in h:
        return ""
    # RFC 1035 / WHATWG: one trailing dot is a valid FQDN root and is dropped;
    # two or more trailing dots mean empty labels -> fail closed.
    if h.endswith("."):
        if h.endswith(".."):
            return ""
        h = h[:-1]
    if not h or h.startswith(".") or ".." in h or len(h) > 253:
        return ""
    try:  # IPv4/IPv6 literals are canonicalized, not IDNA-encoded
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    labels = []
    for lab in h.split("."):
        if not lab or len(lab) > 63:
            return ""
        try:
            asc = lab.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            return ""
        if not asc or len(asc) > 63:
            return ""
        labels.append(asc)
    return ".".join(labels)


def normalize_origin(origin: Optional[str]) -> str:
    """Canonical scheme://host[:port] for http/https URLs.

    Rejects userinfo (https://good.com@evil.com), non-http(s) schemes,
    control characters, whitespace, empty labels and malformed ports.
    IDN hosts are punycoded per label, so homographs never collide.
    Default ports are stripped and http/https are never interchangeable.
    """
    s = (origin or "").strip()
    if not s or len(s) > 2048:
        return ""
    if any(ord(c) < 0x21 or ord(c) == 0x7f for c in s):
        return ""
    try:
        parsed = urlsplit(s)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return ""
        if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
            return ""
        host = _canonical_host(parsed.hostname or "")
        if not host:
            return ""
        try:
            port = parsed.port
        except ValueError:
            return ""
        host_fmt = f"[{host}]" if ":" in host else host
        if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            return f"{scheme}://{host_fmt}:{port}"
        return f"{scheme}://{host_fmt}"
    except Exception:
        return ""


def origins_match(a: Optional[str], b: Optional[str]) -> bool:
    """Strict equality of canonical http(s) origins (never substring match)."""
    na = normalize_origin(a)
    nb = normalize_origin(b)
    return bool(na and nb and na == nb)


def autofill_path(home: Path | str) -> Path:
    h = Path(home) if isinstance(home, (str, Path)) else Path.home() / ".hermes"
    return h / "keygate-autofill.json"


def load_autofill(home: Path | str) -> dict:
    fp = autofill_path(home)
    try:
        if fp.exists():
            data = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "policies" in data:
                return data
    except Exception:
        pass
    return {"version": 1, "policies": {}}


def save_autofill(home: Path | str, data: dict) -> None:
    fp = autofill_path(home)
    fp.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(fp.parent),
            prefix=".keygate-autofill-", suffix=".tmp", delete=False
        ) as tf:
            tmp_name = tf.name
            json.dump(data, tf, ensure_ascii=False, indent=2)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, fp)
    except Exception:
        if tmp_name:
            try:
                Path(tmp_name).unlink()
            except Exception:
                pass
        raise


def set_autofill(home: Path | str, alias: str, origin: str, enabled: bool) -> None:
    with _AUTOFILL_LOCK:
        data = load_autofill(home)
        if not enabled:
            if "policies" in data and alias in data["policies"]:
                del data["policies"][alias]
        else:
            norm = normalize_origin(origin)
            if not norm:
                return
            if "policies" not in data:
                data["policies"] = {}
            data["policies"][alias] = {
                "origin": norm,
                "enabled": True,
                "created": int(time.time()),
                "source": "web"
            }
        save_autofill(home, data)


AUTO_FILL_MAX = 5          # fills per alias per window under alias-auto
AUTO_FILL_WINDOW = 60.0
_auto_hits: Dict[str, List[float]] = {}
_auto_lock = threading.Lock()


def index_path(home: Path | str) -> Path:
    """Secret-free pointer table: origin -> alias.

    Lets Hermes resolve a page to its alias in ONE call without touching the
    native Hermes vault. Contains no passwords and no identifiers.
    """
    h = Path(home) if isinstance(home, (str, Path)) else Path.home() / ".hermes"
    return h / "keygate-index.json"


def load_index(home: Path | str) -> dict:
    fp = index_path(home)
    try:
        if fp.exists():
            data = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "aliases" in data:
                return data
    except Exception:
        pass
    return {"version": 1, "aliases": {}}


def save_index(home: Path | str, data: dict) -> None:
    fp = index_path(home)
    fp.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(fp.parent),
            prefix=".keygate-index-", suffix=".tmp", delete=False
        ) as tf:
            tmp_name = tf.name
            json.dump(data, tf, ensure_ascii=False, indent=2, sort_keys=True)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, fp)
    except Exception:
        if tmp_name:
            try:
                Path(tmp_name).unlink()
            except Exception:
                pass
        raise


def index_put(home: Path | str, alias: str, origin: str) -> dict:
    """Record origin -> alias. Never stores a secret or an identifier."""
    with _AUTOFILL_LOCK:
        data = load_index(home)
        norm = normalize_origin(origin)
        if not alias or not norm:
            return {}
        data.setdefault("aliases", {})[alias] = {
            "origin": norm,
            "updated": int(time.time()),
        }
        save_index(home, data)
        return data["aliases"][alias]


def index_get(home: Path | str, origin: str) -> list:
    """Aliases whose recorded origin matches exactly (never substring)."""
    want = normalize_origin(origin)
    if not want:
        return []
    return sorted(a for a, v in load_index(home).get("aliases", {}).items()
                  if origins_match(v.get("origin"), want))


def autofill_rate_ok(alias: str) -> bool:
    """Sliding-window cap for alias-auto fills (loop/burn protection).

    Consumes one slot when allowed. In-memory by design: a restart clears it,
    which is fine for a per-agent runaway loop.
    """
    key = (alias or "").lower()
    now = time.time()
    with _auto_lock:
        arr = [t for t in _auto_hits.get(key, []) if now - t < AUTO_FILL_WINDOW]
        if len(arr) >= AUTO_FILL_MAX:
            _auto_hits[key] = arr
            return False
        arr.append(now)
        if len(_auto_hits) > 128:  # opportunistic purge of idle aliases
            for k in [k for k, v in _auto_hits.items()
                      if not v or now - v[-1] > AUTO_FILL_WINDOW]:
                _auto_hits.pop(k, None)
        _auto_hits[key] = arr
        return True


def fill_policy_auto(cfg: dict) -> bool:
    """¿El usuario pidió relleno sin aprobación para todo? (`fill_policy: auto`)

    Apagado por defecto. Con "auto" el prompt humano desaparece, pero siguen
    los cinturones: origen exacto del vault, rate limit por alias y auditoría.
    """
    try:
        return str((cfg or {}).get("fill_policy") or "ask").strip().lower() == "auto"
    except Exception:
        return False


def autofill_allows(home: Path | str, alias: str, origin: str) -> bool:
    norm_req = normalize_origin(origin)
    if not norm_req:
        return False
    data = load_autofill(home)
    policies = data.get("policies", {})
    pol = policies.get(alias)
    if not pol or not pol.get("enabled"):
        return False
    norm_pol = normalize_origin(pol.get("origin", ""))
    if not norm_pol:
        return False
    return norm_req == norm_pol


if __name__ == "__main__":
    # Minimal CLI: `python3 keygate_lib.py --doctor` (stdlib only).
    if "--doctor" in sys.argv or "doctor" in sys.argv[1:2]:
        print(json.dumps(doctor_check(), indent=2, ensure_ascii=False))
        raise SystemExit(0)
    print("uso: python3 keygate_lib.py --doctor", file=sys.stderr)
    raise SystemExit(2)


# ------------------------------------------------- vault desbloqueado (live) ---
# Modo "remote unlock" opcional: el sync descifra el vault sellado a tmpfs y
# deja las rutas + caducidad en un estado JSON 0600. El plugin lo lee aquí para
# usar esas rutas mientras la sesión siga viva. Sin estado, el vault sigue
# sellado (fail-closed).

LIVE_STATE_NAME = "keygate-live.json"


def live_state_path(home: Optional[Path] = None) -> Path:
    return (home or (Path.home() / ".hermes")) / LIVE_STATE_NAME


def live_paths(home: Optional[Path] = None):
    """(db, keyfile) de la sesión desbloqueada, o None si no hay o caducó."""
    try:
        d = json.loads(live_state_path(home).read_text())
        exp = float(d.get("exp") or 0)
        db, kf = str(d.get("db") or ""), str(d.get("key") or "")
        if not db or not kf or exp <= time.time():
            return None
        if not (Path(db).is_file() and Path(kf).is_file()):
            return None
        return db, kf
    except Exception:
        return None


def live_set(db: str, keyfile: str, ttl_seconds: int, home: Optional[Path] = None) -> float:
    """Registra la sesión desbloqueada y devuelve el epoch de caducidad."""
    exp = time.time() + int(ttl_seconds)
    p = live_state_path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"db": db, "key": keyfile, "exp": exp}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    return exp


def live_state_exp(home: Optional[Path] = None) -> float:
    """Epoch de caducidad de la sesión desbloqueada (0 si no hay)."""
    try:
        return float(json.loads(live_state_path(home).read_text()).get("exp") or 0)
    except Exception:
        return 0.0


def live_clear(home: Optional[Path] = None) -> None:
    try:
        live_state_path(home).unlink()
    except Exception:
        pass


def live_shred(home: Optional[Path] = None) -> None:
    """Borra los archivos del vault temporal y el estado."""
    try:
        d = json.loads(live_state_path(home).read_text())
    except Exception:
        d = {}
    for k in ("db", "key"):
        f = Path(str(d.get(k) or ""))
        try:
            if f.is_file():
                f.unlink()
        except Exception:
            pass
    for k in ("db", "key"):
        f = Path(str(d.get(k) or ""))
        try:
            f.parent.rmdir()
        except Exception:
            pass
    live_clear(home)
