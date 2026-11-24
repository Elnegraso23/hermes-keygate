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

from contextlib import contextmanager
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
from typing import Dict, Iterator, List, Optional, Tuple
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
    stack: List[Tuple[int, str]] = []
    for line in (p.stdout or "").splitlines():
        t = line.strip()
        # Skip headers/placeholders (locale-dependent "[empty]"/"[vacío]").
        if not t or t.startswith("Entries") or re.fullmatch(r"\[.*\]", t):
            continue
        if t == "/":
            stack.clear()
            continue
        indent = len(line) - len(line.lstrip(" "))
        if t.endswith("/"):  # group header: following entries hang under it
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, t.rstrip("/")))
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        prefix = "/".join(g for _, g in stack)
        full = f"{prefix}/{t}" if prefix else t
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


# ----------------------------------------- write lock, backups & add_entry ---

_DB_WRITE_THREAD_LOCK = threading.Lock()
_CREATE_POLICY_LOCK = threading.Lock()
CREATE_POLICY_NAME = "keygate-create-policy.json"
CREATE_MODES = ("ask", "auto", "disabled")
CREATE_AUTO_MAX = 5
CREATE_AUTO_WINDOW = 60.0
_create_hits: Dict[str, List[float]] = {}
_create_rate_lock = threading.Lock()


@contextmanager
def db_lock(db: str) -> Iterator[None]:
    """Serialize writes to a .kdbx across threads and processes (flock).

    Lock file lives next to the DB (`<db>.lock`, mode 0600) so plugin and
    keygate-sync never race on staging/os.replace.
    """
    lock_path = Path(str(db) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _DB_WRITE_THREAD_LOCK:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            if os.name == "posix":
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "posix":
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def rotate_backups(db: str, keep: int = 5) -> None:
    p = Path(db)
    existing = sorted(p.parent.glob(p.name + ".*.bak"), key=lambda x: x.stat().st_mtime)
    if keep > 0 and len(existing) > keep:
        for old in existing[: len(existing) - keep]:
            try:
                old.unlink()
            except Exception:
                pass


def backup_db(db: str, keep: int = 5) -> str:
    """Copy current DB to `<db>.<ts>.bak` (0600) and rotate to `keep`."""
    ts = int(time.time())
    dst = f"{db}.{ts}.bak"
    if Path(dst).exists():
        dst = f"{db}.{ts}.{time.time_ns() % 1_000_000:06d}.bak"
    shutil.copy2(db, dst)
    os.chmod(dst, 0o600)
    rotate_backups(db, keep)
    return dst


def create_policy_path(home: Path | str) -> Path:
    h = Path(home) if isinstance(home, (str, Path)) else Path.home() / ".hermes"
    return h / CREATE_POLICY_NAME


def validate_email(email: str) -> Tuple[str, Optional[str]]:
    """Basic sanity check for default signup email (empty is allowed = unset)."""
    s = (email or "").strip()
    if not s:
        return "", None
    if len(s) > 254 or any(ord(c) < 0x21 or ord(c) == 0x7f for c in s):
        return "", "invalid email address"
    if s.count("@") != 1:
        return "", "invalid email address"
    local, domain = s.split("@", 1)
    if not local or not domain or "." not in domain or domain.startswith(".") or domain.endswith("."):
        return "", "invalid email address"
    return s, None


def load_create_policy(home: Path | str) -> dict:
    """Global policy for Hermes credential creation + default signup email.

    mode:
      - 'ask'      (default): requires explicit human approval per creation.
      - 'auto'     : Hermes can create new entries without prompt (rate-limited,
                     audited; rotate still asks; cron/one-shot always denied).
      - 'disabled' : creation from Hermes is blocked (policy_blocked).
    default_email: optional non-secret email used when username is omitted.
    """
    fp = create_policy_path(home)
    try:
        if fp.exists():
            data = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                mode = str(data.get("mode") or "ask").strip().lower()
                if mode not in CREATE_MODES:
                    mode = "ask"
                email, err = validate_email(str(data.get("default_email") or ""))
                return {
                    "version": 1,
                    "mode": mode,
                    "default_email": email if not err else "",
                    "updated": int(data.get("updated") or 0),
                }
    except Exception:
        pass
    return {"version": 1, "mode": "ask", "default_email": "", "updated": 0}


def save_create_policy(home: Path | str, data: dict) -> None:
    fp = create_policy_path(home)
    fp.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(fp.parent),
            prefix=".keygate-create-policy-", suffix=".tmp", delete=False,
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


def set_create_policy(
    home: Path | str,
    mode: Optional[str] = None,
    default_email: Optional[str] = None,
) -> Tuple[Optional[dict], Optional[str]]:
    """Update create policy atomically. Returns (policy_dict, error_message)."""
    with _CREATE_POLICY_LOCK:
        cur = load_create_policy(home)
        if mode is not None:
            m = str(mode).strip().lower()
            if m not in CREATE_MODES:
                return None, f"mode must be one of {', '.join(CREATE_MODES)}"
            cur["mode"] = m
        if default_email is not None:
            cleaned, err = validate_email(str(default_email))
            if err:
                return None, err
            cur["default_email"] = cleaned
        cur["version"] = 1
        cur["updated"] = int(time.time())
        save_create_policy(home, cur)
        return cur, None


def create_rate_ok(bucket: str = "global") -> bool:
    """Sliding-window cap for auto credential creations (loop protection)."""
    key = (bucket or "global").lower()
    now = time.time()
    with _create_rate_lock:
        arr = [t for t in _create_hits.get(key, []) if now - t < CREATE_AUTO_WINDOW]
        if len(arr) >= CREATE_AUTO_MAX:
            _create_hits[key] = arr
            return False
        arr.append(now)
        _create_hits[key] = arr
        return True


def validate_alias(alias: str) -> Tuple[str, Optional[str]]:
    """Validate an entry title/alias (no slashes, control chars, or trash)."""
    s = (alias or "").strip()
    if not s:
        return "", "alias required"
    if len(s) > 128:
        return "", "alias too long (max 128 chars)"
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        return "", "alias contains control characters"
    if "/" in s or "\\" in s or ".." in s:
        return "", "alias must not contain path separators (use 'group' separately)"
    if is_trash_path(s):
        return "", "alias cannot target recycle bin"
    return s, None


def validate_group(group: str) -> Tuple[str, Optional[str]]:
    """Validate an optional KeePass group path (e.g. 'Agent' or 'Agent/Social')."""
    s = (group or "").strip().strip("/")
    if not s:
        return "", None
    if len(s) > 128:
        return "", "group too long (max 128 chars)"
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s):
        return "", "group contains control characters"
    if "\\" in s:
        return "", "group must use '/' separators"
    parts = [p.strip() for p in s.split("/")]
    if any(not p or p in (".", "..") for p in parts):
        return "", "invalid group path"
    clean = "/".join(parts)
    if is_trash_path(clean):
        return "", "group cannot target recycle bin"
    return clean, None


def _db_needs_password_error(db: str, keyfile: str) -> str:
    """Distinguish db_password_missing from generic vault_locked."""
    if db_uses_password():
        return "vault_locked"
    try:
        p = subprocess.run(
            [_kxc(), "ls", "-k", keyfile, "--no-password", "-q", "--", db],
            env=_child_env(), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=8,
        )
        err = ((p.stderr or "") + " " + (p.stdout or "")).lower()
        if any(w in err for w in ("password", "credential", "invalid", "clave", "contrase")):
            return "db_password_missing"
    except Exception:
        pass
    return "vault_locked"


def precheck_add_entry(
    db: str,
    keyfile: str,
    alias: str,
    origin: str,
    username: str,
    group: str = "",
    rotate: bool = False,
) -> dict:
    """Validate inputs + vault state before prompting for human approval.

    Returns {"ok": True, "alias", "group", "origin", "username", "entry_path",
    "existing_path", "is_rotate"} or {"ok": False, "error_type", "error"}.
    Never reads or returns any password.
    """
    clean_alias, aerr = validate_alias(alias)
    if aerr:
        return {"ok": False, "error_type": "invalid_alias", "error": aerr}
    clean_group, gerr = validate_group(group)
    if gerr:
        return {"ok": False, "error_type": "invalid_alias", "error": gerr}
    norm_origin = normalize_origin(origin)
    if not norm_origin:
        return {"ok": False, "error_type": "invalid_origin",
                "error": "origin must be a valid http(s)://host URL"}
    clean_user = (username or "").strip()
    if not clean_user or len(clean_user) > 256 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in clean_user):
        return {"ok": False, "error_type": "invalid_username",
                "error": "username required (or configure default_email in keygate-sync web)"}
    try:
        _kxc()
    except Exception:
        return {"ok": False, "error_type": "kxc_missing",
                "error": f"keepassxc-cli not available — {install_hint()}"}
    if not Path(db).is_file() or not Path(keyfile).is_file():
        return {"ok": False, "error_type": "vault_locked",
                "error": "operative DB or keyfile not found"}
    if db_locked(db, keyfile):
        et = _db_needs_password_error(db, keyfile)
        msg = ("operative DB requires master password (KEYGATE_DB_PASSWORD not set)"
               if et == "db_password_missing"
               else "operative DB locked — unlock hermes.kdbx locally")
        return {"ok": False, "error_type": et, "error": msg}

    entries = list_entries(db, keyfile)
    entry_path = f"{clean_group}/{clean_alias}" if clean_group else clean_alias
    leaf_matches = [e for e in entries if e.split("/")[-1] == clean_alias]
    if not rotate:
        if entry_path in entries or leaf_matches:
            return {"ok": False, "error_type": "alias_exists",
                    "error": f"alias {redact_label(clean_alias)!r} already exists (pass rotate=true to regenerate)"}
        return {"ok": True, "alias": clean_alias, "group": clean_group,
                "origin": norm_origin, "username": clean_user,
                "entry_path": entry_path, "existing_path": None, "is_rotate": False}

    # rotate=True
    if len(leaf_matches) > 1 and entry_path not in entries:
        return {"ok": False, "error_type": "ambiguous_alias",
                "error": f"ambiguous alias {redact_label(clean_alias)!r} in {len(leaf_matches)} groups"}
    existing_path = entry_path if entry_path in entries else (leaf_matches[0] if leaf_matches else None)
    if existing_path:
        existing_url = show_field(db, keyfile, existing_path, "url") or ""
        if not origins_match(existing_url, norm_origin):
            return {"ok": False, "error_type": "domain_mismatch",
                    "error": "vault entry URL does not match requested origin — rotation refused"}
        return {"ok": True, "alias": clean_alias, "group": clean_group,
                "origin": norm_origin, "username": clean_user,
                "entry_path": existing_path, "existing_path": existing_path, "is_rotate": True}
    return {"ok": True, "alias": clean_alias, "group": clean_group,
            "origin": norm_origin, "username": clean_user,
            "entry_path": entry_path, "existing_path": None, "is_rotate": False}


def add_entry(
    db: str,
    keyfile: str,
    alias: str,
    origin: str,
    username: str,
    password: Optional[str] = None,
    generate: bool = True,
    length: int = 24,
    group: str = "",
    rotate: bool = False,
    backup_keep: int = 5,
) -> dict:
    """Create (or rotate) a KeePassXC entry atomically, without leaking secrets.

    - Acquires `<db>.lock` (flock) to serialize writes between plugin and sync.
    - Stages a copy on the SAME filesystem as `db` (no EXDEV).
    - Uses `keepassxc-cli add`/`edit` with `-g -L <len> -l -U -n -s --every-group`
      when `generate=True`, or `-p` via stdin (never argv) when `generate=False`.
    - Verifies the staged DB opens with `keyfile`, passes anti-wipe, and stores
      the expected URL/username and a non-empty password.
    - Backs up the previous DB (`backup_db`), atomically replaces with
      `os.replace`, and enforces 0600 permissions.
    - Returns metadata only — never the password.
    """
    try:
        pw_len = max(16, min(64, int(length if length is not None else 24)))
    except (ValueError, TypeError):
        pw_len = 24
    if not generate and not (password or ""):
        return {"success": False, "error_type": "write_failed",
                "error": "password required when generate=False"}

    pw_buf = bytearray((password or "").encode("utf-8")) if (not generate and password) else bytearray()
    try:
        pre = precheck_add_entry(db, keyfile, alias, origin, username, group=group, rotate=rotate)
        if not pre.get("ok"):
            return {"success": False, "error_type": pre["error_type"], "error": pre["error"]}

        with db_lock(db):
            # Re-check inside the lock to avoid TOCTOU races with concurrent writers.
            pre = precheck_add_entry(db, keyfile, alias, origin, username, group=group, rotate=rotate)
            if not pre.get("ok"):
                return {"success": False, "error_type": pre["error_type"], "error": pre["error"]}

            clean_alias = pre["alias"]
            clean_group = pre["group"]
            norm_origin = pre["origin"]
            clean_user = pre["username"]
            target_path = pre["entry_path"]
            is_rotate = bool(pre["is_rotate"])
            entries_before = list_entries(db, keyfile)

            db_parent = Path(db).parent
            staging = ""
            replaced = False
            try:
                with tempfile.NamedTemporaryFile(
                    delete=False, prefix=".keygate-stage-", suffix=".kdbx",
                    dir=str(db_parent),
                ) as tf:
                    staging = tf.name
                shutil.copy2(db, staging)
                os.chmod(staging, 0o600)

                # Ensure intermediate groups exist when creating under a group.
                if not is_rotate and clean_group:
                    accum = []
                    for part in clean_group.split("/"):
                        accum.append(part)
                        _run_kxc(["mkdir", *kxc_auth(keyfile), "-q", "--", staging, "/".join(accum)])

                subcmd = "edit" if is_rotate else "add"
                args = [subcmd, *kxc_auth(keyfile), "-q",
                        "-u", clean_user, "--url", norm_origin]
                stdin_data: Optional[str] = None
                if generate:
                    args += ["-g", "-L", str(pw_len), "-l", "-U", "-n", "-s", "--every-group"]
                else:
                    args += ["-p"]
                    prefix = (os.environ.get(DB_PASSWORD_ENV, "") + "\n") if db_uses_password() else ""
                    stdin_data = prefix + pw_buf.decode("utf-8") + "\n"
                args += ["--", staging, target_path]

                proc = _run_kxc(args, stdin_data=stdin_data)
                if stdin_data is not None:
                    stdin_data = ""
                if proc.returncode != 0:
                    return {"success": False, "error_type": "write_failed",
                            "error": f"keepassxc-cli {subcmd} failed (exit {proc.returncode})"}

                # Verify staged DB integrity + anti-wipe before replacing.
                entries_after = list_entries(staging, keyfile)
                min_expected = max(1, len(entries_before))
                if len(entries_after) < min_expected:
                    return {"success": False, "error_type": "write_failed",
                            "error": "staging failed anti-wipe verification"}

                resolved, rerr = resolve_entry(staging, keyfile, target_path)
                if not resolved:
                    return {"success": False, "error_type": "write_failed",
                            "error": rerr or "created entry could not be verified"}
                got_url = show_field(staging, keyfile, resolved, "url") or ""
                got_user = show_field(staging, keyfile, resolved, "username") or ""
                if not origins_match(got_url, norm_origin) or got_user != clean_user:
                    return {"success": False, "error_type": "write_failed",
                            "error": "staged entry metadata mismatch"}
                got_pw = show_field(staging, keyfile, resolved, "password") or ""
                pw_ok = bool(got_pw)
                if got_pw:
                    zeroize(bytearray(got_pw.encode("utf-8")))
                    got_pw = ""
                if not pw_ok:
                    return {"success": False, "error_type": "write_failed",
                            "error": "staged entry has empty password"}

                backup_db(db, keep=backup_keep)
                os.chmod(staging, 0o600)
                os.replace(staging, db)
                replaced = True
                os.chmod(db, 0o600)

                return {
                    "success": True,
                    "created": not is_rotate,
                    "rotated": is_rotate,
                    "alias": clean_alias,
                    "entry_path": resolved,
                    "origin": norm_origin,
                    "identifier": clean_user,
                    "generated": bool(generate),
                    "length": pw_len if generate else None,
                    "entries_before": len(entries_before),
                    "entries_after": len(entries_after),
                }
            finally:
                if staging and not replaced:
                    try:
                        Path(staging).unlink()
                    except Exception:
                        pass
    finally:
        zeroize(pw_buf)
        password = None


def augment_signup_password_fills(classified, fills: List[dict], password: str) -> List[dict]:
    """Support blind sign-up forms with Password + Confirm Password inputs.

    `select_password_fill` fills only the primary password control. When a
    registration page exposes a second password control (e.g. confirm-password
    or second `new-password`), append at most ONE extra fill so Hermes can
    complete blind sign-ups without ever seeing the password.
    """
    if not password or not fills or not classified:
        return list(fills or [])
    pw_tokens = {"password", "new_password", "confirm_password", "password_confirm"}
    used_idx = {int(f.get("index")) for f in fills if isinstance(f, dict) and f.get("index") is not None}
    pw_already = sum(1 for f in fills if isinstance(f, dict) and str(f.get("token") or "") in pw_tokens)
    if pw_already != 1:
        return list(fills)
    extras = []
    for c in classified:
        tok = str(getattr(c, "token", "") or "")
        ctrl = getattr(c, "control", None)
        idx = getattr(ctrl, "index", None)
        if tok in pw_tokens and idx is not None and int(idx) not in used_idx:
            extras.append((int(idx), tok))
    if not extras:
        return list(fills)
    extras.sort(key=lambda x: x[0])
    idx, tok = extras[0]
    return list(fills) + [{"index": idx, "token": tok, "value": password}]
