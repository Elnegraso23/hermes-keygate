#!/usr/bin/env python3
"""keygate-sync: Tailscale/LAN-only web for the OPERATIVE hermes.kdbx.

The web NEVER sees a plaintext password: you edit locally in KeePassXC and
upload the ciphertext .kdbx. The server validates (opens with the host
keyfile), backs up, and atomically replaces. keygate reads the file per
call, so changes apply instantly with no restart.

Endpoints (all require `Authorization: Bearer $KEYGATE_SYNC_TOKEN`):
  GET  /                        status page (counts only, no secrets)
  GET  /api/aliases             [{alias, hint}] redacted metadata
  POST /api/upload              multipart file field `db` -> validate/backup/atomic replace
  POST /api/alias/remove        {"alias": ...} -> backup + delete entry
  GET  /api/onboarding/keyfile  ONE-TIME keyfile download, then 410 Gone forever
  GET  /api/audit?limit=N       last N audit lines (already redacted)

Env: KEYGATE_DB, KEYGATE_KEYFILE, KEYGATE_SYNC_TOKEN (required),
     KEYGATE_BIND (default 127.0.0.1), KEYGATE_PORT (default 8472),
     KEYGATE_BACKUP_KEEP (default 5).

Stdlib only. Never bind 0.0.0.0 yourself — reach it over Tailscale/LAN.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import keygate_lib as kg

MAX_UPLOAD = 10 * 1024 * 1024
RATE_MAX = 60  # requests per window per IP
RATE_WINDOW = 60.0


def cfg():
    db = os.environ.get("KEYGATE_DB") or kg.DEFAULT_DB
    kf = os.environ.get("KEYGATE_KEYFILE") or kg.DEFAULT_KEYFILE
    token = os.environ.get("KEYGATE_SYNC_TOKEN", "")
    bind = os.environ.get("KEYGATE_BIND", "127.0.0.1")
    port = int(os.environ.get("KEYGATE_PORT", "8472"))
    keep = int(os.environ.get("KEYGATE_BACKUP_KEEP", "5"))
    return db, kf, token, bind, port, keep


def audit_ev(home: Path, ev: dict):
    kg.audit(home, ev)


def rotate_backups(db: str, keep: int):
    p = Path(db)
    existing = sorted(p.parent.glob(p.name + ".*.bak"), key=lambda x: x.stat().st_mtime)
    for old in existing[:max(0, len(existing) - keep + 1)] if len(existing) >= keep else []:
        try:
            old.unlink()
        except Exception:
            pass


def backup_db(db: str, keep: int) -> str:
    dst = f"{db}.{int(time.time())}.bak"
    shutil.copy2(db, dst)
    os.chmod(dst, 0o600)
    rotate_backups(db, keep)
    return dst


def count_entries(db: str, kf: str) -> int:
    return len(kg.list_entries(db, kf))


def parse_multipart(body: bytes, boundary: bytes):
    """Minimal single-file multipart parser. Returns (filename, data) or (None, None)."""
    parts = body.split(b"--" + boundary)
    for part in parts:
        if b'name="db"' not in part.split(b"\r\n\r\n", 1)[0]:
            continue
        head, _, data = part.partition(b"\r\n\r\n")
        if b'filename="' not in head:
            continue
        data = data[: -2] if data.endswith(b"\r\n") else data
        fn = head.split(b'filename="', 1)[1].split(b'"', 1)[0].decode("utf-8", "replace")
        return fn, data
    return None, None


INDEX_HTML = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>keygate-sync</title></head><body>
<h1>keygate-sync (vault operativo)</h1>
<p>Esta web solo mueve <b>ciphertext</b>: sube el .kdbx editado en tu KeePassXC local.
Nunca escribas passwords aquí: no hay ningún campo para eso.</p>
<p>Aliases: <span id="n">…</span> · DB: <span id="db">…</span></p>
<ul id="aliases"></ul>
<h2>Subir nuevo hermes.kdbx</h2>
<input type="file" id="f" accept=".kdbx"><button onclick="up()">Subir y reemplazar</button>
<pre id="out"></pre>
<script>
const t = sessionStorage.getItem('kg_t') || prompt('Token de keygate-sync:') || '';
sessionStorage.setItem('kg_t', t);
const H = {'Authorization': 'Bearer ' + t};
async function api(p, o) {
  const r = await fetch(p, Object.assign({headers: H}, o));
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { sessionStorage.removeItem('kg_t'); alert('Token inválido'); }
  return {status: r.status, body: j};
}
(async () => {
  const r = await api('/api/aliases');
  document.getElementById('n').textContent = (r.body.items || []).length;
  document.getElementById('db').textContent = r.body.locked ? 'bloqueada' : 'ok';
  document.getElementById('aliases').innerHTML = (r.body.items || [])
    .map(i => `<li><b>${i.alias}</b> <small>${i.hint}</small></li>`).join('');
})();
async function up() {
  const f = document.getElementById('f').files[0];
  if (!f) return alert('elige el .kdbx');
  const fd = new FormData(); fd.append('db', f, 'hermes.kdbx');
  const r = await fetch('/api/upload', {method: 'POST', headers: H, body: fd});
  document.getElementById('out').textContent = r.status + ' ' + await r.text();
}
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "keygate-sync/0.1"
    _hits: dict = {}

    def log_message(self, *a):
        pass  # never log request details (may carry metadata)

    # -- helpers --
    def _cfg(self):
        return cfg()

    def _home(self):
        return Path.home() / ".hermes"

    def _authed(self, token: str) -> bool:
        if not token:
            return False
        given = self.headers.get("Authorization", "")
        if not given.startswith("Bearer "):
            return False
        return hmac.compare_digest(given[7:].strip(), token)

    def _rate_ok(self) -> bool:
        ip = self.client_address[0]
        now = time.time()
        arr = [t for t in self._hits.get(ip, []) if now - t < RATE_WINDOW]
        arr.append(now)
        self._hits[ip] = arr
        return len(arr) <= RATE_MAX

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _need_auth(self, token: str) -> bool:
        if not self._rate_ok():
            self._send(429, {"success": False, "error": "rate limited"})
            return False
        if not self._authed(token):
            self._send(401, {"success": False, "error": "unauthorized"})
            return False
        return True

    # -- routes --
    def do_GET(self):
        db, kf, token, _b, _p, _k = self._cfg()
        url = urlparse(self.path)
        if url.path == "/":
            # Public shell on purpose: browsers can't send Authorization headers
            # on plain navigation. The page holds zero secrets; it prompts for
            # the token and calls /api/* with it (those stay Bearer-gated).
            if not self._rate_ok():
                self._send(429, {"success": False, "error": "rate limited"})
                return
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self._need_auth(token):
            return
        if url.path == "/api/aliases":
            if kg.db_locked(db, kf):
                self._send(200, {"success": False, "locked": True, "items": []})
                return
            items = [{"alias": e.split("/")[-1],
                      "hint": kg.hint_for(e.split("/")[-1], "")}
                     for e in kg.list_entries(db, kf)][:200]
            self._send(200, {"success": True, "locked": False,
                             "count": len(items), "items": items})
            return
        if url.path == "/api/onboarding/keyfile":
            flag = Path(db).parent / ".keygate-keyfile-served"
            if flag.exists():
                self._send(410, {"success": False, "error": "already served (one-time)"})
                return
            try:
                data = Path(kf).read_bytes()
            except Exception:
                self._send(500, {"success": False, "error": "keyfile unreadable"})
                return
            flag.write_text(f"{int(time.time())}\n")
            try:
                os.chmod(flag, 0o600)
            except Exception:
                pass
            audit_ev(self._home(), {"ev": "sync", "action": "keyfile-served-once"})
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if url.path == "/api/audit":
            try:
                n = max(1, min(200, int((parse_qs(url.query).get("limit") or ["50"])[0])))
            except Exception:
                n = 50
            try:
                lines = (self._home() / "keygate-audit.jsonl").read_text().splitlines()[-n:]
            except Exception:
                lines = []
            self._send(200, {"success": True, "lines": lines})
            return
        self._send(404, {"success": False, "error": "not found"})

    def do_POST(self):
        db, kf, token, _b, _p, keep = self._cfg()
        url = urlparse(self.path)
        if not self._need_auth(token):
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_UPLOAD + 65536:
            self._send(400, {"success": False, "error": "bad upload size"})
            return
        body = self.rfile.read(length)

        if url.path == "/api/upload":
            ctype = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in ctype or "boundary=" not in ctype:
                self._send(400, {"success": False, "error": "multipart db required"})
                return
            boundary = ctype.split("boundary=", 1)[1].strip().strip('"').encode()
            _fn, data = parse_multipart(body, boundary)
            if not data or len(data) > MAX_UPLOAD:
                self._send(400, {"success": False, "error": "empty/too big"})
                return
            if not data.startswith(b"\x03\xd9\xa2\x9a"):  # KDBX magic
                self._send(400, {"success": False, "error": "not a KDBX file"})
                return
            with tempfile.NamedTemporaryFile(delete=False, suffix=".kdbx") as tf:
                tf.write(data)
                staging = tf.name
            replaced = False
            try:
                before = count_entries(db, kf) if Path(db).exists() else 0
                # validate staging against the HOST keyfile:
                staged_n = self._count_with(staging, kf)
                if staged_n < 1:
                    self._send(400, {"success": False,
                                     "error": "staging opens but holds 0 entries — refused (anti-wipe)"})
                    return
                backup_db(db, keep)
                os.replace(staging, db)
                replaced = True
                os.chmod(db, 0o600)
                after = count_entries(db, kf)
                audit_ev(self._home(), {"ev": "sync", "action": "replace",
                                        "sha256": hashlib.sha256(data).hexdigest()[:16],
                                        "before": before, "after": after})
                self._send(200, {"success": True, "before": before, "after": after})
            except Exception as exc:
                self._send(500, {"success": False, "error": f"replace failed: {exc}"[:200]})
            finally:
                if not replaced:
                    try:
                        Path(staging).unlink()
                    except Exception:
                        pass
            return

        if url.path == "/api/alias/remove":
            try:
                alias = str(json.loads(body or b"{}").get("alias") or "").strip()
            except Exception:
                alias = ""
            if not alias:
                self._send(400, {"success": False, "error": "alias required"})
                return
            entries = kg.list_entries(db, kf)
            match = next((e for e in entries if e.split("/")[-1] == alias), None)
            if not match:
                self._send(404, {"success": False, "error": "alias not found"})
                return
            try:
                backup_db(db, keep)
                p = subprocess.run(
                    ["keepassxc-cli", "rm", "-k", kf, "--no-password", "-q",
                     "--", db, match],
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
                if p.returncode != 0:
                    self._send(500, {"success": False, "error": "rm failed"})
                    return
                audit_ev(self._home(), {"ev": "sync", "action": "alias-remove",
                                        "alias": kg.redact_label(alias)})
                self._send(200, {"success": True, "removed": alias})
            except Exception as exc:
                self._send(500, {"success": False, "error": str(exc)[:200]})
            return
        self._send(404, {"success": False, "error": "not found"})

    def _count_with(self, staging: str, kf: str) -> int:
        # keepassxc-cli reads any path; staging validated by magic + open test
        try:
            p = subprocess.run(
                ["keepassxc-cli", "ls", "-R", "-k", kf, "--no-password", "-q", staging],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
            if p.returncode != 0:
                return -1
            import re
            n = 0
            for line in (p.stdout or "").splitlines():
                t = line.strip()
                if t and not t.startswith("Entries") and t != "/" and not re.fullmatch(r"\[.*\]", t):
                    if kg.is_trash_path(t):
                        continue
                    n += 1
            return n
        except Exception:
            return -1


def main() -> int:
    db, kf, token, bind, port, _keep = cfg()
    if not token or len(token) < 16:
        print("KEYGATE_SYNC_TOKEN requerido (>=16 chars). Nada expuesto sin auth.", file=sys.stderr)
        return 2
    if bind == "0.0.0.0":
        print("REFUSED: no bindees 0.0.0.0 — usa 127.0.0.1 o tu IP Tailscale.", file=sys.stderr)
        return 2
    if not Path(db).exists():
        print(f"DB no existe aún: {db} (corre keygate-setup primero)", file=sys.stderr)
    srv = ThreadingHTTPServer((bind, port), Handler)
    print(f"keygate-sync en http://{bind}:{port} (solo red local/Tailscale)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
