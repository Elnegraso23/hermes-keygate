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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>keygate-sync</title>
<style>
:root{color-scheme:dark;--bg:#101418;--card:#1a2129;--line:#2a3440;--txt:#dbe4ee;
--mut:#8fa1b5;--acc:#4cc38a;--warn:#e5b567;--bad:#ef6461;--btn:#2f6fed}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;align-items:center;gap:12px;margin-bottom:6px}
.logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#2f6fed,#4cc38a);
display:flex;align-items:center;justify-content:center;font-size:20px}
h1{font-size:20px;margin:0}h2{font-size:15px;margin:26px 0 10px;color:var(--mut);
text-transform:uppercase;letter-spacing:.06em}
.sub{color:var(--mut);font-size:13px;margin:0 0 18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:10px 0}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:12px;padding:3px 10px;border-radius:99px;border:1px solid var(--line);color:var(--mut)}
.badge.ok{color:var(--acc);border-color:var(--acc)}
.badge.bad{color:var(--bad);border-color:var(--bad)}
.alias{display:flex;justify-content:space-between;align-items:center;gap:10px;
padding:9px 2px;border-bottom:1px solid var(--line)}
.alias:last-child{border-bottom:0}
.alias b{font-family:ui-monospace,monospace;font-size:14px}
.alias small{color:var(--mut)}
button{background:var(--btn);color:#fff;border:0;border-radius:8px;padding:9px 16px;
font-size:14px;cursor:pointer}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
button.danger{background:transparent;border:1px solid var(--bad);color:var(--bad);padding:6px 12px;font-size:13px}
button:disabled{opacity:.5;cursor:default}
.drop{border:2px dashed var(--line);border-radius:12px;padding:26px;text-align:center;
color:var(--mut);cursor:pointer;transition:.15s}
.drop.over{border-color:var(--acc);color:var(--acc)}
pre{background:#0b0e12;border:1px solid var(--line);border-radius:8px;padding:10px;
font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto}
.audit{font-family:ui-monospace,monospace;font-size:12px;color:var(--mut)}
.topbar{display:flex;justify-content:flex-end;margin-bottom:4px}
.hide{display:none}
footer{color:var(--mut);font-size:12px;margin-top:26px}
code{background:#0b0e12;padding:2px 6px;border-radius:6px;font-size:13px}
</style></head><body><div class="wrap">
<div class="topbar"><button class="ghost" id="logout" onclick="logout()">Cerrar sesión</button></div>
<header><div class="logo">🔑</div><div><h1>keygate-sync</h1>
<div class="sub">Vault operativo · solo mueve ciphertext · sin passwords en esta página</div></div></header>

<div class="card"><div class="row">
<span class="badge" id="dbstate">…</span>
<span class="badge" id="count">… aliases</span>
<span style="flex:1"></span>
<button class="ghost" onclick="load()">↻ Recargar</button>
</div></div>

<h2>Aliases</h2>
<div class="card" id="aliases"><div class="sub">Cargando…</div></div>

<h2>Subir nuevo hermes.kdbx</h2>
<div class="card">
<div class="drop" id="drop">Arrastra el <code>.kdbx</code> aquí o haz clic para elegirlo
<input type="file" id="f" accept=".kdbx" class="hide"></div>
<div class="row" style="margin-top:10px"><button id="upbtn" onclick="up()">Subir y reemplazar</button></div>
<pre id="out">Sin subidas todavía.</pre>
</div>

<h2>Baja de alias</h2>
<div class="card"><div class="row">
<input id="rmalias" placeholder="alias exacto (ej. sitio-agent-1)" style="flex:1;background:#0b0e12;border:1px solid var(--line);border-radius:8px;padding:9px;color:var(--txt)">
<button class="danger" onclick="rmAlias()">Eliminar copia operativa</button>
</div><div class="sub">Borra solo la copia de Hermes (recuperable desde backup/personal). Pide confirmación.</div></div>

<h2>Onboarding del .key</h2>
<div class="card"><div class="row">
<span class="badge" id="obstate">…</span>
<button class="ghost" id="obbtn" onclick="onboard()">Descargar .key (una sola vez)</button>
</div><div class="sub">Guárdalo con permisos 600 en tu PC editor. Tras la primera descarga este botón muere para siempre.</div></div>

<h2>Auditoría</h2>
<div class="card audit" id="audit">…</div>

<footer>keygate-sync · red local/Tailscale únicamente · todo cambio deja backup + audit</footer>
</div>
<script>
const t = sessionStorage.getItem('kg_t') || prompt('Token de keygate-sync:') || '';
sessionStorage.setItem('kg_t', t);
const H = {'Authorization': 'Bearer ' + t};
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function logout(){ sessionStorage.removeItem('kg_t'); location.reload(); }
async function api(p, o) {
  const r = await fetch(p, Object.assign({headers: H}, o));
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { sessionStorage.removeItem('kg_t'); alert('Token inválido, recarga e inténtalo de nuevo'); }
  return {status: r.status, body: j};
}
async function load() {
  const r = await api('/api/aliases');
  const b = r.body;
  const ds = document.getElementById('dbstate');
  ds.textContent = b.locked ? '🔒 DB bloqueada' : '🟢 DB ok';
  ds.className = 'badge ' + (b.locked ? 'bad' : 'ok');
  document.getElementById('count').textContent = (b.items || []).length + ' aliases';
  document.getElementById('aliases').innerHTML = (b.items && b.items.length)
    ? b.items.map(i => `<div class="alias"><div><b>${esc(i.alias)}</b><br><small>${esc(i.hint)}</small></div></div>`).join('')
    : '<div class="sub">Vacío — sube tu primer .kdbx o añade copias en KeePassXC.</div>';
  const a = await api('/api/audit?limit=8');
  document.getElementById('audit').innerHTML = (a.body.lines || []).slice().reverse()
    .map(l => `<div>${esc(l)}</div>`).join('') || 'Sin eventos.';
  document.getElementById('obstate').textContent = '⚪ un solo uso (no se puede consultar sin consumirlo)';
}
const drop = document.getElementById('drop'), fi = document.getElementById('f');
drop.onclick = () => fi.click();
fi.onchange = () => drop.firstChild.textContent = 'Elegido: ' + (fi.files[0] ? fi.files[0].name : 'nada');
['dragover','dragenter'].forEach(e => drop.addEventListener(e, ev => {ev.preventDefault(); drop.classList.add('over');}));
['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {ev.preventDefault(); drop.classList.remove('over');}));
drop.addEventListener('drop', ev => { fi.files = ev.dataTransfer.files; fi.onchange(); });
async function up() {
  const f = fi.files[0];
  if (!f) return alert('Elige primero el .kdbx (clic o arrastra)');
  if (!confirm('Reemplazar el operativo con ' + f.name + ' (' + f.size + ' bytes)? Se guarda backup.')) return;
  const fd = new FormData(); fd.append('db', f, 'hermes.kdbx');
  document.getElementById('out').textContent = 'Subiendo…';
  const r = await fetch('/api/upload', {method: 'POST', headers: H, body: fd});
  document.getElementById('out').textContent = r.status + ' ' + await r.text();
  load();
}
async function rmAlias() {
  const a = document.getElementById('rmalias').value.trim();
  if (!a) return alert('Escribe el alias exacto');
  if (!confirm('Eliminar la copia operativa "' + a + '"? Recuperable desde backup/personal.')) return;
  const r = await api('/api/alias/remove', {method: 'POST',
    headers: Object.assign({'Content-Type': 'application/json'}, H),
    body: JSON.stringify({alias: a})});
  alert(r.status + ' ' + JSON.stringify(r.body));
  document.getElementById('rmalias').value = '';
  load();
}
async function onboard() {
  if (!confirm('Descargar el .key UNA SOLA VEZ y deshabilitar este botón para siempre?')) return;
  const r = await fetch('/api/onboarding/keyfile', {headers: H});
  if (!r.ok) { alert('Ya servido o error: ' + r.status); return; }
  const blob = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'keepass-agent.key'; a.click();
  alert('Guardado. Ponle permisos 600 y desactiva si tu browser pregunta. Este botón ya no funcionará.');
}
load();
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
