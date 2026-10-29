#!/usr/bin/env python3
"""keygate-sync: Tailscale/LAN-only web for the OPERATIVE hermes.kdbx.

The web NEVER sees a plaintext password: you edit locally in KeePassXC and
upload the ciphertext .kdbx. The server validates (opens with the host
keyfile), backs up, and atomically replaces. keygate reads the file per
call, so changes apply instantly with no restart.

Endpoints (all require `Authorization: Bearer <password>` unless noted):
  GET  /                        status page (counts only, no secrets; public shell)
  GET  /api/setup-state          public: {setup_required} (first visit forces password creation)
  POST /api/set-password         {password} — allowed ONCE while no password set (min 12 chars)
  POST /api/reset-password       {current, new} — change password (needs the current one, min 12)
  GET  /api/health               public minimal: {ok, locked, entries, setup_required} (monitoring)
  GET  /api/aliases             [{alias, hint}] redacted metadata
  GET  /api/download            current operative .kdbx bytes (ciphertext only)
  POST /api/upload              multipart file field `db` -> validate/backup/atomic replace
  GET  /api/onboarding/keyfile  ONE-TIME keyfile download, then 410 Gone forever
  GET  /api/onboarding/state   {served} — non-consuming probe so the UI kills the button visibly
  GET  /api/audit?limit=N       last N audit lines (already redacted)

Auth model: no default password, no token file. The first visit MUST create
the password (min 12 chars, PBKDF2-HMAC-SHA256 210k + random salt, stdlib
only, stored 0600 at ~/.hermes/keygate-sync-pass). Until then every /api/*
except setup-state/set-password answers 403. The browser keeps it in
sessionStorage of that tab only. A local terminal reader gains nothing from
this either way (they can read the vault files directly) — the password
protects REMOTE web access without a secret sitting on disk.

Env: KEYGATE_DB, KEYGATE_KEYFILE, KEYGATE_BIND (default 127.0.0.1),
     KEYGATE_PORT (default 8472), KEYGATE_BACKUP_KEEP (default 5).

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
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import keygate_lib as kg

MAX_UPLOAD = 10 * 1024 * 1024
RATE_MAX = 60  # requests per window per IP
RATE_WINDOW = 60.0
AUTH_FAIL_MAX = 8  # wrong-password attempts per window per IP

# Host allowlist, built at startup from the bind address. Defeats DNS
# rebinding: a page on evil.com that resolves to 127.0.0.1 still sends
# "Host: evil.com", which is not in the list -> 403 before any routing.
_ALLOWED_HOSTS = set()
PW_MIN_LEN = 12
PW_ITERS = 210_000


def passfile(home: Path) -> Path:
    return home / "keygate-sync-pass"


def hash_pw(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PW_ITERS)


def password_is_set(home: Path) -> bool:
    try:
        d = json.loads(passfile(home).read_bytes().decode())
        return bool(d.get("salt") and d.get("hash"))
    except Exception:
        return False


def check_password(home: Path, given: str) -> bool:
    try:
        d = json.loads(passfile(home).read_bytes().decode())
        salt = bytes.fromhex(d["salt"])
        want = bytes.fromhex(d["hash"])
    except Exception:
        return False
    if not given:
        return False
    return hmac.compare_digest(hash_pw(given, salt), want)


def set_password_once(home: Path, password: str) -> bool:
    """Create the password. Only when none exists (first visit)."""
    if password_is_set(home):
        return False
    if not isinstance(password, str) or len(password) < PW_MIN_LEN:
        return False
    salt = os.urandom(32)
    d = {"salt": salt.hex(), "hash": hash_pw(password, salt).hex(),
         "iters": PW_ITERS, "set_at": int(time.time())}
    pf = passfile(home)
    pf.parent.mkdir(parents=True, exist_ok=True)  # ~/.hermes puede no existir aún
    fd = os.open(str(pf), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
    except Exception:
        try:
            pf.unlink()
        except Exception:
            pass
        raise
    return True


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
    # backup_db() already wrote the NEW backup before calling us, so `existing`
    # includes it: delete down to exactly `keep`.
    for old in existing[:max(0, len(existing) - keep)] if len(existing) >= keep else []:
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
:root{color-scheme:dark;--bg:#0d1117;--card:#161b22;--card2:#1c232d;--line:#2a3440;--txt:#e6edf3;
--mut:#8b949e;--acc:#3fb950;--warn:#d29922;--bad:#f85149;--btn:#2f6fed;--btn-h:#388bfd}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#2f6fed,#3fb950);
display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:0 4px 12px rgba(0,0,0,.35)}
h1{font-size:20px;margin:0}h2{font-size:13px;margin:26px 0 10px;color:var(--mut);
text-transform:uppercase;letter-spacing:.07em;font-weight:600}
.sub{color:var(--mut);font-size:13px;margin:0 0 14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:10px 0}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:12px;padding:3px 10px;border-radius:99px;border:1px solid var(--line);color:var(--mut);background:#0d1117}
.badge.ok{color:var(--acc);border-color:rgba(63,185,80,.45);background:rgba(63,185,80,.08)}
.badge.warn{color:var(--warn);border-color:rgba(210,153,34,.45);background:rgba(210,153,34,.08)}
.badge.bad{color:var(--bad);border-color:rgba(248,81,73,.45);background:rgba(248,81,73,.08)}
.alias{display:flex;justify-content:space-between;align-items:center;gap:10px;
padding:11px 4px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.alias:last-child{border-bottom:0}
.alias b{font-family:ui-monospace,monospace;font-size:14px}
.alias small{color:var(--mut)}
input[type="password"],input[type="text"],input[type="search"]{
padding:9px 11px;border-radius:8px;border:1px solid var(--line);background:#0b0e12;color:var(--txt);font-size:14px}
input:focus{outline:none;border-color:var(--btn-h)}
button{background:var(--btn);color:#fff;border:0;border-radius:8px;padding:8px 15px;
font-size:13.5px;font-weight:500;cursor:pointer;transition:.15s}
button:hover:not(:disabled){background:var(--btn-h)}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
button.ghost:hover:not(:disabled){background:var(--card2);border-color:var(--mut)}
button.sm{padding:4px 9px;font-size:12px;border-radius:6px}
button.danger{background:transparent;border:1px solid var(--bad);color:var(--bad);padding:6px 12px;font-size:13px}
button:disabled{opacity:.45;cursor:default}
.drop{border:2px dashed var(--line);border-radius:12px;padding:26px;text-align:center;
color:var(--mut);cursor:pointer;transition:.15s;background:rgba(13,17,23,.4)}
.drop:hover,.drop.over{border-color:var(--acc);color:var(--acc);background:rgba(63,185,80,.05)}
pre{background:#0b0e12;border:1px solid var(--line);border-radius:8px;padding:10px;
font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;margin:10px 0 0}
.audit{font-family:ui-monospace,monospace;font-size:12px;color:var(--mut)}
.audit-row{display:flex;align-items:center;gap:8px;padding:6px 2px;border-bottom:1px solid rgba(42,52,64,.6);flex-wrap:wrap}
.audit-row:last-child{border-bottom:0}
.topbar{display:flex;gap:8px;align-items:center}
.hide{display:none!important}
footer{color:var(--mut);font-size:12px;margin-top:28px;text-align:center}
code{background:#0b0e12;padding:2px 6px;border-radius:6px;font-size:13px;border:1px solid var(--line)}
a{color:var(--btn-h);text-decoration:none}a:hover{text-decoration:underline}
</style></head><body><div class="wrap">
<header>
  <div class="brand"><div class="logo">🔑</div><div><h1>keygate-sync</h1>
  <div class="sub" style="margin:0">Vault operativo · solo mueve ciphertext · sin passwords en esta página</div></div></div>
  <div class="topbar" id="userbar" style="display:none">
    <button class="ghost sm" onclick="togglePwReset()">🔒 Cambiar clave</button>
    <button class="ghost sm" id="logout" onclick="logout()">Cerrar sesión</button>
  </div>
</header>

<div class="card" id="setupcard" style="display:none;border-color:var(--warn)">
<h2 style="margin-top:0;color:var(--warn)">Crea tu contraseña (primera y única vez)</h2>
<div class="sub">No hay contraseña por defecto. Mínimo 12 caracteres. Se guarda con PBKDF2 en el host; aquí solo vive en esta pestaña.</div>
<div class="row">
  <input type="password" id="pw1" placeholder="Nueva contraseña (mín. 12)" style="flex:1;min-width:200px"
   oninput="checkSetupHint()" onkeydown="if(event.key==='Enter')kg_setup()">
  <input type="password" id="pw2" placeholder="Repítela" style="flex:1;min-width:200px"
   oninput="checkSetupHint()" onkeydown="if(event.key==='Enter')kg_setup()">
  <button class="ghost sm" type="button" onclick="toggleVis(['pw1','pw2'])" title="Mostrar/ocultar">👁</button>
  <button onclick="kg_setup()">Crear</button>
</div>
<div class="sub" id="setuphint" style="margin:8px 0 0;font-size:12px">Longitud: 0 / 12 caracteres mínimo.</div>
<pre id="setupout" style="display:none"></pre>
</div>

<div id="logincard" class="card" style="display:none;border-color:var(--acc)">
<h2 style="margin-top:0;color:var(--acc)">Acceso a keygate-sync</h2>
<div class="sub">Ingresa la contraseña de la web. No se muestra nada sin ella.</div>
<div class="row">
<input type="password" id="loginpw" placeholder="Contraseña" autocomplete="current-password"
 style="flex:1;min-width:200px"
 onkeydown="if(event.key==='Enter')kg_login()">
<button class="ghost sm" type="button" onclick="toggleVis(['loginpw'])" title="Mostrar/ocultar">👁</button>
<button onclick="kg_login()">Entrar</button>
</div>
<pre id="loginout" style="display:none"></pre>
</div>

<div id="app" style="display:none">

<div class="card" id="pwresetcard" style="display:none;border-color:var(--warn)">
  <div class="row" style="justify-content:space-between;margin-bottom:8px">
    <b style="font-size:14px">Cambiar contraseña de acceso web</b>
    <button class="ghost sm" onclick="togglePwReset()">✕ Cerrar</button>
  </div>
  <div class="sub">Exige tu contraseña actual y una nueva de al menos 12 caracteres. Invalida la anterior al instante.</div>
  <div class="row">
    <input type="password" id="curpw" placeholder="Contraseña actual" style="flex:1;min-width:170px" onkeydown="if(event.key==='Enter')kg_reset_pw()">
    <input type="password" id="newpw1" placeholder="Nueva (mín. 12)" style="flex:1;min-width:170px" onkeydown="if(event.key==='Enter')kg_reset_pw()">
    <input type="password" id="newpw2" placeholder="Repetir nueva" style="flex:1;min-width:170px" onkeydown="if(event.key==='Enter')kg_reset_pw()">
    <button class="ghost sm" type="button" onclick="toggleVis(['curpw','newpw1','newpw2'])">👁</button>
    <button onclick="kg_reset_pw()">Actualizar clave</button>
  </div>
  <pre id="pwresetout" style="display:none"></pre>
</div>

<div class="card"><div class="row">
<span class="badge" id="dbstate">…</span>
<span class="badge" id="count">… aliases</span>
<span class="badge" id="dbmeta">…</span>
<span style="flex:1"></span>
<button class="ghost sm" onclick="load()">↻ Recargar</button>
</div></div>

<h2>Aliases y auto-relleno</h2>
<div class="card">
  <div class="row" style="justify-content:space-between;margin-bottom:10px">
    <div class="sub" style="margin:0;flex:1">Marca <b>Sin aprobación</b> en una cuenta para que su relleno no pida confirmación. Solo vale para el origin exacto guardado en la URL del vault.</div>
    <input type="search" id="aliasfilter" placeholder="🔍 Filtrar alias o grupo…" oninput="renderAliases()" style="min-width:210px">
  </div>
  <div id="aliases"><div class="sub">Cargando…</div></div>
</div>

<h2 id="primera">Primera vez (tu PC editor)</h2>
<div class="card"><div class="sub" id="checklist">Verificando estado…</div>
<div class="sub" style="margin:0">
1. <a href="#bajar">⬇ Descarga el .kdbx actual</a> (vacío la primera vez).<br>
2. <a href="#onb">Descarga el .key (una sola vez)</a> — guárdalo 600, no sale de tu PC.<br>
3. Abre el .kdbx en KeePassXC con ese .key, añade copias con alias opacos y URL exacta, guarda.<br>
4. <a href="#bajar">Sube el .kdbx editado</a> (pide confirmación, deja backup).<br>
De aquí en adelante solo repites 3–4. Sin el .key el .kdbx no se abre en ningún lado.
</div></div>

<h2 id="bajar">Bajar y subir el hermes.kdbx</h2>
<div class="card">
<div class="row">
<button class="ghost" onclick="dl()">⬇ Descargar .kdbx actual</button>
<span class="sub" style="margin:0">Flujo: descarga → edita en KeePassXC (añade copias con alias opacos) → súbelo abajo. Solo viaja ciphertext; sin el .key no se abre.</span>
</div>
<div class="drop" id="drop" style="margin-top:12px">Arrastra el <code>.kdbx</code> editado aquí o haz clic para elegirlo
<input type="file" id="f" accept=".kdbx" class="hide"></div>
<div class="row" style="margin-top:10px"><button id="upbtn" onclick="up()">⬆ Subir y reemplazar</button></div>
<pre id="out">Sin subidas todavía.</pre>
</div>

<h2 id="onb">Onboarding del .key</h2>
<div class="card"><div class="row">
<span class="badge" id="obstate">…</span>
<button class="ghost" id="obbtn" onclick="onboard()">Descargar .key (una sola vez)</button>
</div><div class="sub" style="margin:8px 0 0">Guárdalo con permisos 600 en tu PC editor. Tras la primera descarga este botón muere para siempre.</div></div>

<div class="row" style="justify-content:space-between;align-items:baseline;margin-top:22px">
  <h2 style="margin:0">Auditoría reciente</h2>
  <button class="ghost sm" onclick="toggleAuditRaw()" id="auditmodebtn">Ver JSON crudo</button>
</div>
<div class="card audit" id="audit">…</div>

<footer>keygate-sync · red local/Tailscale únicamente · todo cambio deja backup + audit</footer>
</div>
</div>
<script>
let __auditRaw = localStorage.getItem('kg_audit_raw') === '1';
let __lastAuditLines = [];
let __aliasRows = [];
function authHeaders() {
  const t = sessionStorage.getItem('kg_t') || '';
  return {'Authorization': 'Bearer ' + t};
}
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toggleVis(ids) {
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.type = (el.type === 'password') ? 'text' : 'password';
  });
}
function checkSetupHint() {
  const a = (document.getElementById('pw1').value || '');
  const b = (document.getElementById('pw2').value || '');
  const h = document.getElementById('setuphint');
  if (!a.length) { h.textContent = 'Longitud: 0 / 12 caracteres mínimo.'; h.style.color = 'var(--mut)'; return; }
  if (a.length < 12) { h.textContent = `Longitud: ${a.length} / 12 (faltan ${12 - a.length}).`; h.style.color = 'var(--warn)'; return; }
  if (b && a !== b) { h.textContent = 'Longitud OK, pero las contraseñas aún no coinciden.'; h.style.color = 'var(--bad)'; return; }
  h.textContent = b ? '✅ Contraseña válida y coincide.' : `✅ Longitud OK (${a.length} caracteres). Repítela al lado.`;
  h.style.color = 'var(--acc)';
}
function logout(){ sessionStorage.removeItem('kg_t'); location.reload(); }
function showAuthedUI() {
  document.getElementById('setupcard').style.display = 'none';
  document.getElementById('logincard').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  document.getElementById('userbar').style.display = 'flex';
}
function togglePwReset() {
  const c = document.getElementById('pwresetcard');
  c.style.display = (c.style.display === 'none') ? 'block' : 'none';
  document.getElementById('pwresetout').style.display = 'none';
}
async function kg_reset_pw() {
  const cur = document.getElementById('curpw').value;
  const n1 = document.getElementById('newpw1').value;
  const n2 = document.getElementById('newpw2').value;
  const out = document.getElementById('pwresetout');
  out.style.display = 'block';
  if (!cur) { out.textContent = 'Ingresa tu contraseña actual.'; return; }
  if (n1.length < 12) { out.textContent = 'La nueva contraseña debe tener al menos 12 caracteres.'; return; }
  if (n1 !== n2) { out.textContent = 'La nueva contraseña y su confirmación no coinciden.'; return; }
  const h = Object.assign({'Content-Type': 'application/json'}, authHeaders());
  const r = await fetch('/api/reset-password', {method: 'POST', headers: h,
    body: JSON.stringify({current: cur, new: n1})});
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.success) {
    out.textContent = 'Error: ' + (j.error || r.status);
    return;
  }
  sessionStorage.setItem('kg_t', n1);
  document.getElementById('curpw').value = '';
  document.getElementById('newpw1').value = '';
  document.getElementById('newpw2').value = '';
  out.textContent = '✅ Contraseña actualizada en el host y en esta pestaña.';
  load();
}
async function boot() {
  let st = {};
  try {
    const r = await fetch('/api/setup-state');
    st = await r.json();
  } catch (e) { document.getElementById('setupout').style.display = 'block';
    document.getElementById('setupout').textContent = 'Servidor no responde. ¿Está corriendo keygate-sync?';
    document.getElementById('setupcard').style.display = 'block'; return; }
  if (st.setup_required) { document.getElementById('setupcard').style.display = 'block'; return; }
  // #app stays hidden until a verified login: cancelling must show nothing.
  document.getElementById('logincard').style.display = 'block';
  if (sessionStorage.getItem('kg_t')) {
    const ok = await kg_verify_token(sessionStorage.getItem('kg_t'));
    if (ok) { showAuthedUI(); load(); }
  }
}
async function kg_verify_token(t) {
  try {
    const r = await fetch('/api/audit', {headers: {'Authorization': 'Bearer ' + t}});
    return r.status === 200;
  } catch (e) { return false; }
}
async function kg_login() {
  const pw = document.getElementById('loginpw').value;
  const out = document.getElementById('loginout');
  out.style.display = 'block';
  if (!pw) { out.textContent = 'Ingresa la contraseña.'; return; }
  const ok = await kg_verify_token(pw);
  if (!ok) { out.textContent = 'Contraseña incorrecta (o límite de intentos alcanzado).';
             document.getElementById('loginpw').value = ''; return; }
  sessionStorage.setItem('kg_t', pw);
  document.getElementById('loginpw').value = '';
  out.style.display = 'none';
  showAuthedUI();
  load();
}
async function kg_setup() {
  const a = document.getElementById('pw1').value, b = document.getElementById('pw2').value;
  const out = document.getElementById('setupout'); out.style.display = 'block';
  if (a.length < 12) { out.textContent = 'Mínimo 12 caracteres.'; return; }
  if (a !== b) { out.textContent = 'No coinciden.'; return; }
  try {
    const r = await fetch('/api/set-password', {method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: a})});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { out.textContent = 'Falló: ' + (j.error || r.status); return; }
  } catch (e) { out.textContent = 'Servidor no responde.'; return; }
  sessionStorage.setItem('kg_t', a);
  document.getElementById('pw1').value = document.getElementById('pw2').value = '';
  showAuthedUI();
  load();
}
async function api(p, o) {
  const r = await fetch(p, Object.assign({headers: authHeaders()}, o));
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { sessionStorage.removeItem('kg_t'); alert('Sesión expirada o contraseña cambiada; vuelve a entrar.'); location.reload(); }
  if (r.status === 403 && j.setup_required) { location.reload(); return {status: r.status, body: j}; }
  return {status: r.status, body: j};
}
async function copyAlias(i, btn) {
  const alias = (window.__aliases || [])[i];
  if (!alias || !navigator.clipboard) return;
  try {
    await navigator.clipboard.writeText(alias);
    const old = btn.dataset.label || btn.textContent;
    btn.dataset.label = old;
    btn.textContent = '✓ Copiado';
    clearTimeout(btn.__t);
    btn.__t = setTimeout(() => { btn.textContent = old; }, 1400);
  } catch (e) {}
}
function renderAliases() {
  const q = ((document.getElementById('aliasfilter') || {}).value || '').trim().toLowerCase();
  const box = document.getElementById('aliases');
  if (!__aliasRows.length) {
    box.innerHTML = '<div class="sub" style="margin:0">Vacío — sube tu primer .kdbx o añade copias en KeePassXC.</div>';
    return;
  }
  const filtered = __aliasRows.filter(r => !q || r.alias.toLowerCase().includes(q) || (r.group || '').toLowerCase().includes(q));
  if (!filtered.length) {
    box.innerHTML = '<div class="sub" style="margin:0">Ningún alias coincide con el filtro.</div>';
    return;
  }
  box.innerHTML = filtered.map(r => {
    const i = r.idx;
    const p = r.policy;
    const val = p.enabled ? (p.origin || '') : (p.suggested_origin || '');
    const grp = r.group ? `<span class="badge" style="margin-left:6px;font-size:11px">📁 ${esc(r.group)}</span>` : '';
    return `<div class="alias"><div><div class="row" style="gap:6px"><b>${esc(r.alias)}</b>${grp}` +
      `<button class="ghost sm" onclick="copyAlias(${i}, this)" title="Copiar alias para el chat">📋 Copiar</button></div>` +
      `<small>Hint: ${esc(r.hint)}</small></div>` +
      `<div class="row" style="gap:6px">` +
      `<input type="text" id="ao_${i}" value="${esc(val)}" placeholder="https://sitio" ` +
      `style="width:210px;padding:7px;font-size:13px">` +
      `<label class="badge${p.enabled ? ' ok' : ''}" style="display:flex;align-items:center;gap:6px;cursor:pointer">` +
      `<input type="checkbox" id="ae_${i}" ${p.enabled ? 'checked' : ''}> Sin aprobación</label>` +
      `<button class="ghost sm" onclick="saveAuto(${i})">Guardar</button></div></div>`;
  }).join('');
}
function renderAudit() {
  const box = document.getElementById('audit');
  const lines = (__lastAuditLines || []).slice().reverse();
  if (!lines.length) { box.innerHTML = 'Sin eventos.'; return; }
  if (__auditRaw) {
    box.innerHTML = lines.map(l => `<div>${esc(l)}</div>`).join('');
    return;
  }
  box.innerHTML = lines.map(l => {
    try {
      const o = JSON.parse(l);
      const dt = o.ts ? new Date(o.ts * 1000).toLocaleString() : '—';
      const ev = o.ev || 'ev';
      const dec = o.decision || o.action || '';
      let bcls = '';
      if (dec === 'allow' || dec === 'replace' || dec === 'password-created') bcls = 'ok';
      else if (dec === 'deny' || dec.includes('mismatch') || dec === 'refused') bcls = 'bad';
      else if (dec) bcls = 'warn';
      const details = [];
      if (o.alias) details.push(`alias=${o.alias}`);
      if (o.origin) details.push(`origin=${o.origin}`);
      if (o.approval) details.push(`approval=${o.approval}`);
      if (o.before !== undefined && o.after !== undefined) details.push(`${o.before}→${o.after} entries`);
      if (o.sha256) details.push(`sha256=${o.sha256}`);
      return `<div class="audit-row"><span style="color:var(--mut);min-width:145px">${esc(dt)}</span>` +
        `<span class="badge">${esc(ev)}</span>` +
        (dec ? `<span class="badge ${bcls}">${esc(dec)}</span>` : '') +
        `<span style="color:var(--txt)">${esc(details.join(' · '))}</span></div>`;
    } catch (e) {
      return `<div class="audit-row">${esc(l)}</div>`;
    }
  }).join('');
}
function toggleAuditRaw() {
  __auditRaw = !__auditRaw;
  localStorage.setItem('kg_audit_raw', __auditRaw ? '1' : '0');
  document.getElementById('auditmodebtn').textContent = __auditRaw ? 'Ver vista estructurada' : 'Ver JSON crudo';
  renderAudit();
}
async function load() {
  const r = await api('/api/aliases');
  const b = r.body;
  const ds = document.getElementById('dbstate');
  ds.textContent = b.locked ? '🔒 DB bloqueada' : '🟢 DB ok';
  ds.className = 'badge ' + (b.locked ? 'bad' : 'ok');
  const items = b.items || [];
  window.__aliases = items.map(x => x.alias);
  const kb = b.db_size ? (b.db_size / 1024).toFixed(1) + ' KB' : '0 KB';
  const baks = (b.backups !== undefined) ? `${b.backups} backups` : '';
  const mt = b.db_mtime ? new Date(b.db_mtime * 1000).toLocaleString() : '';
  document.getElementById('dbmeta').textContent = `💾 ${kb}` + (baks ? ` · ${baks}` : '') + (mt ? ` · ${mt}` : '');
  const af = await api('/api/autofill');
  const amap = {};
  ((af.body && af.body.items) || []).forEach(x => { amap[x.alias] = x; });
  document.getElementById('count').textContent = items.length + ' aliases';
  __aliasRows = items.map((it, i) => ({
    idx: i,
    alias: it.alias,
    group: it.group || '',
    hint: it.hint || '',
    policy: amap[it.alias] || {enabled: false, origin: '', suggested_origin: ''}
  }));
  renderAliases();
  const a = await api('/api/audit?limit=12');
  __lastAuditLines = a.body.lines || [];
  renderAudit();
  document.getElementById('obstate').textContent = '⚪ disponible (un solo uso)';
  try {
    const ob = await api('/api/onboarding/state');
    const served = !!(ob.body && ob.body.served);
    if (served) { killOb(); }
    const n = items.length;
    document.getElementById('checklist').innerHTML =
      '✅ Contraseña creada (estás dentro)<br>' +
      (n ? `✅ .kdbx con ${n} alias` : '⬜ .kdbx vacío — súbelo con tus copias') + '<br>' +
      (served ? '✅ .key descargado (botón muerto)' : '⬜ .key sin descargar (una sola vez)');
  } catch (e) { document.getElementById('checklist').textContent = 'No se pudo leer el estado.'; }
}
async function saveAuto(i) {
  const alias = (window.__aliases || [])[i];
  const on = document.getElementById('ae_' + i).checked;
  const inp = document.getElementById('ao_' + i);
  let origin = (inp.value || '').trim();
  if (on && !origin) {
    origin = (prompt('Origin exacto para ' + alias + ' (ej. https://accounts.google.com):') || '').trim();
    if (!origin) { document.getElementById('ae_' + i).checked = false; return; }
    inp.value = origin;
  }
  const h = Object.assign({'Content-Type': 'application/json'}, authHeaders());
  const r = await api('/api/autofill', {method: 'POST', headers: h,
    body: JSON.stringify({alias: alias, origin: origin, enabled: on})});
  if (r.status !== 200 || !(r.body && r.body.success)) {
    alert('No se pudo guardar: ' + ((r.body && r.body.error) || r.status));
    return;
  }
  load();
}
const drop = document.getElementById('drop'), fi = document.getElementById('f');
drop.onclick = () => fi.click();
fi.onchange = () => {
  const f = fi.files[0];
  drop.firstChild.textContent = f ? `Elegido: ${f.name} (${(f.size / 1024).toFixed(1)} KB) ` : 'Nada elegido ';
};
['dragover','dragenter'].forEach(e => drop.addEventListener(e, ev => {ev.preventDefault(); drop.classList.add('over');}));
['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {ev.preventDefault(); drop.classList.remove('over');}));
drop.addEventListener('drop', ev => { fi.files = ev.dataTransfer.files; fi.onchange(); });
async function dl() {
  try {
    const r = await fetch('/api/download', {headers: authHeaders()});
    if (!r.ok) { alert('Descarga falló: ' + r.status); return; }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'hermes.kdbx';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  } catch (e) { alert('Servidor no responde. ¿Sigue corriendo keygate-sync?'); }
}
async function up() {
  const f = fi.files[0];
  if (!f) return alert('Elige primero el .kdbx (clic o arrastra)');
  if (!confirm('Reemplazar el operativo con ' + f.name + ' (' + f.size + ' bytes)? Se guarda backup.')) return;
  const fd = new FormData(); fd.append('db', f, 'hermes.kdbx');
  const out = document.getElementById('out');
  out.textContent = 'Subiendo y verificando con keyfile del host…';
  const r = await fetch('/api/upload', {method: 'POST', headers: authHeaders(), body: fd});
  const txt = await r.text();
  try {
    const j = JSON.parse(txt);
    if (r.ok && j.success) {
      out.textContent = `✅ Reemplazo atómico exitoso (HTTP ${r.status}) · Entradas antes: ${j.before} → ahora: ${j.after} · Backup rotado guardado.`;
    } else {
      out.textContent = `❌ Rechazado (HTTP ${r.status}): ${j.error || txt}`;
    }
  } catch (e) {
    out.textContent = r.status + ' ' + txt;
  }
  load();
}
async function onboard() {
  if (!confirm('Descargar el .key UNA SOLA VEZ y deshabilitar este botón para siempre?')) return;
  let r;
  try {
    r = await fetch('/api/onboarding/keyfile', {headers: authHeaders()});
  } catch (e) { alert('Servidor no responde.'); return; }
  if (r.status === 410) { alert('Este .key ya fue descargado (una sola vez). Si lo perdiste, genera un vault nuevo con keygate-setup.'); killOb(); return; }
  if (!r.ok) { alert('Error: ' + r.status); return; }
  const blob = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'keepass-agent.key';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  killOb();
  alert('Guardado. Ponle permisos 600. Este botón ya murió.');
}
function killOb() {
  document.getElementById('obstate').textContent = '🔴 ya descargado — este botón murió para siempre';
  document.getElementById('obstate').className = 'badge bad';
  document.getElementById('obbtn').disabled = true;
}
boot();
</script></body></html>
"""


def _build_allowed_hosts(bind: str, port: int) -> set:
    """Exact Host header values accepted by this instance (bind IP only)."""
    hosts = set()

    def add(h: str) -> None:
        h = (h or "").strip().lower()
        if not h:
            return
        hosts.add(h)
        if port not in (80, 443):
            hosts.add(f"{h}:{port}")

    add(bind)
    if bind in ("127.0.0.1", "::1", "localhost"):
        for h in ("127.0.0.1", "localhost", "[::1]"):
            add(h)
    return hosts


class Handler(BaseHTTPRequestHandler):
    server_version = "keygate-sync/0.2"
    _hits: dict = {}
    _auth_fails: dict = {}
    _hits_lock = threading.Lock()  # ThreadingHTTPServer: dict ops race without it
    _keyfile_lock = threading.Lock()

    def log_message(self, *a):
        pass  # never log request details (may carry metadata)

    # -- helpers --
    def _cfg(self):
        return cfg()

    def _home(self):
        return Path.home() / ".hermes"

    def _content_length(self) -> int:
        try:
            return int(self.headers.get("Content-Length") or 0)
        except (ValueError, TypeError):
            return -1

    def _host_ok(self) -> bool:
        """Strict Host check (DNS-rebinding defense). Never echoes the input."""
        raw = (self.headers.get("Host") or "").strip().lower()
        return bool(raw) and raw in _ALLOWED_HOSTS

    def _send_sec_headers(self, no_store: bool = True) -> None:
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        if no_store:
            self.send_header("Cache-Control", "no-store, max-age=0")

    def _csrf_ok(self, want_json: bool = True) -> bool:
        """Block cross-origin browser POSTs (Drive-By CSRF protection)."""
        sfs = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            self._send(403, {"success": False, "error": "cross-origin request blocked (CSRF)"})
            return False
        origin = (self.headers.get("Origin") or "").strip()
        if origin:
            host = (self.headers.get("Host") or "").strip().lower()
            orig_host = (urlparse(origin).netloc or "").strip().lower()
            if origin.lower() == "null" or not orig_host or (host and orig_host != host):
                self._send(403, {"success": False, "error": "cross-origin request blocked (CSRF)"})
                return False
        if want_json:
            ctype = (self.headers.get("Content-Type") or "").strip().lower()
            if "application/json" not in ctype:
                self._send(415, {"success": False, "error": "Content-Type application/json required"})
                return False
        return True

    def _authed(self) -> bool:
        given = self.headers.get("Authorization", "")
        if not given.startswith("Bearer "):
            return False
        return check_password(self._home(), given[7:].strip())

    def _rate_ok(self) -> bool:
        ip = self.client_address[0]
        now = time.time()
        with self._hits_lock:
            # Purge stale IPs periodically so _hits cannot grow unbounded
            if len(self._hits) > 64:
                for k in list(self._hits.keys()):
                    kept = [t for t in self._hits[k] if now - t < RATE_WINDOW]
                    if kept:
                        self._hits[k] = kept
                    else:
                        del self._hits[k]
            arr = [t for t in self._hits.get(ip, []) if now - t < RATE_WINDOW]
            arr.append(now)
            self._hits[ip] = arr
            n = len(arr)
        return n <= RATE_MAX

    def _auth_rate_ok(self) -> bool:
        ip = self.client_address[0]
        now = time.time()
        with self._hits_lock:
            arr = [t for t in self._auth_fails.get(ip, []) if now - t < RATE_WINDOW]
            if arr:
                self._auth_fails[ip] = arr
            elif ip in self._auth_fails:
                del self._auth_fails[ip]
            return len(arr) < AUTH_FAIL_MAX

    def _record_auth_fail(self) -> None:
        ip = self.client_address[0]
        now = time.time()
        with self._hits_lock:
            arr = [t for t in self._auth_fails.get(ip, []) if now - t < RATE_WINDOW]
            arr.append(now)
            self._auth_fails[ip] = arr

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self._send_sec_headers(no_store=True)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _need_auth(self) -> bool:
        if not self._rate_ok() or not self._auth_rate_ok():
            self._send(429, {"success": False, "error": "rate limited"})
            return False
        if not password_is_set(self._home()):
            self._send(403, {"success": False, "error": "password not created yet",
                             "setup_required": True})
            return False
        if not self._authed():
            self._record_auth_fail()
            self._send(401, {"success": False, "error": "wrong password"})
            return False
        return True

    # -- routes --
    def do_HEAD(self):
        if not self._host_ok():
            self.send_response(403)
            self._send_sec_headers(no_store=True)
            self.end_headers()
            return
        if not self._rate_ok():
            self.send_response(429)
            self._send_sec_headers(no_store=True)
            self.end_headers()
            return
        self.send_response(200)
        self._send_sec_headers(no_store=True)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        if not self._host_ok():
            self._send(403, {"success": False, "error": "forbidden"})
            return
        db, kf, _token, _b, _p, _k = self._cfg()
        url = urlparse(self.path)
        if url.path == "/":
            # Public shell on purpose: browsers can't send Authorization headers
            # on plain navigation. The page holds zero secrets; it prompts for
            # the password (or its creation) and calls /api/* with it.
            if not self._rate_ok():
                self._send(429, {"success": False, "error": "rate limited"})
                return
            body = INDEX_HTML.encode()
            self.send_response(200)
            self._send_sec_headers(no_store=True)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if url.path == "/api/setup-state":
            if not self._rate_ok():
                self._send(429, {"success": False, "error": "rate limited"})
                return
            self._send(200, {"success": True,
                             "setup_required": not password_is_set(self._home())})
            return
        if url.path == "/api/health":
            # Public by design (monitoring/startup probes): counts and flags
            # only, zero secrets, zero hints.
            if not self._rate_ok():
                self._send(429, {"success": False, "error": "rate limited"})
                return
            locked = kg.db_locked(db, kf)
            self._send(200, {"success": True, "ok": True,
                             "locked": locked,
                             "entries": 0 if locked else len(kg.list_entries(db, kf)),
                             "setup_required": not password_is_set(self._home())})
            return
        if not self._need_auth():
            return
        if url.path == "/api/aliases":
            if kg.db_locked(db, kf):
                self._send(200, {"success": False, "locked": True, "items": []})
                return
            items = [{"alias": e.split("/")[-1],
                      "group": e.rsplit("/", 1)[0] if "/" in e else "",
                      "hint": kg.hint_for(e.split("/")[-1], "")}
                     for e in kg.list_entries(db, kf)][:200]
            db_p = Path(db)
            try:
                st = db_p.stat()
                db_size, db_mtime = st.st_size, int(st.st_mtime)
            except Exception:
                db_size, db_mtime = 0, 0
            try:
                backups = len(list(db_p.parent.glob(db_p.name + ".*.bak")))
            except Exception:
                backups = 0
            self._send(200, {"success": True, "locked": False,
                             "count": len(items), "items": items,
                             "db_size": db_size, "db_mtime": db_mtime,
                             "backups": backups})
            return
        if url.path == "/api/onboarding/state":
            # Non-consuming probe: tells the UI whether the one-time keyfile
            # was already served, so the button can die VISIBLY.
            flag = Path(db).parent / ".keygate-keyfile-served"
            self._send(200, {"success": True, "served": flag.exists()})
            return
        if url.path == "/api/onboarding/keyfile":
            flag = Path(db).parent / ".keygate-keyfile-served"
            with self._keyfile_lock:
                if flag.exists():
                    self._send(410, {"success": False, "error": "already served (one-time)"})
                    return
                try:
                    data = Path(kf).read_bytes()
                except Exception:
                    self._send(500, {"success": False, "error": "keyfile unreadable"})
                    return
                try:
                    flag.parent.mkdir(parents=True, exist_ok=True)
                    fd = os.open(str(flag), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        os.write(fd, f"{int(time.time())}\n".encode("ascii"))
                        # H14: the one-shot marker must be durable BEFORE the
                        # key bytes leave the process, or a crash could serve
                        # the file twice after a reboot.
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    try:  # durability of the directory entry itself (POSIX)
                        dfd = os.open(str(flag.parent), os.O_RDONLY)
                        try:
                            os.fsync(dfd)
                        finally:
                            os.close(dfd)
                    except OSError:
                        pass
                except FileExistsError:
                    self._send(410, {"success": False, "error": "already served (one-time)"})
                    return
                except Exception:
                    self._send(500, {"success": False, "error": "could not mark keyfile state"})
                    return
                # Roll back the flag if the socket drops mid-transfer so a
                # broken connection does not burn the one-time download.
                try:
                    self.send_response(200)
                    self._send_sec_headers(no_store=True)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    try:
                        flag.unlink()
                    except Exception:
                        pass
                    return
            audit_ev(self._home(), {"ev": "sync", "action": "keyfile-served-once"})
            return
        if url.path == "/api/download":
            # Ciphertext only: useless without the host keyfile. Bearer-gated
            # like everything else; enables download -> edit in KeePassXC ->
            # upload round-trip without touching the terminal.
            try:
                data = Path(db).read_bytes()
            except Exception:
                self._send(500, {"success": False, "error": "db unreadable"})
                return
            audit_ev(self._home(), {"ev": "sync", "action": "db-downloaded",
                                    "bytes": len(data)})
            self.send_response(200)
            self._send_sec_headers(no_store=True)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition",
                             'attachment; filename="hermes.kdbx"')
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
                # Bounded read: last 64KB only, so a bloated audit file can
                # never balloon a response (or memory).
                with open(self._home() / "keygate-audit.jsonl", "rb") as f:
                    try:
                        f.seek(-65536, 2)
                        f.readline()  # drop a possibly torn first line
                    except OSError:
                        pass
                    lines = f.read().decode("utf-8", errors="replace").splitlines()[-n:]
            except Exception:
                lines = []
            self._send(200, {"success": True, "lines": lines})
            return
        if url.path == "/api/autofill":
            # Per-alias auto-fill policies: metadata only (alias, origins).
            # The policy file is shared with the plugin (same HOME).
            if kg.db_locked(db, kf):
                self._send(200, {"success": False, "locked": True, "items": []})
                return
            data = kg.load_autofill(self._home())
            policies = data.get("policies", {}) if isinstance(data, dict) else {}
            items = []
            for e in kg.list_entries(db, kf)[:200]:
                alias = e.split("/")[-1]
                try:
                    sug = kg.normalize_origin(kg.show_field(db, kf, e, "url") or "")
                except Exception:
                    sug = ""
                pol = policies.get(alias) if isinstance(policies, dict) else None
                if not isinstance(pol, dict):
                    pol = {}
                items.append({"alias": alias, "hint": kg.hint_for(alias, ""),
                              "enabled": bool(pol.get("enabled")),
                              "origin": str(pol.get("origin") or "") if pol.get("enabled") else "",
                              "suggested_origin": sug})
            self._send(200, {"success": True, "locked": False, "items": items})
            return
        self._send(404, {"success": False, "error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            self._send(403, {"success": False, "error": "forbidden"})
            return
        db, kf, _token, _b, _p, keep = self._cfg()
        url = urlparse(self.path)
        if url.path == "/api/set-password":
            # First visit only: creates the password (min 12 chars). Once set,
            # this endpoint is dead (403) — no change/reset over the web.
            if not self._rate_ok():
                self._send(429, {"success": False, "error": "rate limited"})
                return
            if not self._csrf_ok(want_json=True):
                return
            length = self._content_length()
            if length <= 0 or length > 1024:
                self._send(400, {"success": False, "error": "bad request size"})
                return
            try:
                password = str(json.loads(self.rfile.read(length).decode()).get("password") or "")
            except Exception:
                self._send(400, {"success": False, "error": "bad json"})
                return
            if password_is_set(self._home()):
                self._send(403, {"success": False, "error": "password already set"})
                return
            if len(password) < PW_MIN_LEN:
                self._send(400, {"success": False,
                                 "error": f"password must be >= {PW_MIN_LEN} chars"})
                return
            try:
                set_password_once(self._home(), password)
            except FileExistsError:
                self._send(403, {"success": False, "error": "password already set"})
                return
            except Exception:
                self._send(500, {"success": False, "error": "could not store password"})
                return
            audit_ev(self._home(), {"ev": "sync", "action": "password-created"})
            self._send(200, {"success": True})
            return
        if not self._need_auth():
            return
        if url.path == "/api/reset-password":
            # Change the web password. Requires the CURRENT one (proves
            # possession; no weaker than logging in). Min 12. Audited.
            if not self._csrf_ok(want_json=True):
                return
            length = self._content_length()
            if length <= 0 or length > 1024:
                self._send(400, {"success": False, "error": "bad request size"})
                return
            try:
                body_j = json.loads(self.rfile.read(length).decode())
                current = str(body_j.get("current") or "")
                new = str(body_j.get("new") or "")
            except Exception:
                self._send(400, {"success": False, "error": "bad json"})
                return
            if not check_password(self._home(), current):
                self._record_auth_fail()
                self._send(401, {"success": False, "error": "current password wrong"})
                return
            if len(new) < PW_MIN_LEN:
                self._send(400, {"success": False,
                                 "error": f"new password must be >= {PW_MIN_LEN} chars"})
                return
            try:
                salt = os.urandom(32)
                d = {"salt": salt.hex(), "hash": hash_pw(new, salt).hex(),
                     "iters": PW_ITERS, "set_at": int(time.time())}
                pf = passfile(self._home())
                pf.parent.mkdir(parents=True, exist_ok=True)
                tmp_pf = pf.with_suffix(".tmp")
                tmp_pf.write_text(json.dumps(d))
                os.chmod(tmp_pf, 0o600)
                os.replace(tmp_pf, pf)
            except Exception:
                self._send(500, {"success": False, "error": "could not store password"})
                return
            audit_ev(self._home(), {"ev": "sync", "action": "password-reset"})
            self._send(200, {"success": True})
            return
        if url.path == "/api/autofill":
            # Toggle a per-alias auto-fill policy. Requires the web session
            # (Bearer) plus an origin that matches the vault entry's exact origin:
            # the policy can never widen what the phishing guard already allows.
            if not self._csrf_ok(want_json=True):
                return
            length = self._content_length()
            if length <= 0 or length > 4096:
                self._send(400, {"success": False, "error": "bad request size"})
                return
            try:
                j = json.loads(self.rfile.read(length).decode())
                alias = str(j.get("alias") or "").strip()
                origin = str(j.get("origin") or "").strip()
                enabled = bool(j.get("enabled"))
            except Exception:
                self._send(400, {"success": False, "error": "bad json"})
                return
            if not alias:
                self._send(400, {"success": False, "error": "alias required"})
                return
            if kg.db_locked(db, kf):
                self._send(400, {"success": False, "locked": True,
                                 "error": "operative DB locked"})
                return
            entry, resolve_err = kg.resolve_entry(db, kf, alias)
            if not entry:
                self._send(404 if "not found" in (resolve_err or "") else 400,
                           {"success": False,
                            "error": resolve_err or "alias not found in operative vault"})
                return
            leaf_alias = entry.split("/")[-1]
            if enabled:
                norm = kg.normalize_origin(origin)
                if not norm:
                    self._send(400, {"success": False,
                                     "error": "origin must be a valid http(s)://host"})
                    return
                try:
                    vault_url = kg.show_field(db, kf, entry, "url") or ""
                except Exception:
                    vault_url = ""
                vnorm = kg.normalize_origin(vault_url)
                if not vnorm:
                    self._send(400, {"success": False,
                                     "error": ("vault entry has no valid URL — set the exact "
                                               "URL in KeePassXC before enabling auto-fill")})
                    return
                if norm != vnorm:
                    self._send(400, {"success": False,
                                     "error": (f"origin ({norm}) does not match the "
                                               f"vault entry origin ({vnorm})")})
                    return
                kg.set_autofill(self._home(), leaf_alias, norm, True)
                audit_ev(self._home(), {"ev": "sync", "action": "autofill-policy",
                                        "alias": kg.redact_label(leaf_alias),
                                        "origin": kg.redact_origin(norm),
                                        "enabled": True})
                self._send(200, {"success": True, "alias": leaf_alias,
                                 "enabled": True, "origin": norm})
            else:
                kg.set_autofill(self._home(), leaf_alias, origin, False)
                audit_ev(self._home(), {"ev": "sync", "action": "autofill-policy",
                                        "alias": kg.redact_label(leaf_alias),
                                        "origin": kg.redact_origin(origin),
                                        "enabled": False})
                self._send(200, {"success": True, "alias": leaf_alias, "enabled": False})
            return
        if not self._csrf_ok(want_json=False):
            return
        length = self._content_length()
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
            # Staging lives NEXT TO the DB (same filesystem): /tmp is often
            # tmpfs and os.replace() across filesystems dies with EXDEV.
            with tempfile.NamedTemporaryFile(delete=False, suffix=".kdbx",
                                             dir=str(Path(db).parent)) as tf:
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
                try:
                    os.replace(staging, db)
                except OSError:
                    # Cross-device fallback (shouldn't happen now that staging
                    # is next to the DB, but fail safe, never fail loud).
                    shutil.move(staging, db)
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

        self._send(404, {"success": False, "error": "not found"})

    def _count_with(self, staging: str, kf: str) -> int:
        # keepassxc-cli reads any path; staging validated by magic + open test
        try:
            p = subprocess.run(
                [kg._kxc(), "ls", "-R", "-k", kf, "--no-password", "-q", "--", staging],
                env=kg._child_env(), stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=30)
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
    db, kf, _token, bind, port, _keep = cfg()
    if os.environ.get("KEYGATE_SYNC_TOKEN"):
        print("aviso: KEYGATE_SYNC_TOKEN ya no se usa (auth ahora por contraseña creada en primera visita).",
              file=sys.stderr)
    # Esta es justamente la comprobación que rechaza 0.0.0.0.
    if bind == "0.0.0.0":  # nosec B104
        print("REFUSED: no bindees 0.0.0.0 — usa 127.0.0.1 o tu IP Tailscale.", file=sys.stderr)
        return 2
    if not Path(db).exists():
        print(f"DB no existe aún: {db} (corre keygate-setup primero)", file=sys.stderr)
    home = Path.home() / ".hermes"
    if not password_is_set(home):
        print("Sin contraseña todavía: la primera visita a la pagina la crea (min 12, una sola vez).",
              file=sys.stderr)
    try:  # PID file: lets the installer stop THIS server without pkill
        # (Hermes' gateway guard blocks pkill patterns).
        pf = home / "keygate-sync.pid"
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(str(os.getpid()))
        try:
            os.chmod(pf, 0o600)
        except Exception:
            pass
    except Exception:
        pass
    # bind ya validado arriba: 0.0.0.0 se rechaza antes de llegar aquí.
    global _ALLOWED_HOSTS
    _ALLOWED_HOSTS = _build_allowed_hosts(bind, port)
    srv = ThreadingHTTPServer((bind, port), Handler)  # nosec B104
    print(f"keygate-sync en http://{bind}:{port} (solo red local/Tailscale)")
    print("Auth por contraseña (PBKDF2, solo en tu navegador por pestaña). Jamás por chat (queda en historial).")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
