"""keygate_web — alias & auto-fill page for keygate (stdlib only).

This page manages *policies*, never secrets: it lists the aliases keygate knows,
shows which ones auto-fill without an approval prompt, and lets the owner flip
that switch -- so Hermes can hand out a link instead of asking for an approval
on every login.

Access is protected by HTTP Basic auth; only a PBKDF2-SHA256 hash is stored, in
``~/.hermes/keygate-web.meta.json`` (0600). The page never accepts or displays a
site password.

CLI:
  python3 keygate_web.py init                 # set the access password (getpass)
  python3 keygate_web.py set-password
  python3 keygate_web.py serve [--bind H] [--port 8790]
  python3 keygate_web.py url [ALIAS]          # print the URL Hermes should send
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import keygate_lib as kg

DEFAULT_PORT = 8790
PBKDF2_ROUNDS = 260_000


def home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")


def meta_path() -> Path:
    return home() / "keygate-web.meta.json"


def _load_meta() -> dict:
    try:
        return json.loads(meta_path().read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_meta(data: dict) -> None:
    fp = meta_path()
    fp.parent.mkdir(parents=True, exist_ok=True)
    tmp = fp.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, fp)


# ------------------------------------------------------------------- auth ---

def _hash(password: str, salt: bytes) -> str:
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", password.encode(),
                                                salt, PBKDF2_ROUNDS)).decode()


def set_password(password: str) -> None:
    meta = _load_meta()
    salt = os.urandom(16)
    meta["salt"] = base64.b64encode(salt).decode()
    meta["hash"] = _hash(password, salt)
    meta.setdefault("port", DEFAULT_PORT)
    meta.setdefault("bind", "127.0.0.1")
    meta["created"] = meta.get("created", int(time.time()))
    meta["rotated"] = int(time.time())
    _save_meta(meta)


def noauth_enabled() -> bool:
    """Modo sin contraseña explícito (KEYGATE_ALIAS_NOAUTH=1).

    Pensado para una página que sólo escucha en localhost o en la tailnet del
    dueño, cuando éste decide no poner contraseña. Cualquiera que alcance el
    puerto puede cambiar el auto-fill de los alias (nunca ver contraseñas).
    """
    return (os.environ.get("KEYGATE_ALIAS_NOAUTH") or "").strip().lower() in ("1", "true", "yes", "on")


def _sync_passfile() -> Path:
    return home() / "keygate-sync-pass"


def check_password(user: str, password: str) -> bool:
    """Una sola contraseña para las dos páginas.

    Si existe la contraseña de keygate-sync (la que el usuario define en el
    paso 1 del asistente), se valida contra ella: misma credencial en :8472 y
    :8790. Si no existe, se usa la contraseña propia de esta página (legado).
    """
    sp = _sync_passfile()
    if sp.exists():
        try:
            d = json.loads(sp.read_text(encoding="utf-8"))
            salt = bytes.fromhex(d["salt"])
            iters = int(d.get("iters") or PBKDF2_ROUNDS)
            got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters).hex()
            return hmac.compare_digest(got, str(d["hash"]))
        except Exception:
            return False
    meta = _load_meta()
    if not meta.get("hash") or not meta.get("salt"):
        return False
    salt = base64.b64decode(meta["salt"])
    return hmac.compare_digest(_hash(password, salt), meta["hash"])


# ------------------------------------------------------------------- views ---

def alias_rows() -> list:
    idx = kg.load_index(home()).get("aliases", {})
    pol = kg.load_autofill(home()).get("policies", {})
    rows = []
    for name in sorted(set(idx) | set(pol)):
        p = pol.get(name) or {}
        rows.append({"alias": name,
                     "origin": p.get("origin") or (idx.get(name) or {}).get("origin") or "",
                     "enabled": bool(p.get("enabled"))})
    return rows


def apply_toggle(alias: str, enable: bool) -> bool:
    if not alias:
        return False
    if enable:
        origin = ((kg.load_autofill(home()).get("policies", {}).get(alias) or {}).get("origin")
                  or (kg.load_index(home()).get("aliases", {}).get(alias) or {}).get("origin"))
        if not origin:
            return False
        kg.set_autofill(home(), alias, origin, True)
        return True
    kg.set_autofill(home(), alias, "", False)  # repo semantics: delete the policy
    return True


def url_for(alias: str = "") -> str:
    meta = _load_meta()
    port = int(meta.get("port") or DEFAULT_PORT)
    bind = str(meta.get("bind") or "127.0.0.1")
    if bind in ("127.0.0.1", "localhost", "::1"):
        host = bind
    elif bind in ("0.0.0.0", "::", ""):  # nosec B104 - comparación, no bind: LAN es opt-in explícito
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.0.1", 9))
            host = s.getsockname()[0]
        except Exception:
            host = "localhost"
        finally:
            s.close()
    else:
        host = bind
    return f"http://{host}:{port}/" + (f"?alias={alias}" if alias else "")


# ------------------------------------------------------------------ server ---

PAGE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>keygate — alias</title>
<style>
:root{
  color-scheme: light dark;
  --bg:        light-dark(oklch(98.4% 0.003 250), oklch(19%   0.015 255));
  --surface:   light-dark(oklch(100%  0     0  ), oklch(23%   0.017 255));
  --surface-2: light-dark(oklch(96.5% 0.004 250), oklch(26.5% 0.019 255));
  --line:      light-dark(oklch(88%   0.007 250), oklch(33%   0.020 255));
  --text:      light-dark(oklch(21%   0.010 255), oklch(95%   0.008 255));
  --muted:     light-dark(oklch(44%   0.015 255), oklch(74%   0.015 255));
  --accent:    light-dark(oklch(50%   0.150 255), oklch(80%   0.120 220));
  --ok:        light-dark(oklch(42%   0.120 155), oklch(84%   0.130 155));
  --ok-bg:     light-dark(oklch(94%   0.040 155), oklch(30%   0.045 155));
  --warn:      light-dark(oklch(45%   0.110 70 ), oklch(86%   0.110 85 ));
  --warn-bg:   light-dark(oklch(95%   0.035 85 ), oklch(31%   0.040 85 ));
  --off:       light-dark(oklch(45%   0.160 25 ), oklch(80%   0.110 30 ));
  --off-bg:    light-dark(oklch(95%   0.030 25 ), oklch(31%   0.045 30 ));
  --focus:     light-dark(oklch(52%   0.180 255), oklch(86%   0.140 220));
  --radius: 10px;
  --wrap: 62rem;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  scrollbar-color: light-dark(oklch(70% 0.01 255), oklch(45% 0.015 255))
                  light-dark(oklch(94% 0.004 250), oklch(24% 0.015 255));
  scrollbar-width: thin;
  accent-color: var(--accent);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
  -webkit-text-size-adjust: 100%;
}
*, *::before, *::after{ box-sizing: border-box; }
::selection{ background: var(--accent); color: var(--bg); }
:focus-visible{ outline: 2px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
body{ margin: 0; }
.wrap{
  inline-size: 100%; max-inline-size: var(--wrap);
  margin-inline: auto; padding-inline: clamp(1rem, 3vw, 1.75rem);
}
.bar{
  position: sticky; inset-block-start: 0; z-index: 10;
  background: var(--surface); border-block-end: 1px solid var(--line);
}
.bar .wrap{
  display: flex; flex-wrap: wrap; gap: .75rem 1rem;
  align-items: center; justify-content: space-between;
  padding-block: 1rem;
}
.bar h1{ margin: 0; font-size: 1.15rem; letter-spacing: -0.01em; text-wrap: balance; }
.sub{ margin: .2rem 0 0; color: var(--muted); font-size: .82rem; max-inline-size: 46ch; text-wrap: pretty; }
main{ padding-block: clamp(1rem, 3vw, 1.75rem) 3rem; }
main .wrap{ display: grid; gap: 1.75rem; }
h2{
  margin: 0 0 .6rem; font-size: .72rem; font-weight: 650; letter-spacing: .07em;
  text-transform: uppercase; color: var(--muted);
  display: flex; align-items: baseline; justify-content: space-between; gap: 1rem;
}
h2 .count{ font-weight: 500; letter-spacing: 0; text-transform: none; font-size: .76rem; }
.flash{
  display: flex; align-items: flex-start; gap: .6rem;
  padding: .7rem .9rem;
  background: var(--surface); border: 1px solid var(--line);
  border-inline-start: 3px solid var(--accent);
  border-radius: var(--radius); font-size: .88rem;
  opacity: 1; transform: translateY(0);
  transition: opacity .28s ease, transform .28s cubic-bezier(.2,.7,.3,1);
}
.flash--err{ border-inline-start-color: var(--off); }
.flash strong{ font-weight: 650; }
@starting-style{ .flash{ opacity: 0; transform: translateY(-6px); } }
.table-wrap{
  container-type: inline-size; overflow: auto;
  max-block-size: min(30rem, 70vh);
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius);
}
table{ inline-size: 100%; border-collapse: separate; border-spacing: 0; font-size: .9rem; }
caption.vh{
  position: absolute; inline-size: 1px; block-size: 1px;
  overflow: hidden; clip-path: inset(50%); white-space: nowrap;
}
thead th{
  position: sticky; inset-block-start: 0; z-index: 2;
  background: var(--surface-2); text-align: start;
  padding: .55rem .9rem;
  font-size: .68rem; font-weight: 650; letter-spacing: .06em;
  text-transform: uppercase; color: var(--muted);
  border-block-end: 1px solid var(--line); white-space: nowrap;
}
thead th:last-child, tbody td:last-child{ text-align: end; }
thead th.col-status, tbody td.col-status{ text-align: start; }
tbody th, tbody td{
  padding: .55rem .9rem; text-align: start; font-weight: 400;
  border-block-end: 1px solid color-mix(in oklch, var(--line) 55%, transparent);
  vertical-align: middle;
}
tbody tr:last-child th, tbody tr:last-child td{ border-block-end: 0; }
tbody th{
  font-weight: 600; position: sticky; inset-inline-start: 0;
  background: var(--surface); white-space: nowrap;
  font-family: var(--mono); font-size: .84rem;
}
tbody tr:hover th, tbody tr:hover td{ background: var(--surface-2); }
tbody tr[data-changed] th{ box-shadow: inset 3px 0 0 var(--accent); color: var(--accent); }
.origin{ color: var(--muted); font-family: var(--mono); font-size: .82rem; }
.pill{
  display: inline-flex; align-items: center; gap: .38rem;
  inline-size: fit-content;
  padding: .14rem .5rem .14rem .42rem;
  border-radius: 999px; font-size: .77rem; font-weight: 550; white-space: nowrap;
}
.pill::before{
  content: ""; inline-size: .4rem; block-size: .4rem;
  border-radius: 50%; background: currentColor; flex: none;
}
.pill--on{ background: var(--ok-bg); color: var(--ok); }
.pill--warn{ background: var(--warn-bg); color: var(--warn); }
.pill--off{ background: var(--off-bg); color: var(--off); }
.empty{ color: var(--muted); font-size: .88rem; }
.btn{
  font: inherit; font-size: .8rem; font-weight: 500;
  min-block-size: 1.9rem; padding: .25rem .7rem;
  color: var(--text); background: var(--surface-2);
  border: 1px solid var(--line); border-radius: 8px;
  cursor: pointer; white-space: nowrap;
  transition: background .15s ease, border-color .15s ease, transform .08s ease;
}
.btn:hover{ border-color: var(--accent); background: color-mix(in oklch, var(--surface-2) 72%, var(--text) 8%); }
.btn:active{ transform: translateY(1px); }
form.inline{ margin: 0; display: inline; }
.log{
  container-type: inline-size;
  margin: 0; padding: .3rem; list-style: none;
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); max-block-size: 16rem; overflow: auto;
  font-size: .83rem;
}
.log li{
  display: grid; grid-template-columns: 4.4rem 5.6rem 1fr auto;
  gap: .7rem; align-items: center;
  padding: .42rem .55rem; border-radius: 6px;
  font-variant-numeric: tabular-nums;
}
.log li + li{ border-block-start: 1px solid color-mix(in oklch, var(--line) 50%, transparent); }
.log time{ color: var(--muted); }
.log .ev{ font-family: var(--mono); font-size: .78rem; }
.log .al{ color: var(--muted); font-family: var(--mono); font-size: .78rem; overflow-wrap: anywhere; }
@container (width < 34rem){
  table, thead, tbody, tr, th, td{ display: block; }
  thead{ display: none; }
  tbody tr{
    margin: 0 0 .75rem; padding: .6rem .75rem .75rem;
    border: 1px solid var(--line); border-radius: var(--radius);
  }
  tbody tr:last-child{ margin-block-end: 0; }
  tbody th{ position: static; background: transparent; font-size: .95rem; padding: 0 0 .45rem; }
  tbody tr[data-changed] th{ box-shadow: none; }
  tbody tr[data-changed]{ box-shadow: inset 3px 0 0 var(--accent); }
  tbody td{
    border: 0; padding: .18rem 0; text-align: start;
    display: grid; grid-template-columns: 6rem 1fr; gap: .5rem; align-items: center;
  }
  tbody td::before{
    content: attr(data-label); color: var(--muted);
    font-size: .68rem; font-weight: 650; letter-spacing: .06em; text-transform: uppercase;
  }
  tbody td:last-child{ padding-block-start: .55rem; }
  tbody td:last-child::before{ content: none; }
  tbody td:last-child .btn{ inline-size: 100%; }
  .table-wrap{ background: transparent; border: 0; }
}
@container (width < 30rem){
  .log li{
    grid-template-columns: 3.6rem 1fr auto;
    grid-template-areas: "time ev dec" "alias alias alias";
    row-gap: .3rem;
  }
  .log time{ grid-area: time; }
  .log .ev{ grid-area: ev; }
  .log .de{ grid-area: dec; justify-self: end; }
  .log .al{ grid-area: alias; padding-inline-start: 3.6rem; }
}
@media (prefers-reduced-motion: reduce){
  *{ transition: none !important; animation: none !important; }
}
@media (forced-colors: active){
  .pill, .btn, .flash, .table-wrap, .log{ border: 1px solid CanvasText; }
}
</style>
</head>
<body>

<header class="bar">
  <div class="wrap">
    <div>
      <h1>keygate</h1>
      <p class="sub">Alias y auto-fill. Esta página no muestra contraseñas: solo políticas.</p>
    </div>
    <span class="pill pill--on">@@COUNT@@</span>
  </div>
</header>

<main>
  <div class="wrap">
    @@MSG@@
    <section aria-labelledby="alias-h">
      <h2 id="alias-h">Estado por alias <span class="count">@@ALIASCOUNT@@</span></h2>
      <div class="table-wrap" tabindex="0" role="region" aria-labelledby="alias-h">
        <table>
          <caption class="vh">Alias registrados: origen, estado del auto-fill y acciones</caption>
          <thead>
            <tr>
              <th scope="col">Alias</th>
              <th scope="col">Origen</th>
              <th scope="col" class="col-status">Auto-fill</th>
              <th scope="col"><span class="vh">Acciones</span></th>
            </tr>
          </thead>
          <tbody>
@@ROWS@@
          </tbody>
        </table>
      </div>
    </section>

    <section aria-labelledby="log-h">
      <h2 id="log-h">Eventos recientes <span class="count">@@EVCOUNT@@</span></h2>
      <ol class="log" tabindex="0" role="region" aria-label="Bitácora de auto-fill">
@@EVENTS@@
      </ol>
    </section>
  </div>
</main>

</body>
</html>"""

_DECISIONS = {
    "allow": ("pill--on", "permitido"),
    "intent": ("pill--warn", "sin relleno"),
    "deny": ("pill--off", "bloqueado"),
    "blocked": ("pill--off", "bloqueado"),
    "error": ("pill--off", "error"),
}


def _pretty_origin(origin: str) -> str:
    """Host + ruta, sin esquema: 'https://mail.x.com/' -> 'mail.x.com'."""
    s = (origin or "").strip()
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    return s.rstrip("/")


def _count_label(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _events(limit: int = 8) -> list:
    audit_fp = home() / "keygate-audit.jsonl"
    out = []
    if audit_fp.exists():
        for ln in audit_fp.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
            try:
                ev = json.loads(ln)
            except Exception:
                continue
            if isinstance(ev, dict):
                out.append(ev)
    out.reverse()  # el más reciente primero
    return out


def _event_items(events: list) -> str:
    items = []
    for ev in events:
        ts = ev.get("ts")
        try:
            stamp = time.strftime("%H:%M", time.localtime(float(ts)))
            iso = time.strftime("%Y-%m-%dT%H:%M", time.localtime(float(ts)))
        except Exception:
            stamp, iso = "--:--", ""
        cls, label = _DECISIONS.get(str(ev.get("decision") or "").lower(), ("pill--warn", "registrado"))
        target = _pretty_origin(ev.get("origin") or "") or ev.get("alias") or "—"
        items.append(
            '<li>'
            f'<time datetime="{html.escape(iso)}">{html.escape(stamp)}</time>'
            f'<span class="ev">{html.escape(str(ev.get("ev") or "?"))}</span>'
            f'<span class="al">{html.escape(str(target))}</span>'
            f'<span class="pill de {cls}">{html.escape(label)}</span>'
            "</li>")
    if not items:
        items.append('<li><span class="al">Sin eventos registrados todavía.</span></li>')
    return "\n".join(items)


def _render(msg: str = "", kind: str = "ok", changed: str = "") -> bytes:
    data = alias_rows()
    rows = []
    for r in data:
        alias = html.escape(r["alias"])
        origin = html.escape(_pretty_origin(r["origin"])) or "—"
        if r["enabled"]:
            pill = '<span class="pill pill--on">activo</span>'
            action, label = "disable", "Desactivar"
        else:
            pill = '<span class="pill pill--warn">pausado</span>'
            action, label = "enable", "Activar"
        flag = ' data-changed' if r["alias"] == changed else ""
        rows.append(
            f'<tr{flag}>'
            f'<th scope="row">{alias}</th>'
            f'<td data-label="Origen" class="origin">{origin}</td>'
            f'<td data-label="Auto-fill" class="col-status">{pill}</td>'
            f'<td><form class="inline" method="post" action="/toggle">'
            f'<input type="hidden" name="alias" value="{alias}">'
            f'<input type="hidden" name="action" value="{action}">'
            f'<button class="btn" type="submit">{label}</button>'
            "</form></td></tr>")
    if not rows:
        rows.append('<tr><td colspan="4" class="empty">Sin alias todavía: pídele a Hermes '
                    'keygate_import con el alias de KeePass.</td></tr>')

    events = _events()
    flash = ""
    if msg:
        cls = "flash flash--err" if kind == "err" else "flash"
        flash = f'<p class="{cls}" role="status">{msg}</p>'

    page = (PAGE
            .replace("@@COUNT@@", html.escape(_count_label(len(data), "alias", "alias")))
            .replace("@@ALIASCOUNT@@", html.escape(_count_label(len(data), "registrado", "registrados")))
            .replace("@@EVCOUNT@@", html.escape(_count_label(len(events), "último", "últimos")))
            .replace("@@MSG@@", flash)
            .replace("@@ROWS@@", "\n".join(rows))
            .replace("@@EVENTS@@", _event_items(events)))
    return page.encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "keygate-web/1.0"

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    def _authed(self) -> bool:
        if noauth_enabled():
            return True
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
        except Exception:
            return False
        return check_password(user, pw)

    def _deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="keygate"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"auth required\n")

    def _send(self, body: bytes, code: int = 200, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Esta página no ejecuta JavaScript: sin script-src, nada corre.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self._send(b"ok\n", ctype="text/plain")
        if not self._authed():
            return self._deny()
        if path == "/":
            q = parse_qs(urlparse(self.path).query)
            msg, changed = "", ""
            if q.get("alias"):
                alias = q["alias"][0]
                msg = (f"Alias <strong>{html.escape(alias)}</strong> listo: "
                       "activa el auto-fill para no pedir aprobación cada vez.")
                changed = alias
            return self._send(_render(msg, changed=changed))
        if path == "/audit":
            fp = home() / "keygate-audit.jsonl"
            body = fp.read_text(encoding="utf-8", errors="replace") if fp.exists() else ""
            return self._send(body.encode(), ctype="text/plain; charset=utf-8")
        return self._send(b"not found\n", 404, "text/plain")

    def do_POST(self):
        if not self._authed():
            return self._deny()
        if urlparse(self.path).path != "/toggle":
            return self._send(b"not found\n", 404, "text/plain")
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(min(length, 4096)).decode("utf-8", "replace"))
        alias = (form.get("alias") or [""])[0]
        action = (form.get("action") or [""])[0]
        ok = apply_toggle(alias, action == "enable")
        if ok:
            msg = (f'Alias <strong>{html.escape(alias)}</strong> → '
                   f'{"auto-fill activo" if action == "enable" else "auto-fill apagado"}.')
        else:
            msg = "No se pudo cambiar el alias."
        return self._send(_render(msg, kind="ok" if ok else "err",
                                  changed=alias if ok else ""))


def serve(bind: str = "127.0.0.1", port: int = DEFAULT_PORT) -> None:
    """Bind locally by default; pass --bind 0.0.0.0 (or a tailnet IP) for LAN.

    LAN se habilita sólo con --bind explícito: nunca por defecto.
    """
    meta = _load_meta()
    meta.update({"bind": bind, "port": port, "updated": int(time.time())})
    _save_meta(meta)
    httpd = ThreadingHTTPServer((bind, port), Handler)
    sys.stderr.write(f"keygate-web listening on http://{bind}:{port}\n")
    httpd.serve_forever()


def _cli(argv) -> int:
    cmd = argv[1] if len(argv) > 1 else "help"
    if cmd in ("init", "set-password"):
        if "--from-stdin" in argv:  # instalación desatendida: nunca por argv
            pw = sys.stdin.readline().strip()
        else:
            from getpass import getpass
            pw = getpass("keygate web password: ")
            if pw != getpass("confirm: "):
                print("mismatch")
                return 2
        if len(pw) < 10:
            print("password too short (10+ chars)")
            return 2
        set_password(pw)
        print(json.dumps({"ok": True, "meta": str(meta_path())}))
        return 0
    if cmd == "serve":
        bind, port = "127.0.0.1", DEFAULT_PORT
        args = argv[2:]
        for i, a in enumerate(args):
            if a == "--bind" and i + 1 < len(args):
                bind = args[i + 1]
            elif a == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
        serve(bind, port)
        return 0
    if cmd == "url":
        print(url_for(argv[2] if len(argv) > 2 else ""))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
