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


def check_password(user: str, password: str) -> bool:
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

PAGE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>keygate — alias</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;margin:0;background:#11141a;color:#e6e9ef}}
 header{{padding:18px 22px;background:#1a1f29;border-bottom:1px solid #2c3442}}
 h1{{margin:0;font-size:19px}} .sub{{color:#8b94a7;font-size:13px;margin-top:4px}}
 main{{padding:22px;max-width:900px}}
 table{{width:100%;border-collapse:collapse;margin-top:14px}}
 th,td{{text-align:left;padding:10px 8px;border-bottom:1px solid #242b37;font-size:14px}}
 th{{color:#8b94a7;font-weight:600;font-size:12px;text-transform:uppercase}}
 code{{background:#1e2432;padding:2px 6px;border-radius:4px;font-size:13px}}
 .on{{color:#5ddc9a}} .off{{color:#e8837a}}
 button{{background:#2f3a4d;color:#e6e9ef;border:1px solid #3b485f;border-radius:6px;
  padding:6px 12px;cursor:pointer;font-size:13px}}
 button:hover{{background:#3a4761}}
 .card{{background:#1a1f29;border:1px solid #2c3442;border-radius:10px;padding:16px;margin-top:18px}}
 .msg{{background:#1f3b2c;border:1px solid #2f6b4b;padding:10px 14px;border-radius:8px;margin-top:14px}}
</style></head><body>
<header><h1>keygate</h1>
<div class="sub">Alias y auto-fill. Esta página no muestra contraseñas: sólo políticas.</div></header>
<main>{msg}
<table><tr><th>Alias</th><th>Origen</th><th>Auto-fill</th><th></th></tr>{rows}</table>
<div class="card"><strong>Eventos recientes</strong>
<pre style="white-space:pre-wrap;font-size:12px;color:#9aa4b8">{audit}</pre></div>
</main></body></html>"""


def _render(msg: str = "") -> bytes:
    rows = []
    for r in alias_rows():
        state = '<span class="on">activo</span>' if r["enabled"] else '<span class="off">inactivo</span>'
        action = "disable" if r["enabled"] else "enable"
        rows.append(
            f'<tr><td><code>{html.escape(r["alias"])}</code></td>'
            f'<td>{html.escape(r["origin"])}</td><td>{state}</td>'
            f'<td><form method="post" action="/toggle" style="margin:0">'
            f'<input type="hidden" name="alias" value="{html.escape(r["alias"])}">'
            f'<input type="hidden" name="action" value="{action}">'
            f'<button type="submit">{action}</button></form></td></tr>')
    if not rows:
        rows.append('<tr><td colspan="4" style="color:#8b94a7">Sin alias todavía: '
                    'pídele a Hermes keygate_import con el alias de KeePass.</td></tr>')
    events = []
    audit_fp = home() / "keygate-audit.jsonl"
    if audit_fp.exists():
        for ln in audit_fp.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]:
            try:
                events.append(json.loads(ln))
            except Exception:
                continue
    body = "\n".join(json.dumps(e, ensure_ascii=False) for e in reversed(events))
    return PAGE.format(msg=msg, rows="".join(rows),
                       audit=html.escape(body or "—")).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "keygate-web/1.0"

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    def _authed(self) -> bool:
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
            msg = ""
            if q.get("alias"):
                msg = (f'<div class="msg">Alias <code>{html.escape(q["alias"][0])}</code> '
                       f'listo: activa auto-fill para no pedir aprobación.</div>')
            return self._send(_render(msg))
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
        msg = (f'<div class="msg">{html.escape(alias)} → '
               f'{"auto-fill activo" if action == "enable" else "auto-fill apagado"}</div>'
               if ok else '<div class="msg">no se pudo cambiar el alias</div>')
        return self._send(_render(msg))


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
