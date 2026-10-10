#!/usr/bin/env python3
"""keygate-leakcheck: prueba con canario de que ningún secreto llega al modelo.

Crea un vault temporal con una contraseña centinela (KGCANARY-<hex>, alta
entropía, imposible de confundir), corre TODAS las rutas del plugin contra él
(search, status, doctor, version, import-denied, fill-not-ready, sync
aliases/audit/download) y rastrea el centinela en cada superficie observable:
JSONs que vería el modelo, audit, respuestas de la web y bytes descargados.

Veredicto: PASS si el centinela no aparece en ningún lado en claro
(descargarlo cifrado está bien: verifica que NO esté en plaintext).
Nunca toca tu vault real (usa KEYGATE_DB/KEYGATE_KEYFILE + HOME temporales).

Uso: python3 scripts/keygate-leakcheck.py  (exit 0 = PASS, 1 = LEAK)
Requisito: keepassxc-cli (el mismo que usa el plugin).
"""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAILURES: list = []


def check(name: str, surfaces: dict):
    """surfaces: {nombre: texto}. FAIL si el centinela aparece en claro."""
    leaked = [k for k, v in surfaces.items() if CANARY in (v or "")]
    if leaked:
        FAILURES.append(name)
        print(f"  FAIL {name}: centinela visible en {leaked}")
    else:
        print(f"  ok   {name}")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


CANARY = "KGCANARY-" + secrets.token_hex(16)

REAL_HOME = os.path.expanduser("~")  # ANTES de cambiar HOME
HERMES_AGENT = os.path.join(REAL_HOME, ".hermes/hermes-agent")
PLUGIN_INIT = os.path.join(REAL_HOME, ".hermes/plugins/keygate/__init__.py")
tmp = Path(tempfile.mkdtemp(prefix="kgleak-"))
os.environ["HOME"] = str(tmp)  # audit del plugin cae aquí, no en tu ~/.hermes
TDB = str(tmp / "leak.kdbx")
TKF = str(tmp / "leak.key")
os.environ["KEYGATE_DB"] = TDB
os.environ["KEYGATE_KEYFILE"] = TKF
Path(TKF).write_bytes(os.urandom(128))
os.chmod(TKF, 0o600)

print(f"== keygate-leakcheck (canario {CANARY[:12]}…) ==")
# 1. vault temporal con el centinela como password (+ un user público).
# db-create SÍ crea DBs (add no); keyfile-only sin master.
p = run(["keepassxc-cli", "db-create", "--set-key-file", TKF, "-q", TDB])
assert Path(TDB).exists(), f"db-create falló: {p.stderr[:200]}"
p = run(["keepassxc-cli", "add", "-k", TKF, "--no-password", "-q", TDB,
         "canary-alias-1", "-u", "canaryuser", "--url",
         "https://example.com/login", "-p"], input=CANARY + "\n")
assert p.returncode == 0, f"add falló: {p.stderr[:200]}"
print("  ok   vault temporal con centinela (solo existe en /tmp)")

# 2. carga el plugin REAL (el instalado, no una copia)
sys.path.insert(0, HERMES_AGENT)
sys.path.insert(0, os.path.dirname(PLUGIN_INIT))
spec = importlib.util.spec_from_file_location("kgp", PLUGIN_INIT)
kgp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kgp)


class Ctx:
    def __init__(self):
        self.tools = {}
    def register_tool(self, **kw):
        self.tools[kw["name"]] = kw["handler"]
    def register_secret_source(self, s):
        pass
    def register_skill(self, n, p):
        pass


ctx = Ctx()
kgp.register(ctx)
T = ctx.tools
print("  ok   plugin cargado:", len(T), "tools")

# 3. corre todas las rutas que vería el modelo (sin browser, sin aprobación)
outs = {
    "search": T["keygate_search"]({"query": "canary"}),
    "status": T["keygate_status"]({}),
    "version": T["keygate_version"]({}),
    "doctor": T["keygate_doctor"]({}),
    "import-denied(headless)": T["keygate_import"]({"alias": "canary-alias-1"}),
    "fill-not-ready(headless)": T["keygate_request_fill"](
        {"alias": "canary-alias-1", "origin": "https://example.com"}),
    "alias-add-bloqueado": T["keygate_alias_add"]({}),
}
print("== superficies que vería el modelo ==")
for name, out in outs.items():
    check(name, {"json": out})
    if "canary-alias-1" in out and name == "search":
        print("       (el alias sí sale: es metadata, no secreto — esperado)")

# 4. audit temporal: estructura + ausencia del centinela
audit = ""
af = tmp / ".hermes" / "keygate-audit.jsonl"
if af.exists():
    audit = af.read_text()
    try:
        keys = sorted({k for line in audit.splitlines() if line.strip()
                       for k in json.loads(line).keys()})
        print("       claves de audit:", keys)
    except Exception as e:
        print("       audit ilegible:", e)
check("audit-temporal", {"audit": audit})

# 5. web: aliases/audit deben salir redactados; download NO en plaintext
print("== superficies web (server temporal) ==")
srv = subprocess.Popen(
    [sys.executable, str(REPO / "sync" / "keygate_sync.py")],
    env={**os.environ, "KEYGATE_BIND": "127.0.0.1", "KEYGATE_PORT": "8479"},
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import time
import urllib.request
time.sleep(2)
try:
    pw = "clave-temporal-larga-1"
    def api(path, data=None, auth=True):
        req = urllib.request.Request(
            f"http://127.0.0.1:8479{path}",
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Authorization": f"Bearer {pw}"} if auth else {})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read()
        except Exception as e:
            body = e.read() if hasattr(e, "read") else b""
            return getattr(e, "code", 0), body
    api("/api/set-password", {"password": pw}, auth=False)
    H = {"Authorization": f"Bearer {pw}"}
    _, aliases = api("/api/aliases")
    _, waudit = api("/api/audit?limit=50")
    req = urllib.request.Request("http://127.0.0.1:8479/api/download", headers=H)
    with urllib.request.urlopen(req, timeout=15) as r:
        blob = r.read()
    check("web-aliases", {"json": aliases.decode()})
    check("web-audit", {"json": waudit.decode()})
    # el blob SÍ contiene el centinela pero cifrado: no debe estar en claro
    if CANARY.encode() in blob:
        FAILURES.append("web-download")
        print("  FAIL web-download: ¡centinela en PLAINTEXT dentro del .kdbx!")
    else:
        print(f"  ok   web-download ({len(blob)}B cifrados, sin plaintext)")
finally:
    srv.terminate()

# 6. limpieza total del temporal (el centinela no queda en ningún lado)
import shutil
shutil.rmtree(tmp, ignore_errors=True)
print("== temporal borrado ==")
if FAILURES:
    print(f"LEAK en: {FAILURES}")
    sys.exit(1)
print("PASS: el centinela no salió del vault en ninguna superficie.")
