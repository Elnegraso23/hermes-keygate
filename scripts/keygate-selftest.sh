#!/bin/bash
# keygate-selftest: prueba de regresión para la clase de bug
# "funciona en mi máquina, muere en un host fresco".
#
# Corre las operaciones frágiles bajo un HOME desechable SIMULANDO host fresco:
# sin ~/Documentos, sin ~/.hermes, sin repo, sin red. Cada PASS es una clase de
# falla que ya ocurrió y no debe volver.
#
# Uso: scripts/keygate-selftest.sh   (exit 0 = todos PASS)
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/kg-selftest-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok()   { echo "  PASS $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL $1 — $2"; fail=$((fail+1)); }

echo "== keygate-selftest (HOME fresco: $TMP) =="
mkdir -p "$TMP"

# --- 1. keygate-setup en home SIN ~/Documentos ni ~/.config ---
# (bug real: db-create moría con "No such file or directory" en /opt/hermes)
out=$(HOME="$TMP" KEYGATE_DB="$TMP/Documentos/hermes.kdbx" \
      KEYGATE_KEYFILE="$TMP/.keepass-agent.key" \
      bash "$REPO/scripts/keygate-setup" 2>&1)
if [ -f "$TMP/Documentos/hermes.kdbx" ] && [ -f "$TMP/.keepass-agent.key" ]; then
  ok "keygate-setup crea el dir del vault (home fresco)"
else
  bad "keygate-setup en home fresco" "$(echo "$out" | tail -n 2)"
fi
if [ "$(stat -c '%a' "$TMP/.keepass-agent.key" 2>/dev/null)" = "600" ]; then
  ok "keyfile queda 0600"
else
  bad "permisos del keyfile" "esperaba 600"
fi

# --- 2. escritura del audit sin ~/.hermes ---
# (el audit sin mkdir reventaba en homes nuevos)
out=$(HOME="$TMP/h2" mkdir -p "$TMP/h2" && \
      PYTHONPATH="$REPO" HOME="$TMP/h2" python3 -c "
import keygate_lib as kg
kg.audit(__import__('pathlib').Path('$TMP/h2/.hermes'), {'ev': 'selftest', 'decision': 'allow'})
print('audit-ok')" 2>&1)
[ -f "$TMP/h2/.hermes/keygate-audit.jsonl" ] && ok "audit crea ~/.hermes si falta" \
  || bad "audit sin ~/.hermes" "$out"

# --- 3. password del sync sin ~/.hermes (500 real en su momento) ---
out=$(PYTHONPATH="$REPO/sync" python3 -c "
import sys, tempfile, json
from pathlib import Path
sys.path.insert(0, '$REPO/sync')
import keygate_sync as ks
home = Path(tempfile.mkdtemp()) / 'no-existe-aun'
assert ks.set_password_once(home, 'clave-de-prueba-larga-y-larga')
d = json.loads((home / 'keygate-sync-pass').read_bytes().decode())
assert d['salt'] and d['hash']
assert ks.check_password(home, 'clave-de-prueba-larga-y-larga') is True
assert ks.set_password_once(home, 'otra') is False
print('pass-ok')" 2>&1)
echo "$out" | grep -q "pass-ok" && ok "set_password_once crea el home" || bad "password sin ~/.hermes" "$out"

# --- 4. rutas con comillas (el 'locked' fantasma) ---
out=$(PYTHONPATH="$REPO" python3 -c "
import keygate_lib as kg
db, kf = kg.cfg_paths({'db_path': '\"$TMP/Documentos/hermes.kdbx\"',
                       'keyfile': '\"$TMP/.keepass-agent.key\"'})
assert db == '$TMP/Documentos/hermes.kdbx', db
assert kf == '$TMP/.keepass-agent.key', kf
assert kg.db_locked(db, kf) is False
print('quotes-ok')" 2>&1)
echo "$out" | grep -q "quotes-ok" && ok "cfg_paths sanea comillas + vault abre" || bad "comillas en rutas" "$out"

# --- 5. preflight corre y crea el dir del vault ---
out=$(HOME="$TMP/h5" KEYGATE_DB="$TMP/h5/Documentos/hermes.kdbx" \
      bash "$REPO/scripts/keygate-preflight.sh" 2>&1)
if echo "$out" | grep -q "preflight OK" && [ -d "$TMP/h5/Documentos" ]; then
  ok "preflight pasa en home fresco (y crea el dir)"
else
  bad "preflight en home fresco" "$(echo "$out" | tail -n 2)"
fi

# --- 6. updater: repo inexistente falla con mensaje claro, no con error crudo ---
out=$(HOME="$TMP" bash "$REPO/scripts/keygate-update" 2>&1)
if echo "$out" | grep -q "no encuentro el clon"; then
  ok "updater sin repo: mensaje claro"
else
  bad "updater sin repo" "$out"
fi

# --- 7. updater con repo local real llega a comparar HEAD ---
git -C "$REPO" rev-parse HEAD >/dev/null 2>&1 || { bad "repo git" "el repo del selftest no es git"; }
out=$(HOME="$TMP" bash "$REPO/scripts/keygate-update" "$REPO" 2>&1) || true
echo "$out" | grep -qE "instalado en|sin cambios" && ok "updater con repo real instala" \
  || bad "updater con repo" "$(echo "$out" | tail -n 2)"

echo "== selftest: $pass PASS, $fail FAIL =="
[ "$fail" = 0 ] || exit 1
