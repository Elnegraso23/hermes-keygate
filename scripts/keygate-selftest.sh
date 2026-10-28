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
# El updater hace `git pull --ff-only` contra el ORIGEN del repo. Si ese origin
# es un repo PRIVADO de GitHub, el pull pide usuario (no hay tty) y el selftest
# falla con "could not read Username" -> falso negativo que NO es un bug del
# updater. Por eso el selftest clona el repo a un clon LOCAL (file://, offline,
# sin red ni credenciales) y prueba el updater contra ese clon.
git -C "$REPO" rev-parse HEAD >/dev/null 2>&1 || { bad "repo git" "el repo del selftest no es git"; }
# Repo de prueba AUTÓNOMO, con su propio origin local y una rama real.
# No se clona $REPO: en CI el checkout de actions/checkout queda en HEAD
# DETACHED y sin ramas locales, así que el clon heredaba esa condición
# (sin rama, sin upstream) y el 'git pull --ff-only' del updater fallaba con
# "couldn't find remote ref main" -> falso negativo que NO era un bug del
# updater. Se arma a mano un repo con rama + origin local: determinista.
CLONE="$TMP/cloned-repo"
CLONE_ORIGIN="$TMP/cloned-origin.git"
rm -rf "$CLONE" "$CLONE_ORIGIN"
if mkdir -p "$CLONE" && git init -q -b main "$CLONE" 2>/dev/null; then
  # Snapshot del código del repo (sin .git) como contenido del repo de prueba.
  (cd "$REPO" && tar --exclude=.git -cf - .) | (cd "$CLONE" && tar -xf -) 2>/dev/null
  git -C "$CLONE" add -A >/dev/null 2>&1
  git -C "$CLONE" -c user.email=selftest@local -c user.name=selftest \
      commit -qm "snapshot para el test del updater" >/dev/null 2>&1
  git init -q --bare "$CLONE_ORIGIN" 2>/dev/null
  git -C "$CLONE" remote add origin "$CLONE_ORIGIN" 2>/dev/null || true
  git -C "$CLONE" push -q -u origin main >/dev/null 2>&1 || git -C "$CLONE" push -q origin main >/dev/null 2>&1
  out=$(HOME="$TMP" bash "$REPO/scripts/keygate-update" "$CLONE" 2>&1) || true
  echo "$out" | grep -qE "instalado en|sin cambios" && ok "updater con repo real instala" \
    || bad "updater con repo" "$(echo "$out" | tail -n 2)"
else
  bad "updater con repo" "no se pudo crear el repo de prueba"
fi

# --- 7b. updater JAMÁS toca vault/keyfile/pass/flag (garantía de actualización) ---
UH="$TMP/uhome"; mkdir -p "$UH/Documentos" "$UH/.hermes"
head -c 64 /dev/urandom | base64 > "$UH/.keepass-agent.key" && chmod 600 "$UH/.keepass-agent.key"
keepassxc-cli db-create --set-key-file "$UH/.keepass-agent.key" -q "$UH/Documentos/hermes.kdbx" >/dev/null 2>&1
printf 'x\n' | keepassxc-cli add -k "$UH/.keepass-agent.key" --no-password -q "$UH/Documentos/hermes.kdbx" u-entry -u u --url https://example.com/ -p >/dev/null 2>&1
echo "pass-falsa" > "$UH/.hermes/keygate-sync-pass"
echo "123" > "$UH/Documentos/.keygate-keyfile-served"
before=$(sha256sum "$UH/Documentos/hermes.kdbx" "$UH/.keepass-agent.key" "$UH/.hermes/keygate-sync-pass" "$UH/Documentos/.keygate-keyfile-served" | sha256sum | cut -d' ' -f1)
HOME="$UH" bash "$REPO/scripts/keygate-update" "$CLONE" >/dev/null 2>&1 || true
after=$(sha256sum "$UH/Documentos/hermes.kdbx" "$UH/.keepass-agent.key" "$UH/.hermes/keygate-sync-pass" "$UH/Documentos/.keygate-keyfile-served" | sha256sum | cut -d' ' -f1)
if [ "$before" = "$after" ]; then
  ok "updater no toca vault/keyfile/pass/flag (hashes idénticos)"
else
  bad "updater tocó el vault" "hash antes=$before después=$after"
fi
# y el updater aborta si el rango trajera .kdbx/.key (aunque .gitignore lo impide)
echo "$out" | grep -q "instalado en" && ok "marcador .installed_commit escrito" \
  || bad "marcador" "$out"

# --- 8. servidor vivo: health público + login card sin prompt() + PID file ---
SHOME="$TMP/srvhome"; mkdir -p "$SHOME"
SDB="$TMP/srvdb.kdbx"; SKF="$TMP/srv.key"
head -c 128 /dev/urandom > "$SKF" && chmod 600 "$SKF"
keepassxc-cli db-create --set-key-file "$SKF" -q "$SDB" >/dev/null 2>&1
printf 'x\n' | keepassxc-cli add -k "$SKF" --no-password -q "$SDB" t-alias -u u --url https://example.com/login -p >/dev/null 2>&1
SPORT=8479
HOME="$SHOME" KEYGATE_DB="$SDB" KEYGATE_KEYFILE="$SKF" KEYGATE_BIND=127.0.0.1 KEYGATE_PORT=$SPORT \
  setsid python3 "$REPO/sync/keygate_sync.py" >/tmp/kg-selftest-srv.log 2>&1 < /dev/null &
SRV=$!
sleep 2
B="http://127.0.0.1:$SPORT"
[ -f "$SHOME/.hermes/keygate-sync.pid" ] && ok "server escribe PID file" \
  || bad "PID file del server" "no apareció $SHOME/.hermes/keygate-sync.pid"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" "$B/api/health")
body=$(curl -s -m 10 "$B/api/health")
if [ "$code" = "200" ] && echo "$body" | grep -q '"entries": 1'; then
  ok "health público (locked/entries sin auth)"
else
  bad "health público" "code=$code body=$body"
fi
page=$(curl -s -m 10 "$B/")
if echo "$page" | grep -q "logincard" && ! echo "$page" | grep -q "prompt('Contraseña"; then
  ok "login card presente, prompt() nativo eliminado"
else
  bad "login card" "falta logincard o sigue prompt() nativo"
fi

# --- 9. reset-password + CSRF guard + security headers ---
# (el endpoint exige Bearer ADEMÁS del campo current: los curls llevan auth)
PW1="clave-inicial-larga-1"; PW2="clave-nueva-larga-22"
hdrs=$(curl -sI -m 10 "$B/")
if echo "$hdrs" | grep -qi "X-Frame-Options: DENY" && echo "$hdrs" | grep -qi "Content-Security-Policy:"; then
  ok "cabeceras HTTP de seguridad (X-Frame-Options + CSP)"
else
  bad "cabeceras HTTP" "$hdrs"
fi
csrf_code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$B/api/set-password" \
  -H 'Origin: https://evil.example' -H 'Content-Type: application/json' \
  -d "{\"password\":\"$PW1\"}")
[ "$csrf_code" = "403" ] && ok "CSRF cross-origin bloqueado en set-password (403)" \
  || bad "CSRF set-password" "esperaba 403, obtuvo $csrf_code"
r=$(curl -s -m 15 -X POST "$B/api/set-password" -H 'Content-Type: application/json' -d "{\"password\":\"$PW1\"}")
echo "$r" | grep -q '"success": true' && ok "set-password inicial" || bad "set-password" "$r"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$B/api/reset-password" \
  -H 'Content-Type: application/json' -d "{\"current\":\"mal\",\"new\":\"$PW2\"}")
[ "$code" = "401" ] && ok "reset sin Bearer -> 401" || bad "reset sin auth" "code=$code"
A1="Authorization: Bearer $PW1"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$B/api/reset-password" \
  -H "$A1" -H 'Content-Type: application/json' -d "{\"current\":\"mal\",\"new\":\"$PW2\"}")
[ "$code" = "401" ] && ok "reset con actual mala -> 401" || bad "reset mala" "code=$code"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$B/api/reset-password" \
  -H "$A1" -H 'Content-Type: application/json' -d "{\"current\":\"$PW1\",\"new\":\"corta\"}")
[ "$code" = "400" ] && ok "reset con nueva corta -> 400" || bad "reset corta" "code=$code"
r=$(curl -s -m 10 -X POST "$B/api/reset-password" -H "$A1" -H 'Content-Type: application/json' \
  -d "{\"current\":\"$PW1\",\"new\":\"$PW2\"}")
echo "$r" | grep -q '"success": true' && ok "reset con actual buena -> 200" || bad "reset buena" "$r"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $PW1" "$B/api/aliases")
[ "$code" = "401" ] && ok "password vieja ya no autentica" || bad "vieja aun vale" "code=$code"
code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $PW2" "$B/api/aliases")
[ "$code" = "200" ] && ok "password nueva autentica" || bad "nueva no vale" "code=$code"

# --- 10. upload round-trip: acepta válido, rehúsa vacío, rotación exacta ---
H="Authorization: Bearer $PW2"
# --- 9b. autofill policy (H9): acepta origen exacto, rehúsa rebaja http o dominio ajeno ---
af_bad=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$B/api/autofill" \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"alias":"t-alias","origin":"http://example.com","enabled":true}')
[ "$af_bad" = "400" ] && ok "autofill rehúsa rebaja https->http (400)" \
  || bad "autofill scheme downgrade" "esperaba 400, obtuvo $af_bad"
af_evil=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$B/api/autofill" \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"alias":"t-alias","origin":"https://example.com.evil.com","enabled":true}')
[ "$af_evil" = "400" ] && ok "autofill rehúsa subdominio/sufijo phishing (400)" \
  || bad "autofill phishing" "esperaba 400, obtuvo $af_evil"
af_ok=$(curl -s -m 10 -X POST "$B/api/autofill" \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"alias":"t-alias","origin":"https://example.com","enabled":true}')
echo "$af_ok" | grep -q '"enabled": true' && ok "autofill acepta origen exacto del vault" \
  || bad "autofill válido" "$af_ok"
DDB="$TMP/up.kdbx"
cp "$SDB" "$DDB"
# 5 backups viejos JUNTO AL DB DEL SERVER + upload = deben quedar exactamente 5 (fórmula sin +1)
for i in 1 2 3 4 5; do cp "$SDB" "$SDB.100$i.bak"; touch -d "@100$i" "$SDB.100$i.bak"; done
printf 'y\n' | keepassxc-cli add -k "$SKF" --no-password -q "$DDB" t-alias-2 -u u2 --url https://example.com/login -p >/dev/null 2>&1
r=$(curl -s -m 30 -X POST -H "$H" -F "db=@$DDB;filename=hermes.kdbx" "$B/api/upload")
if echo "$r" | grep -q '"success": true'; then
  ok "upload válido aceptado: $r"
else
  bad "upload válido" "$r"
fi
n=$(ls "$SDB".*.bak 2>/dev/null | wc -l)
[ "$n" = "5" ] && ok "rotación exacta: 5 backups (no 4)" || bad "rotación" "quedaron $n, esperaba 5"
EDB="$TMP/empty.kdbx"
keepassxc-cli db-create --set-key-file "$SKF" -q "$EDB" >/dev/null 2>&1
r=$(curl -s -m 30 -X POST -H "$H" -F "db=@$EDB;filename=hermes.kdbx" "$B/api/upload")
echo "$r" | grep -q "anti-wipe" && ok "upload vacío rehusado (anti-wipe)" || bad "anti-wipe" "$r"
left=$(ls "$(dirname "$SDB")"/hermes.kdbx.* 2>/dev/null | grep -v -E "\.bak$|srvdb" | wc -l)
[ "$left" = "0" ] && ok "staging limpiado tras rechazo" || bad "staging huerfano" "$left archivos"
kill $SRV 2>/dev/null || true

# --- 11. keygate-setup --reset-key con la DB YA CREADA ---
# (bug real: el reseteo del flag one-shot estaba AL FINAL del script, despues
#  de la rama "operative DB exists" que hace `exit 0` -> con la DB ya creada el
#  flag NUNCA se borraba y el .key quedaba irrecuperable desde la web: el
#  endpoint /api/onboarding/keyfile respondia 410 Gone para siempre.)
RDB="$TMP/reset/hermes.kdbx"
RKF="$TMP/reset/.keepass-agent.key"
mkdir -p "$TMP/reset"
HOME="$TMP/reset" KEYGATE_DB="$RDB" KEYGATE_KEYFILE="$RKF" \
  bash "$REPO/scripts/keygate-setup" >/dev/null 2>&1
FLAG="$(dirname "$RDB")/.keygate-keyfile-served"
printf '%s\n' "1234567890" > "$FLAG"
out=$(HOME="$TMP/reset" KEYGATE_DB="$RDB" KEYGATE_KEYFILE="$RKF" \
      bash "$REPO/scripts/keygate-setup" --reset-key 2>&1)
if [ ! -f "$FLAG" ]; then
  ok "--reset-key borra el flag one-shot aunque la DB ya exista"
else
  bad "--reset-key con DB existente" "el flag .keygate-keyfile-served sigue ahí (no-op silencioso)"
fi
# El reset NO debe regenerar el keyfile ni tocar la DB operativa.
if [ -f "$RKF" ] && [ -f "$RDB" ]; then
  ok "--reset-key no toca keyfile ni DB operativa"
else
  bad "--reset-key destruyó keyfile o DB" "keyfile o vault faltantes"
fi
# Y el vault debe seguir abrible con su keyfile (integridad).
if HOME="$TMP/reset" KEYGATE_DB="$RDB" KEYGATE_KEYFILE="$RKF" \
   timeout 10 keepassxc-cli ls -k "$RKF" --no-password -q "$RDB" < /dev/null >/dev/null 2>&1; then
  ok "vault sigue abrible tras --reset-key"
else
  bad "vault abrible tras --reset-key" "keepassxc-cli no pudo abrir el vault"
fi

echo "== selftest: $pass PASS, $fail FAIL =="
[ "$fail" = 0 ] || exit 1
