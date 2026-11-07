#!/bin/bash
# keygate-install: one-shot setup. Idempotent (safe to re-run).
# Clones if missing, installs plugin + skills, enables it, creates the
# operative vault, applies config (no quotes), and STARTS keygate-sync.
# Prints the exact URLs/commands the user needs afterwards.
#
# Usage: bash <repo>/scripts/keygate-install.sh [--reset] [repo-path]
#   --reset: reset TOTAL antes de instalar (borra password web + flag one-shot
#            del .key + reemplaza el vault con respaldo). Default: no destructivo.
set -euo pipefail

REPO_DEFAULT="${KEYGATE_REPO:-$HOME/Projects/github/hermes-keygate}"
REPO="$REPO_DEFAULT"; RESET=0
NOWEB=0
for a in "$@"; do
  case "$a" in
    --reset) RESET=1 ;;
    --no-web-auth) NOWEB=1 ;;
    *) REPO="$a" ;;
  esac
done
DEST="$HOME/.hermes/plugins/keygate"
DB="$HOME/Documentos/hermes.kdbx"
KF="$HOME/.keepass-agent.key"
PORT="${KEYGATE_PORT:-8472}"

say() { printf '  %s\n' "$*"; }
run() { timeout 25 hermes "$@" >/dev/null 2>&1 && say "ok: hermes $*" || say "(!) hermes $* — check output / cfg"; }

# 1. Repo: clone if missing, pull if present (ff-only).
if [ ! -d "$REPO/.git" ]; then
  mkdir -p "$(dirname "$REPO")"
  git clone https://github.com/Elnegraso23/hermes-keygate.git "$REPO"
else
  git -C "$REPO" pull --ff-only >/dev/null 2>&1 && say "repo actualizado: $REPO" || say "repo sin cambios (o conflicto): $REPO"
fi

# 2. Plugin files + skills (BOTH — skills are instructions the agent reads).
# 1.5 Preflight: con el repo ya presente, verificar que ESTA máquina puede
# (keepassxc con db-create, HOME escribible, dir del vault). Fallar aqui es
# barato y claro; a mitad del install, caro.
bash "$REPO/scripts/keygate-preflight.sh" || {
  echo "preflight falló — corregilo antes de instalar (no se toco nada)" >&2; exit 2; }

mkdir -p "$DEST"
# Todos los módulos del plugin, no sólo el par histórico: keygate_web.py y
# keygate_vault.py son nuevos (página de alias y store propio). Copiar sólo
# __init__/lib dejaba `keygate_link` roto con ImportError en una instalación
# limpia.
for f in "$REPO"/*.py; do cp "$f" "$DEST/"; done
cp "$REPO/plugin.yaml" "$DEST/plugin.yaml"
rm -rf "$DEST/sync"
cp -r "$REPO/sync" "$DEST/sync"
find "$DEST/sync" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf "$DEST/skills"
cp -r "$REPO/skills" "$DEST/skills"
find "$DEST/skills" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
run plugins enable keygate

# 3. Operative vault (keyfile-only, NO master) via the repo's own script.
if [ "$RESET" = 1 ]; then
  echo "-- RESET total pedido: borro password web + flag one-shot + reemplazo vault"
  rm -f "$HOME/.hermes/keygate-sync-pass" && echo "   password web borrada (recreala en primera visita)"
  rm -f "$HOME/Documentos/.keygate-keyfile-served" && echo "   flag one-shot borrado (el .key se puede bajar una vez más)"
  bash "$REPO/scripts/keygate-setup" --force
else
  bash "$REPO/scripts/keygate-setup"
fi

# 4. Config via CLI (NEVER by hand — the YAML is agent-owned).
run config set approvals.mode manual
run config set approvals.timeout 60
run config set approvals.single_query_mode deny
run config set secrets.keepass.enabled true
run config set secrets.keepass.db_path "$DB"
run config set secrets.keepass.keyfile "$KF"
run config set secrets.keepass.timeout_seconds 30
run config set browser.backend off
run config set browser.use_real_profile false

# Detiene un sync previo SIN pkill (el guard de Hermes bloquea pkill desde el
# gateway, y un pkill -f python3 podría llevarse el gateway mismo: ambos corren
# sobre python3). Orden: unit systemd si existe -> PID file del propio server.
stop_sync() {
  if command -v systemctl >/dev/null 2>&1 \
     && [ -f "$HOME/.config/systemd/user/keygate-sync.service" ]; then
    systemctl --user stop keygate-sync.service 2>/dev/null || true
  fi
  PIDF="$HOME/.hermes/keygate-sync.pid"
  if [ -f "$PIDF" ]; then
    PID="$(cat "$PIDF" 2>/dev/null | tr -dc '0-9')"
    if [ -n "$PID" ] && [ -r "/proc/$PID/cmdline" ] \
       && tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null | grep -q "keygate_sync"; then
      kill "$PID" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$PIDF"
  fi
}

# 5. Start keygate-sync (idempotent: stop any old instance on this port).
# Bind: KEYGATE_BIND explícito manda; si no, auto-detecta la IP de Tailscale
# (así el vault se maneja desde otro equipo sin configurar nada); si no hay
# Tailscale, 127.0.0.1. NUNCA 0.0.0.0 (el server lo rehúsa igual).
stop_sync
if [ -n "${KEYGATE_BIND:-}" ]; then
  BIND="$KEYGATE_BIND"
elif command -v tailscale >/dev/null 2>&1; then
  TS_IP="$(timeout 5 tailscale ip -4 2>/dev/null | head -n1 || true)"
  if [ -n "$TS_IP" ]; then BIND="$TS_IP"; say "Tailscale detectado: $TS_IP"; else BIND="127.0.0.1"; fi
else
  BIND="127.0.0.1"
fi
# systemd user si existe (duro: sobrevive al cierre del chat); si no, proceso
# en background como antes. El proceso suelto se moría al terminar el turno:
# el curl del install pasaba y minutos después no había nadie escuchando.
PY_BIN="$(command -v python3)"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/keygate-sync.service"
if command -v systemctl >/dev/null 2>&1 && [ -n "$PY_BIN" ]; then
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT" <<UNITEOF
[Unit]
Description=keygate-sync (vault web de hermes-keygate)
After=default.target

[Service]
Type=simple
Environment=KEYGATE_DB=$DB
Environment=KEYGATE_KEYFILE=$KF
Environment=KEYGATE_BIND=$BIND
Environment=KEYGATE_PORT=$PORT
Environment=KEYGATE_ALLOW_NOAUTH=$NOWEB
ExecStart=$PY_BIN $DEST/sync/keygate_sync.py
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
UNITEOF
  # Bajar cualquier proceso suelto previo: dos servers en el puerto = conflicto.
  stop_sync
  sleep 1
  systemctl --user daemon-reload 2>/dev/null || true
  systemctl --user enable --now keygate-sync.service 2>/dev/null || true
  loginctl enable-linger 2>/dev/null || true
fi
# Espera activa: `enable --now` vuelve antes de que el socket escuche. Sin
# esto el curl fallaba, el script arrancaba ADEMÁS un proceso suelto y los dos
# se peleaban el puerto (systemd en bucle de "Address already in use").
SYNC_OK=0
for _ in $(seq 1 25); do
  sleep 0.4
  if curl -s -o /dev/null -m 3 "http://$BIND:$PORT/" 2>/dev/null; then SYNC_OK=1; break; fi
done
if [ "$SYNC_OK" = 1 ]; then
  if [ -f "$UNIT" ] && systemctl --user is-active --quiet keygate-sync.service 2>/dev/null; then
    say "keygate-sync vivo (systemd) en http://$BIND:$PORT — sobrevive al cierre del chat"
  else
    say "keygate-sync vivo en http://$BIND:$PORT"
  fi
elif [ -f "$UNIT" ]; then
  # Hay unidad pero no responde: NO arrancamos un segundo server (eso causaba
  # el conflicto de puerto). Se reporta para que se vea el log.
  say "(!) keygate-sync con systemd no respondió — journalctl --user -u keygate-sync -n 50"
else
  # Sin systemd disponible: proceso en background como antes.
  KEYGATE_DB="$DB" KEYGATE_KEYFILE="$KF" \
  KEYGATE_BIND="$BIND" KEYGATE_PORT="$PORT" \
  setsid python3 "$DEST/sync/keygate_sync.py" \
    >/tmp/keygate-sync.log 2>&1 < /dev/null &
  sleep 2
  if curl -s -o /dev/null -m 5 "http://$BIND:$PORT/"; then
    say "keygate-sync vivo (proceso suelto) en http://$BIND:$PORT (log: /tmp/keygate-sync.log)"
  else
    say "(!) keygate-sync NO respondió — mira /tmp/keygate-sync.log"
  fi
fi

# 5b. Contraseña de la web: la DEFINE el usuario, no se inventa.
# Con terminal se pide aquí (dos veces, sin eco, nunca a un archivo). Sin
# terminal NO se crea: la primera visita a la web la pide, con el código de un
# solo uso que imprime el servidor.
if [ "$NOWEB" = 1 ]; then
  printf '%s\n' "$(date +%s)" > "$HOME/.hermes/keygate-sync-noauth"
  chmod 600 "$HOME/.hermes/keygate-sync-noauth"
  say "web SIN contraseña (entra directo) — modo pedido con --no-web-auth"
elif [ ! -f "$HOME/.hermes/keygate-sync-pass" ]; then
  if [ -t 0 ]; then
    DEST_SYNC="$DEST/sync" HH="$HOME/.hermes" python3 - <<'PYEOF'
import getpass, os, pathlib, sys
sys.path.insert(0, os.environ["DEST_SYNC"])
import keygate_sync as ks
pw = getpass.getpass("Contraseña para entrar a la web keygate (min 12): ")
if pw != getpass.getpass("Repítela: "):
    print("  (!) no coinciden: la web te la pedirá en la primera visita")
    raise SystemExit(0)
if len(pw) < 12:
    print("  (!) menos de 12 caracteres: la web te la pedirá en la primera visita")
    raise SystemExit(0)
ok = ks.set_password_once(pathlib.Path(os.environ["HH"]), pw)
print("  contraseña de la web: " + ("definida" if ok else "ya existía"))
PYEOF
  else
    say "sin terminal: la contraseña de la web se define en la primera visita"
    say "el código de un solo uso está en $HOME/.hermes/keygate-sync-bootstrap"
  fi
fi

[ "$NOWEB" = 1 ] && systemctl --user restart keygate-sync 2>/dev/null && sleep 2

# 6. Página de alias (keygate_link). Opt-out con KEYGATE_ALIAS_PAGE=0.
# Bind: tailnet si existe, si no 127.0.0.1. Nunca 0.0.0.0 por defecto.
ALIAS_PORT="${KEYGATE_ALIAS_PORT:-8790}"
if [ "${KEYGATE_ALIAS_PAGE:-1}" != "0" ]; then
  PW_FILE="$HOME/.hermes/keygate-alias-page-pass"
  if [ "$NOWEB" = 1 ]; then
    say "página de alias SIN contraseña (misma decisión que la web)"
  elif [ ! -f "$HOME/.hermes/keygate-web.meta.json" ]; then
    if [ -t 0 ]; then
      python3 "$DEST/keygate_web.py" init || say "(!) sin contrasena de pagina"
    else
      TMPPW="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
      if printf '%s\n' "$TMPPW" | HERMES_HOME="$HOME/.hermes" python3 "$DEST/keygate_web.py" init --from-stdin >/dev/null; then
        printf '%s\n' "$TMPPW" > "$PW_FILE"
        chmod 600 "$PW_FILE"
        say "contrasena de la pagina en $PW_FILE (0600) - cambiala con: python3 $DEST/keygate_web.py set-password"
      else
        say "(!) no se pudo crear la contrasena de la pagina"
      fi
      unset TMPPW
    fi
  fi
  UNIT2="$UNIT_DIR/keygate-alias-page.service"
  if command -v systemctl >/dev/null 2>&1; then
    cat > "$UNIT2" <<UNIT2EOF
[Unit]
Description=keygate alias page (keygate_link)
After=network-online.target

[Service]
Type=simple
Environment=HERMES_HOME=$HOME/.hermes
Environment=KEYGATE_ALIAS_NOAUTH=$NOWEB
ExecStart=$PY_BIN $DEST/keygate_web.py serve --bind ${BIND} --port ${ALIAS_PORT}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
UNIT2EOF
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable --now keygate-alias-page.service 2>/dev/null || true
    # Reintento: `enable --now` vuelve antes de que el socket escuche; un curl
    # inmediato daba un falso "no respondió" en la instalación desde cero.
    ALIAS_OK=0
    for _ in $(seq 1 25); do
      sleep 0.4
      if curl -fsS -m 3 "http://${BIND}:${ALIAS_PORT}/healthz" >/dev/null 2>&1; then
        ALIAS_OK=1; break
      fi
    done
    if [ "$ALIAS_OK" = 1 ]; then
      if [ "$NOWEB" = 1 ]; then
        say "página de alias viva en http://${BIND}:${ALIAS_PORT} (sin contraseña)"
      else
        say "página de alias viva en http://${BIND}:${ALIAS_PORT} (pide contraseña)"
      fi
    else
      say "(!) página de alias no respondió — journalctl --user -u keygate-alias-page"
    fi
  fi
fi

cat <<EOF

== LISTO ==
Plugin skills: $DEST/skills/*/SKILL.md
Vault:        $DB · $KF (0600)
Sync web:     http://$BIND:$PORT  (127.0.0.1 = solo esta máquina; pasá KEYGATE_BIND=<IP Tailscale> para manejarlo desde otro equipo)

Lo que haces ahora:
1) Abre la URL del sync y entra con la contraseña ya generada
   (archivo indicado arriba). No hay código de arranque que copiar.
2) Tarjeta "Primera vez": descarga el .kdbx y el .key (una sola vez),
   edita en KeePassXC con ese .key, sube el .kdbx editado.
3) Si querés el login de prueba: https://the-internet.herokuapp.com/login
   (usuario tomsmith · password SuperSecretPassword! — públicos).

Para cambiar el bind después (sin reinstalar todo):
editá $HOME/.config/systemd/user/keygate-sync.service (KEYGATE_BIND),
después: systemctl --user daemon-reload && systemctl --user restart keygate-sync

Útil: systemctl --user status keygate-sync · journalctl --user -u keygate-sync -n 50

El plugin rige ya en esta sesión si hermes cargó el plugin activo; si no,
reinicia el chat y verifica con keygate_status.
Trackeo: https://github.com/Elnegraso23/hermes-keygate/issues
EOF
