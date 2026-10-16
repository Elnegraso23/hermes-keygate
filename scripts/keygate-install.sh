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
for a in "$@"; do
  case "$a" in
    --reset) RESET=1 ;;
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
cp "$REPO/__init__.py" "$REPO/keygate_lib.py" "$REPO/plugin.yaml" "$DEST/"
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
ExecStart=$PY_BIN $REPO/sync/keygate_sync.py
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
if curl -s -o /dev/null -m 5 "http://$BIND:$PORT/" 2>/dev/null; then
  if [ -f "$UNIT" ]; then
    say "keygate-sync vivo (systemd) en http://$BIND:$PORT — sobrevive al cierre del chat"
  else
    say "keygate-sync vivo (proceso suelto) en http://$BIND:$PORT — morirá con esta sesión"
  fi
else
  # Sin systemd (o falló): proceso en background como antes.
  KEYGATE_DB="$DB" KEYGATE_KEYFILE="$KF" \
  KEYGATE_BIND="$BIND" KEYGATE_PORT="$PORT" \
  setsid python3 "$REPO/sync/keygate_sync.py" \
    >/tmp/keygate-sync.log 2>&1 < /dev/null &
  sleep 2
  if curl -s -o /dev/null -m 5 "http://$BIND:$PORT/"; then
    say "keygate-sync vivo (proceso suelto) en http://$BIND:$PORT (log: /tmp/keygate-sync.log)"
  else
    say "(!) keygate-sync NO respondió — mira /tmp/keygate-sync.log y journalctl --user -u keygate-sync"
  fi
fi

cat <<EOF

== LISTO ==
Plugin skills: \$DEST/skills/*/SKILL.md
Vault:        \$DB (keyfile-only) · \$KF (0600)
Sync web:     http://$BIND:$PORT  (127.0.0.1 = solo esta máquina; pasá KEYGATE_BIND=<IP Tailscale> para manejarlo desde otro equipo)

Lo que haces ahora:
1) Abre la URL del sync en tu navegador. La primera vez te obliga a crear una
   contraseña (mínimo 12). Queda solo en esa pestaña.
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
