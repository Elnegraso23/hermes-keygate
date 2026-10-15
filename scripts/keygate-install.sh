#!/bin/bash
# keygate-install: one-shot setup. Idempotent (safe to re-run).
# Clones if missing, installs plugin + skills, enables it, creates the
# operative vault, applies config (no quotes), and STARTS keygate-sync.
# Prints the exact URLs/commands the user needs afterwards.
#
# Usage: bash <repo>/scripts/keygate-install.sh
set -euo pipefail

REPO_DEFAULT="${KEYGATE_REPO:-$HOME/Projects/github/hermes-keygate}"
REPO="${1:-$REPO_DEFAULT}"
DEST="$HOME/.hermes/plugins/keygate"
DB="$HOME/Documentos/hermes.kdbx"
KF="$HOME/.keepass-agent.key"
PORT="${KEYGATE_PORT:-8472}"

say() { printf '  %s\n' "$*"; }
run() { timeout 25 hermes "$@" >/dev/null 2>&1 && say "ok: hermes $*" || say "(!) hermes $* — check output / cfg"; }

echo "== keygate-install =="
# 1. Repo: clone if missing, pull if present (ff-only).
if [ ! -d "$REPO/.git" ]; then
  mkdir -p "$(dirname "$REPO")"
  git clone https://github.com/Elnegraso23/hermes-keygate.git "$REPO"
else
  git -C "$REPO" pull --ff-only >/dev/null 2>&1 && say "repo actualizado: $REPO" || say "repo sin cambios (o conflicto): $REPO"
fi

# 2. Plugin files + skills (BOTH — skills are instructions the agent reads).
mkdir -p "$DEST"
cp "$REPO/__init__.py" "$REPO/keygate_lib.py" "$REPO/plugin.yaml" "$DEST/"
rm -rf "$DEST/skills"
cp -r "$REPO/skills" "$DEST/skills"
find "$DEST/skills" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
run plugins enable keygate

# 3. Operative vault (keyfile-only, NO master) via the repo's own script.
bash "$REPO/scripts/keygate-setup"

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

# 5. Start keygate-sync (idempotent: kill any old instance on this port).
if pgrep -f "keygate_sync.py" >/dev/null 2>&1; then
  pkill -f "keygate_sync.py" 2>/dev/null || true
  sleep 1
fi
KEYGATE_DB="$DB" KEYGATE_KEYFILE="$KF" KEYGATE_BIND=127.0.0.1 \
KEYGATE_PORT="$PORT" setsid python3 "$REPO/sync/keygate_sync.py" \
  >/tmp/keygate-sync.log 2>&1 < /dev/null &
sleep 2
if curl -s -o /dev/null -m 5 "http://127.0.0.1:$PORT/"; then
  say "keygate-sync vivo en http://127.0.0.1:$PORT (log: /tmp/keygate-sync.log)"
else
  say "(!) keygate-sync NO respondió — mira /tmp/keygate-sync.log"
fi

cat <<EOF

== LISTO ==
Plugin skills: $DEST/skills/*/SKILL.md
Vault:        $DB (keyfile-only) · $KF (0600)

Lo que haces ahora:
1) Abre http://127.0.0.1:$PORT — la primera vez te obliga a crear una
   contraseña (mínimo 12). Queda solo en esa pestaña.
2) Tarjeta "Primera vez": descarga el .kdbx y el .key (una sola vez),
   edita en KeePassXC con ese .key, sube el .kdbx editado.
3) Si quieres el login de prueba: https://the-internet.herokuapp.com/login
   (usuario tomsmith · password SuperSecretPassword! — públicos).

El plugin rige ya en esta sesión si hermes cargó el plugin activo; si no,
reinicia el chat y verifica con keygate_status.
Trackeo: https://github.com/Elnegraso23/hermes-keygate/issues
EOF
