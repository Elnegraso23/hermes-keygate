#!/bin/bash
# keygate-preflight: ¿puede esta máquina correr keygate? Chequea UNA vez, antes
# de instalar. Fallar aquí es barato; fallar a mitad del install, caro.
#
# Verifica: git, python3, keepassxc-cli (CON db-create, 2.7+), curl, HOME
# escribible, y crea el directorio del vault (la falta de ~/Documentos rompía
# db-create en servidores con home fresco).
#
# Uso: scripts/keygate-preflight.sh   (exit 0 = todo ok, 1 = falta algo)
set -uo pipefail
DB="${KEYGATE_DB:-$HOME/Documentos/hermes.kdbx}"
fail=0
say() { printf '  %s\n' "$*"; }

echo "== keygate-preflight =="
for bin in git python3 keepassxc-cli curl; do
  if command -v "$bin" >/dev/null 2>&1; then say "ok: $bin"; else say "FALTA: $bin"; fail=1; fi
done

# db-create apareció en keepassxc-cli 2.7: sin él, keygate-setup no crea el vault.
# NO se comprueba grepeando el help: en varias versiones (p.ej. las de Ubuntu
# 24.04 / keepassxc 2.7.9) `keepassxc-cli` sin argumentos imprime solo una
# lista recortada de comandos y db-create NO aparece, aunque el subcomando
# exista y funcione. Se comprueba EJECUTANDO el subcomando (dry-run sin
# argumentos): si responde con su usage en vez de "Unknown command", existe.
if command -v keepassxc-cli >/dev/null 2>&1; then
  kx_out=$(keepassxc-cli db-create --help 2>&1)
  if echo "$kx_out" | grep -qE "db-create|--set-key-file"; then
    say "ok: keepassxc-cli trae db-create"
  else
    say "FALTA: keepassxc-cli sin db-create (necesitas >= 2.7; $(keepassxc-cli --version 2>&1 | head -n1))"
    fail=1
  fi
fi

# HOME escribible. OJO: [ -w ] sobre un path que AUN NO EXISTE devuelve false
# (bash no puede saber si un dir inexistente sería escribible), así que un
# home recién creado por el instalador daba "HOME no escribible" y el
# preflight FALLABA en hosts perfectamente válidos. Se comprueba tentando
# escribir de verdad, y se crea el home si falta.
if mkdir -p "$HOME" 2>/dev/null && [ -d "$HOME" ] && touch "$HOME/.kg-preflight-write-test" 2>/dev/null; then
  rm -f "$HOME/.kg-preflight-write-test"
  say "ok: HOME escribible ($HOME)"
else
  say "FALTA: HOME no escribible ($HOME)"
  fail=1
fi

if mkdir -p "$(dirname "$DB")" 2>/dev/null; then
  say "ok: dir del vault $([ -d "$(dirname "$DB")" ] && echo existe || echo creado)"
else
  say "FALTA: no puedo crear $(dirname "$DB")"
  fail=1
fi

if [ "$fail" = 0 ]; then
  echo "== preflight OK: esta máquina puede instalar keygate =="
else
  echo "== preflight FALLÓ: corregí lo de arriba y reintentá ==" >&2
fi
exit "$fail"
