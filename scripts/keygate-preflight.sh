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
if command -v keepassxc-cli >/dev/null 2>&1; then
  if keepassxc-cli 2>&1 | grep -q "db-create"; then
    say "ok: keepassxc-cli trae db-create"
  else
    say "FALTA: keepassxc-cli sin db-create (necesitas >= 2.7; $(keepassxc-cli --version 2>&1 | head -n1))"
    fail=1
  fi
fi

if [ -w "$HOME" ]; then say "ok: HOME escribible ($HOME)"; else say "FALTA: HOME no escribible ($HOME)"; fail=1; fi

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
