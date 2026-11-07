#!/usr/bin/env bash
# keygate-uninstall — deshace exactamente lo que hace keygate-install.
#
#   keygate-uninstall                 quita plugin, servicios y estado; CONSERVA
#                                     la base (.kdbx), la keyfile y sus rotaciones
#   keygate-uninstall --purge         además borra la base, la keyfile, TODAS las
#                                     rotaciones *.bak, el escrow y el perfil de
#                                     KeePassXC del agente
#   keygate-uninstall --dry-run       sólo lista lo que haría, no toca nada
#   keygate-uninstall --yes           sin confirmación (para scripts)
#
# Regla: nada se borra sin decir antes qué es. Con --purge se enumeran los
# archivos uno por uno; si alguno no existe, se informa y se sigue.
set -uo pipefail
PROG="$(basename "$0")"
HOME_DIR="${HOME:?}"
DEST="$HOME_DIR/.hermes/plugins/keygate"
HSTATE="$HOME_DIR/.hermes"
DB="${KEYGATE_DB:-$HOME_DIR/Documentos/hermes.kdbx}"
KF="${KEYGATE_KEYFILE:-$HOME_DIR/.keepass-agent.key}"
PURGE=0; YES=0; DRY=0
for a in "$@"; do
  case "$a" in
    --purge) PURGE=1 ;;
    --yes|-y) YES=1 ;;
    --dry-run|-n) DRY=1 ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "$PROG: opción desconocida: $a" >&2; exit 2 ;;
  esac
done

say() { printf '  %s\n' "$*"; }
run_or_echo() {  # $@ = comando
  if [ "$DRY" = 1 ]; then echo "  [dry] $*"; else "$@" >/dev/null 2>&1 || true; fi
}

echo "== keygate-uninstall =="

# ---------- inventario ----------
echo "-- servicios"
UNITS=()
for u in keygate-sync keygate-alias-page keygate-web; do
  [ -f "$HOME_DIR/.config/systemd/user/$u.service" ] && UNITS+=("$u")
done
[ ${#UNITS[@]} -eq 0 ] && say "(ninguno instalado)" || for u in "${UNITS[@]}"; do say "$u.service"; done

echo "-- plugin"
[ -d "$DEST" ] && say "$DEST ($(ls "$DEST"/*.py 2>/dev/null | wc -l) módulos)" || say "(no instalado)"

echo "-- estado en ~/.hermes"
STATE_FILES=(keygate-audit.jsonl keygate-autofill.json keygate-index.json keygate-sync-pass
             keygate-sync-bootstrap keygate-sync-noauth keygate-sync.pid keygate-version-check.json
             keygate-web.meta.json keygate-vault.enc keygate-vault.key keygate-vault.meta.json
             keygate-web-pass keygate-alias-page-pass)
FOUND_STATE=()
for f in "${STATE_FILES[@]}"; do [ -e "$HSTATE/$f" ] && FOUND_STATE+=("$f"); done
[ ${#FOUND_STATE[@]} -eq 0 ] && say "(nada)" || for f in "${FOUND_STATE[@]}"; do say "$f"; done

echo "-- datos (sólo con --purge)"
DATA_FILES=()
[ -e "$DB" ] && DATA_FILES+=("$DB")
[ -e "$KF" ] && DATA_FILES+=("$KF")
[ -e "$HOME_DIR/Documentos/.keygate-keyfile-served" ] && DATA_FILES+=("$HOME_DIR/Documentos/.keygate-keyfile-served")
while IFS= read -r f; do DATA_FILES+=("$f"); done < <(ls -1 "$HOME_DIR/Documentos"/hermes.kdbx.* 2>/dev/null)
if [ "$PURGE" = 1 ]; then
  [ ${#DATA_FILES[@]} -eq 0 ] && say "(nada)" || for f in "${DATA_FILES[@]}"; do say "$f"; done
  [ -d "$HOME_DIR/.keygate-vault" ] && say "$HOME_DIR/.keygate-vault/ (escrow cifrado)"
  [ -f "$HOME_DIR/.config/keepassxc-agent.ini" ] && say "$HOME_DIR/.config/keepassxc-agent.ini (perfil del agente)"
else
  say "(se conservan; usa --purge para borrarlas)"
fi

if [ "$DRY" = 1 ]; then echo "-- dry-run: no se toca nada"; fi
if [ "$DRY" != 1 ] && [ "$YES" != 1 ]; then
  printf '¿Continuar? [s/N] '; read -r r
  case "${r:-n}" in s|S|si|SI|y|Y) ;; *) echo "cancelado"; exit 1 ;; esac
fi

# ---------- ejecución ----------
echo "-- deteniendo servicios"
for u in "${UNITS[@]}"; do
  run_or_echo systemctl --user stop "$u.service"
  run_or_echo systemctl --user disable "$u.service"
  if [ "$DRY" = 1 ]; then echo "  [dry] rm $HOME_DIR/.config/systemd/user/$u.service"
  else rm -f "$HOME_DIR/.config/systemd/user/$u.service"; fi
done
[ "$DRY" = 1 ] || systemctl --user daemon-reload >/dev/null 2>&1 || true

echo "-- desactivando plugin"
run_or_echo hermes plugins disable keygate

echo "-- borrando plugin"
if [ -d "$DEST" ]; then
  if [ "$DRY" = 1 ]; then echo "  [dry] rm -rf $DEST"; else rm -rf "$DEST"; fi
fi

echo "-- borrando estado"
for f in "${FOUND_STATE[@]}"; do
  if [ "$DRY" = 1 ]; then echo "  [dry] rm $HSTATE/$f"; else rm -f "$HSTATE/$f"; fi
done

echo "-- limpiando config de Hermes"
for k in secrets.keepass.enabled secrets.keepass.db_path secrets.keepass.keyfile secrets.keepass.timeout_seconds; do
  run_or_echo hermes config unset "$k"
done

if [ "$PURGE" = 1 ]; then
  echo "-- borrando datos (--purge)"
  for f in "${DATA_FILES[@]}"; do
    if [ "$DRY" = 1 ]; then echo "  [dry] rm $f"; else rm -f "$f"; fi
  done
  for d in "$HOME_DIR/.keygate-vault"; do
    [ -d "$d" ] || continue
    if [ "$DRY" = 1 ]; then echo "  [dry] rm -rf $d"; else rm -rf "$d"; fi
  done
  f="$HOME_DIR/.config/keepassxc-agent.ini"
  [ -f "$f" ] && { if [ "$DRY" = 1 ]; then echo "  [dry] rm $f"; else rm -f "$f"; fi; }
fi
rm -f /tmp/keygate-sync.log 2>/dev/null || true

if [ "$DRY" = 1 ]; then
  echo "== dry-run terminado: nada cambió =="
  exit 0
fi

echo "== LISTO =="
echo "Plugin, servicios y estado: fuera."
if [ "$PURGE" = 1 ]; then
  echo "Datos: borrados (base, keyfile y rotaciones)."
else
  echo "Datos: conservados en $DB y $KF (+ rotaciones)."
  echo "Para borrarlos también:  $PROG --purge"
fi
echo "Reinstalar: bash scripts/keygate-install.sh [--no-web-auth] [repo]"
