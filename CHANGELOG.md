# CHANGELOG — hermes-keygate (alfa, serie 0.x)

Mientras la versión sea `0.x`: cada release puede romper compatibilidad
(nombres de tools, formato de config, flujo de auth). Actualiza con
`scripts/keygate-update` y reinstala skills siempre (el updater ya lo hace).

## 0.6.0 — 2026-10-26
- **Auto-relleno por alias (opt-in desde la web)**: política por cuenta en
  `~/.hermes/keygate-autofill.json` (0600, escritura atómica). Si el alias tiene
  política activa y el origin coincide exacto, `keygate_request_fill` rellena sin
  pedir aprobación; se audita `approval: "auto-policy"` + `policy: "alias-auto"`.
- Web `keygate-sync`: `GET /api/autofill` (lista con `suggested_origin` tomado de
  la URL del vault) y `POST /api/autofill {alias, origin, enabled}` (Bearer), más
  la casilla **“Sin aprobación”** por alias en el dashboard. El POST rechaza con
  `400` un origin cuyo host no coincida con la URL de la entrada y valida contra
  un vault bloqueado.
- Guardas: comparación normalizada `scheme://host:puerto` (otro esquema, puerto o
  subdominio vuelve a pedir aprobación); cron/one-shot siguen rechazados aunque
  la política esté activa.
- Tests: `tests/test_autofill_policy.py` (aislado, sin Hermes) + paso nuevo en CI.
- Docs: sección “Sin aprobación por cuenta” en el README y troubleshooting del
  `ExecStart` que puede capturar un venv efímero al instalar desde una sesión de
  agente (usar `/usr/bin/python3`).

## 0.5.0 — 2026-10-16
- Auditoría externa integrada (3 fixes verificados + 8 propuestas triageadas):
  `rotate_backups` borraba 1 de más (off-by-one real); staging del upload en el
  dir del DB + fallback `shutil.move` (EXDEV cross-device real); login card HTML
  en vez de `prompt()` (cancelar dejaba la app visible sin auth).
- `POST /api/reset-password` (exige la actual, min 12, auditado) y
  `GET /api/health` público mínimo. Rate limiter con lock. Audit acotado a 64KB.
- Server escribe PID file: el instalador para sin `pkill` (el guard de Hermes lo
  bloquea). `keygate-setup --reset-key`, `keygate-install.sh --reset` (reset total
  explícito: pass + flag + vault con respaldo).
- Selftest 22 casos incl. upload round-trip en vivo, reset-password, health,
  login card y rotación exacta. Diferido con motivo: sesiones HttpOnly, ETag,
  multi-vault, rekey, autosubmit, TOTP-skew, CI, uninstall, audit-rotation
  (append-only por forense).

## 0.4.0 — 2026-10-15
- `keygate_version` avisa de updates contra GitHub aunque no tengas clon
  (GET público a `plugin.yaml` de main, cache 24h, offline = `unknown`).
- Rutas de clon autodetectadas (`~/hermes-keygate`,
  `~/Projects/github/hermes-keygate`); el hardcode `~/hermes-keygate` murió.
- Docs: setup CDP persistente por systemd contra el bug de socket de Hermes;
  README lidera con el instalador de una pasada.

## 0.3.0 — 2026-10-08
- Web `keygate-sync` con auth por **contraseña creada en primera visita**
  (PBKDF2-HMAC-SHA256, sin default, sin token en disco). Adiós `KEYGATE_SYNC_TOKEN`.
- `GET /api/download` + tarjeta "Primera vez": round-trip bajar → editar →
  subir sin terminal. Botón de descarga con errores visibles (antes fallaba mudo).
- Keyfile one-shot solo se consume tras envío exitoso (reintento si se corta).
- Skills `keygate-default` + `keygate-install` por fin se instalan, registran
  (ruta al `SKILL.md`, no al directorio — `Errno 21` corregido) y mandan a la
  página localhost como camino principal, con mensaje de cierre literal.
- Instalación por `hermes config set` (sin comillas) + `timeout 20` en el CLI.
- `PRIMERA-VEZ.md`: guía del usuario frase por frase.

## 0.2.0 — 2026-09
- `keygate_import`: el vault de KeePass como default (una aprobación → copia
  al vault nativo cifrado → `browser_vault_fill` normal).
- `keygate_doctor`: diagnóstico remoto sin secretos. Error `unattended`
  distinto de `denied` (+ `channel` en los denies).
- Web `keygate-sync` inicial: upload validado + keyfile onboarding una-sola-vez + audit.
- Sesiones efímeras `keygate_session_ensure/invalidate`, updater con garantía
  anti-`.kdbx`, aviso de updates (`keygate_version` + changelog).

## 0.1.0 — 2026-09
- Primer plugin funcional: `SecretSource keepass` (`kpx://`), `keygate_search`,
  `keygate_request_fill` (aprobación → fill ciego por CDP atado al origen),
  `keygate_status`, redacción estricta, audit redactado, vault operativo
  keyfile-only de dos vaults. `keygate_alias_add` bloqueado por política.
