# CHANGELOG — hermes-keygate (alfa, serie 0.x)

Mientras la versión sea `0.x`: cada release puede romper compatibilidad
(nombres de tools, formato de config, flujo de auth). Actualiza con
`scripts/keygate-update` y reinstala skills siempre (el updater ya lo hace).

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
