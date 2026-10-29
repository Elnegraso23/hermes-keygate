# CHANGELOG — hermes-keygate (alfa, serie 0.x)

Mientras la versión sea `0.x`: cada release puede romper compatibilidad
(nombres de tools, formato de config, flujo de auth). Actualiza con
`scripts/keygate-update` y reinstala skills siempre (el updater ya lo hace).

## 0.6.6 — 2026-10-29

- **Licencia**: MIT → **PolyForm Noncommercial 1.0.0** (uso libre no comercial;
  uso comercial requiere licencia aparte). Ver `LICENSE` y la sección *Licencia*.
- **Cadena de custodia**: commits y tags firmados con SSH (ed25519), llave de
  firma registrada en GitHub; release con checksum SHA-256 del código fuente.
- README: se corrige la afirmación "100% open source" → *source-available*, y el
  badge de versión queda sincronizado con `plugin.yaml`.

## 0.6.5 — 2026-10-28
- **H13 — normalize_origin endurecido**: canonicalización IDNA por etiqueta
  (`https://аpple.com` → `https://xn--pple-43d.com`), rechazo de caracteres de
  control/espacios, etiquetas vacías y longitudes inválidas; IP literales
  canonicalizadas; `http://` y `https://` nunca equivalentes.
- **H14 — centinela durable**: `fsync()` del archivo y del directorio padre
  antes de enviar el `.key`; el flag one-shot sobrevive a cortes y reinicios.
- **H15 — errores opacos + límite alias-auto**: mensajes constantes (sin
  interpolar excepciones ni stdout/stderr) y tope de 5 rellenos/minuto por
  alias con `error_type: alias_auto_rate_limited`, auditado como `alias-auto`.
- **H16 — refactor de `_native_keygate_fill`**: extraídos `_fill_resolve_entry`
  y `_fill_bind_page`; se conserva el `try/finally` con `zeroize` en toda ruta.
- Tests: `test_origin_idn.py` (7), `test_autofill_rate.py` (2), selftest H14
  con 8 descargas concurrentes → 40 PASS.

## 0.6.4 — 2026-10-28
- **H11 — TOCTOU e iframes cerrados en el fill**: el JS de relleno se envuelve en
  una guardia atómica que corre en la MISMA evaluación que escribe en el DOM:
  `window.top !== window.self` aborta con `frame_not_top_level`, y un
  `location.origin` distinto del aprobado aborta con `origin_changed_toctou`.
  Se añade además una re-verificación de origen inmediatamente antes del eval.
- **H12 — anti DNS rebinding**: allowlist estricta de `Host` construida al
  arrancar desde la IP de bind (más `127.0.0.1`/`localhost`/`[::1]` cuando
  aplica). Host ausente o ajeno → 403 sin reflejar el valor.
- Tests: `tests/test_fill_js.py` (3 casos) y 3 casos nuevos en el selftest → 38.

## 0.6.3 — 2026-10-28
- **H10 — resolución endurecida de `keepassxc-cli`**: orden determinista
  (`KEYGATE_KXC_BIN` → rutas canónicas → `PATH`), *fail-closed* si el binario
  configurado es inválido, y validación de propiedad/permisos (archivo regular,
  ejecutable, no escribible por group/others, dueño root o el uid actual,
  directorio padre no escribible; `/tmp` solo con sticky bit y siendo propio).
- **`doctor_check()` + `scripts/keygate-doctor`** (`python3 keygate_lib.py --doctor`):
  ruta, origen, permisos, versión (mínimo 2.7.0) e `install_hint` por distro.
  Expuesto también en la tool `keygate_doctor`.
- Selftest: 3 casos nuevos (env válido, rechazo de binario 0777, doctor) → 35.
- Docs: sección de dependencia en README es/en explicando por qué el CLI sigue
  siendo externo (frontera criptográfica) y cómo usar Flatpak.

## 0.6.2 — 2026-10-28
- Calidad: `error_type: "db_locked"` uniforme, `otpauth://` parseado con
  `urlparse`, errores tipados en `_run_kxc` (124 timeout / 127 binario ausente),
  `db_mtime` visible en la web, `clearTimeout` al copiar alias y vista de
  auditoría persistida en `localStorage`.
- CI: job `security` (bandit `-ll`, semgrep `p/python`+`p/secrets`, gitleaks).
- README: badges y aviso de versión alineados a 0.6.2.

## 0.6.1 — 2026-10-28
- Seguridad H1–H9: igualdad estricta de orígenes (sin subcadenas ni userinfo),
  CSRF y cabeceras CSP en keygate-sync, relleno en subgrupos, lock atómico del
  keyfile, rate limit separado para fallos de auth y guard estricto de autofill.
- Selftest ampliado a 32 casos.

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
- Docs: README bilingüe (`README.md` español + `README.en.md` inglés, con selector de idioma), sección “Sin aprobación por cuenta” y troubleshooting del
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
