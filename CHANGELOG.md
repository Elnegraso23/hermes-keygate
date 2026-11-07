# CHANGELOG — hermes-keygate (alfa, serie 0.x)

Mientras la versión sea `0.x`: cada release puede romper compatibilidad
(nombres de tools, formato de config, flujo de auth). Actualiza con
`scripts/keygate-update` y reinstala skills siempre (el updater ya lo hace).

## 0.7.3 — 2026-11-07
- **`scripts/keygate-uninstall.sh`**: desinstalador completo, espejo del
  instalador. Inventaría antes de borrar y distingue estado de datos:
  por defecto quita plugin, servicios y estado y **conserva** base, keyfile y
  rotaciones; `--purge` borra también esos archivos, el escrow y el perfil del
  agente. `--dry-run` audita sin tocar nada.
  Motivo: "borra todo" dejaba las rotaciones `hermes.kdbx.*.bak` en `Documentos`
  porque no estaban en ninguna lista.

## 0.7.2 — 2026-11-07
- **`--no-web-auth`**: instalación completa sin contraseñas de web. Marca
  `keygate-sync-noauth` + `KEYGATE_ALLOW_NOAUTH=1` y levanta también la página
  de alias sin auth (`KEYGATE_ALIAS_NOAUTH=1`). Ambos servicios entran directos.
  Sin este flag el comportamiento no cambia: contraseña pedida al instalar o en
  la primera visita.
- El resumen ya no dice "pide contraseña" cuando la página va sin ella.

## 0.7.1 — 2026-11-07
- **La web puede correr sin contraseña** (opción explícita, no silenciosa).
  Botón "Entrar sin contraseña" en la primera visita, visible sólo cuando el
  bind es localhost o cuando el dueño lo fuerza con `KEYGATE_ALLOW_NOAUTH=1`.
  Queda un flag 0600 (`keygate-sync-noauth`) y, en cuanto se define una
  contraseña, el modo se desactiva solo. En red la contraseña sigue siendo la
  regla; el override asume el riesgo a sabiendas.
- La pista del código de un solo uso se oculta cuando el modo sin contraseña
  está disponible: ya no hay nada que reclamar.

## 0.7.0 — 2026-11-07
- **Contraseña maestra opcional en la base operativa** (`hermes.kdbx`). Hoy la
  DB abre sólo con la keyfile; en la instalación `scripts/keygate-setup` ahora
  pregunta: *solo keyfile* (default, sin prompt) o *keyfile + contraseña*. La
  contraseña viaja **sólo por stdin** (`KEYGATE_DB_PASSWORD`), nunca por argv ni
  por el chat; `keepassxc-cli` deja de recibir `--no-password` en ese modo
  (`kg.kxc_auth()`), así que una DB protegida no se abre por accidente.
- **keygate deja de escribir en el vault nativo de Hermes por defecto**
  (`vault_sync: false`). `keygate_import` sólo registra un puntero sin secretos
  (origen → alias) en `keygate-index.json` (0600). El espejo al vault de Hermes
  queda como opt-in explícito (`vault_sync: true` / `KEYGATE_VAULT_SYNC=1`).
- **`keygate_lookup(origin)`** (nueva tool): resuelve página → alias en una sola
  llamada y dice si hay auto-fill (o sea, si habrá prompt de aprobación). Match
  de origen exacto: distinto esquema, sufijo y prefijo fallan.
- **`keygate_link(alias)` + `scripts/keygate-alias-page`** (nuevo): página de
  alias con Basic auth (PBKDF2-SHA256; la contraseña de la página no se toca) y
  CSP sin `script-src`. Hermes manda el link en vez de pedir aprobación en cada
  login; activar auto-fill ahí la elimina. La página nunca muestra ni acepta
  contraseñas de sitios.
- **`scripts/keygate-store` + `keygate_vault.py`** (nuevo, opcional): base propia
  de keygate para `store_mode: mirror` — llave local (0600) o llave + contraseña
  con scrypt (N=32768). En modo passphrase no queda archivo de llave y el
  descifrado se cachea sólo en memoria (15 min). El default sigue siendo
  `store_mode: live`: cero copias, todo se resuelve desde `hermes.kdbx`.
- Tests nuevos: índice sin secretos, contraseña de la página, toggles de
  auto-fill, store con/sin passphrase, y DB real con keyfile+contraseña
  (rechaza `--no-password`, rechaza contraseña incorrecta, abre por stdin).
- CI: compila `keygate_web.py`/`keygate_vault.py` y valida `scripts/keygate-store`.

## 0.6.12 — 2026-11-07
- **`scripts/keygate-vault` — cifrado en reposo de SOLO los dos archivos**: la
  DB y la keyfile se guardan como `hermes.kdbx.gpg` + `agent.key.gpg`
  (AES-256, 0600) en `~/.keygate-vault`; el resto de `Documentos` no se toca.
  `open -- CMD` descifra ambos a tmpfs, exporta `KEYGATE_DB`/`KEYGATE_KEYFILE`,
  ejecuta el comando y los destruye al salir. Sin `open` no hay vault usable
  (fail-closed). `status` muestra qué está cifrado y si algo quedó abierto.
  `--ttl N` agrega un vigilante que borra el vault temporal aunque el wrapper
  muera con SIGKILL (el trap no corre en ese caso).

## 0.6.11 — 2026-11-07
- **`scripts/keygate-unlock` — modo escrow de la keyfile**: la `.key` se guarda
  cifrada con gpg (AES-256) fuera del equipo y solo se materializa en tmpfs
  (`/dev/shm`, 0700, 0600) durante el comando que la necesita; al salir o al
  vencer `--ttl` se borra con `shred`. Passphrase por TTY, pasada a gpg por
  descriptor (nunca por argv). `--seal` produce el blob para subir a cualquier
  nube/USB; `--from CMD` permite traerlo con `rclone cat`, `curl`, etc.
- CI: sintaxis de los scripts nuevos + prueba de humo del escrow (hash idéntico
  tras descifrar en tmpfs y rechazo de passphrase incorrecta).

## 0.6.10 — 2026-11-07
- **Icono propio**: `/favicon.svg` (escudo con ojo de cerradura, degradado
  azul→verde) servido por el propio sync con `img-src 'self'`, más el mismo
  vector inline en la cabecera en lugar del emoji. `<link rel="icon">` y
  `theme-color` en el `<head>`. Test de regresión incluido.

## 0.6.9 — 2026-11-07
- **F7 — CSP estricta sin `unsafe-inline`** (lo marcaba ZAP como 4 Medium):
  `script-src`/`style-src` pasan a `'nonce-<aleatorio por respuesta>'`. Para
  ello se eliminaron los 25 handlers inline (`onclick`/`oninput`/`onkeydown`)
  por delegación con `data-act`/`data-oninput`/`data-enter`, los 44 atributos
  `style=""` por clases `.sN`, y las visibilidades/colores que el JS aplicaba
  con `el.style.*` por la clase `.hide` y `data-tone` (Chrome también bloquea
  los estilos creados en runtime).
- Sin versión en la cabecera `Server` (eliminaba las 4 alertas Low de ZAP).
- Verificación visual con Chromium headless (puppeteer): 6 capturas del flujo
  completo, **0 violaciones de CSP** y **0 errores de consola**; ZAP 2.17
  spider+active: **0 alertas** (antes 4 Medium + 4 Low).

## 0.6.8 — 2026-11-07
- **F5 — CSRF sin `Origin` + código de arranque**: `/api/*` rechaza POST que no
  traigan `Origin` **ni** `Sec-Fetch-Site` (403). La primera visita exige un
  código de un solo uso (`~/.hermes/keygate-sync-bootstrap`, 0600, impreso en
  la consola) que se borra al crear la contraseña: un peer que alcance el
  puerto antes ya no puede reclamar la UI de sync.
- **F6 — `Host` duplicado**: más de un `Host` (o con comas) → 403.
- **F2 — auditoría fail-closed en el fill**: `kg.audit(..., strict=True)` con
  `fsync`; si la línea no se puede persistir, el relleno se aborta con
  `audit_unavailable`. Los eventos de lectura siguen best-effort.
- **F1 — tests que nunca corrían**: `pytest` se ejecuta desde `tests/`
  (`tests/conftest.py` + `scripts/keygate-test`), 40 pruebas en CI, que antes
  solo corría `unittest` sobre `test_autofill*` (9 de 29).
- Selftest: 44 PASS (nuevos casos F5/F6). ZAP 2.17 + JRE 17 headless.

## 0.6.7 — 2026-11-05

- **Licencia**: el proyecto pasa a **MIT**, software libre OSI aprobado y sin
  restricción de uso comercial. Se actualizan `LICENSE`, badges y las secciones
  de licencia de README/CONTRIBUTING.

## 0.6.6 — 2026-10-29

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
