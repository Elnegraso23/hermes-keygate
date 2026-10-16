# 🔑 hermes-keygate — logins ciegos de KeePassXC para Hermes Agent

> **⚠️ ALFA (v0.4.0) — software fresco, con fallas conocidas.**
> Esto funciona en la máquina del autor pero cambia rápido y a veces se rompe
> (mira el historial: skills que no cargaban, rutas con comillas, botones mudos
> — todo real, todo corregido en público). **No lo uses todavía para cuentas
> críticas**: prueba con el sitio de pruebas o cuentas desechables, reporta en
> [issues](https://github.com/Elnegraso23/hermes-keygate/issues) (qué esperabas,
> JSON de la tool, últimas líneas del audit **sin secretos**), y actualiza
> seguido (`scripts/keygate-update`). Mientras la versión sea `0.x`, cualquier
> update puede cambiar comportamiento, nombres de tools o formato de config.

Hermes se loguea en tus sitios **sin ver jamás tus contraseñas**: tú apruebas
en tu pantalla, un plugin las inyecta directo en la página. Inspirado en
*1Password for Claude*, 100% open source y self-hosted.

## Cómo funciona (diseño en 30 segundos)

```
Tú (KeePassXC GUI)                Hermes (modelo)              Plugin (tu máquina)
─────────────────                 ──────────────              ───────────────────
hermes.kdbx (keyfile,             pide "alias +               resuelve user/pass
 sin master)                       origin"                    vía keepassxc-cli
      │                                   │                    en memoria local
      │                          ┌────────┴────────┐                   │
      │                          │ TÚ APRUEBAS en  │                   │
      │                          │ tu pantalla     │                   │
      │                          └────────┬────────┘                   │
      │                                   │                    inyecta por CDP
      │                                   │                    solo si la pestaña
      │                                   │                    == URL del ítem
      │                           recibe {success,                    │
      │                           filled_fields}  ← NUNCA el secreto ──┘
```

**Garantías:**
- El password/TOTP **nunca** entra al contexto del modelo, logs, SQLite, Telegram ni audit (solo hints `j***@x.com`).
- Sin aprobación explícita no hay fill (fail-closed verificado; ni timeouts ni errores aprueban).
- Amarre exacto de origen (vault-URL == origen pedido == origen de la pestaña, re-chequeado dentro del script contra TOCTOU).
- Cada fill deja auditoría redactada (`~/.hermes/keygate-audit.jsonl`).
- Altas/bajas de credenciales **desde el chat están bloqueadas por política**: los cambios se hacen en tu KeePassXC + sync del `.kdbx`.

**Dos vaults (el corazón del diseño):**
- `personal.kdbx` — el tuyo de siempre (master+keyfile). Hermes **no lo conoce ni lo toca**.
- `hermes.kdbx` — operativo, **keyfile-only sin master password** (no hay maestra que robar/filtrar), solo con copias de lo que el agente puede usar, con alias opacos (`sitio-agent-1`).

## Instalación

> **🤖 Si eres un agente instalando esto: ejecuta
> `bash <repo>/scripts/keygate-install.sh` y pega su salida. NO hagas los
> pasos a mano ni preguntes qué paso seguir: el script hace todo (repo,
> plugin + skills, vault, config, sync) y termina con un bloque `== LISTO ==`.**
>
> El script es idempotente (puedes re-correrlo), no toca tu vault personal,
> no pide ni genera contraseñas maestras y jamás recibe credenciales.

**Requisitos:** `keepassxc` (aporta `keepassxc-cli`) + Hermes Agent con
browser local. Opcional: `croc` (solo sync remoto sin web).

```bash
# 1. (Solo para humanos que quieran entender los pasos — los agentes: usen
#    el comando de arriba.)
git clone https://github.com/Elnegraso23/hermes-keygate.git ~/Projects/github/hermes-keygate
cd ~/Projects/github/hermes-keygate
bash scripts/keygate-preflight.sh   # ¿esta máquina puede? (binarios, db-create, HOME, dir del vault)
bash scripts/keygate-install.sh     # hace todo; el instalador también corre el preflight
```

# Lo que hace el script, paso por paso (a mano solo si insistes):
#   a. clona/pull del repo
#   b. copia __init__.py + keygate_lib.py + plugin.yaml + skills/ (sin
#      skills/ el plugin queda MUDO: el agente no recibe instrucciones)
#   c. hermes plugins enable keygate
#   d. scripts/keygate-setup  → ~/.keepass-agent.key (0600) +
#      ~/Documentos/hermes.kdbx (keyfile-only, SIN master) + perfil aislado
#   e. hermes config set (sin comillas — con comillas las rutas se rompen):
approvals.mode manual          → approvals.timeout 60
approvals.single_query_mode deny → secrets.keepass.enabled true
secrets.keepass.db_path …      → secrets.keepass.keyfile …
secrets.keepass.timeout_seconds 30 → browser.backend off
browser.use_real_profile false
#   f. arranca keygate-sync en http://127.0.0.1:8472
```

Verifica: `hermes plugins list | grep -i keygate` → `enabled`; en el chat,
`keygate_status` debe decir `{locked:false, entries:0}`.

## Si el browser de Hermes no abre (bug de socket upstream)

Síntoma: `browser_navigate` falla con *"Session name 'hermes_local-…' is too
long. Socket path would be >103 bytes"*. Es un bug de Hermes (su id de sesión
creció a `local-<64hex>` y el binario agent-browser arma un socket Unix largo);
**no es de keygate**. El fill de keygate no lo toca, pero necesita una pestaña
viva.

Workaround verificado (2026-10-15, llenó 2 campos y el password jamás salió al
modelo): apuntá `browser.cdp_url` a un Chromium propio que **tú** controlás —
así además VES el login en vivo.

**Duradero (recomendado): Chromium como servicio systemd de usuario** — sobrevive
cierres de chat y reinicios (con `lingering`):

```ini
# ~/.config/systemd/user/hermes-cdp-chromium.service
[Unit]
Description=Hermes CDP Chromium (endpoint for browser.cdp_url / keygate fills)
After=default.target
[Service]
Type=simple
ExecStart=/home/TU-USUARIO/.hermes/tools/chromium-1208/chrome-linux64/chrome \
  --headless=new --remote-debugging-port=9222 \
  --remote-debugging-address=127.0.0.1 \
  --user-data-dir=/home/TU-USUARIO/.local/share/hermes-cdp/profile \
  --no-first-run --no-default-browser-check --disable-gpu about:blank
Restart=always
RestartSec=3
# Perfil dedicado desechable: sin tus datos, bookmarks ni cookies.
[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now hermes-cdp-chromium.service
loginctl enable-linger   # arranca al boot sin sesión abierta
hermes config set browser.cloud_provider local
hermes config set browser.cdp_url http://127.0.0.1:9222
# Útiles: systemctl --user status hermes-cdp-chromium.service
#         journalctl --user -u hermes-cdp-chromium -n 50
```

**Temporal (una prueba):** lanzá el Chromium a mano con
`--remote-debugging-port=41777` y `hermes config set browser.cdp_url
http://127.0.0.1:41777` (muere al cerrar el chat; quitá la línea después).

Honesto: el override salta el stack local de Hermes completo — el modelo
tampoco ve esa pestaña (solo handles), y vos tenés el control físico.

## Dos equipos con Tailscale (el bot en un servidor, vos desde tu PC)

Patrón típico: hablás con Hermes por **Telegram** (su gateway corre en un
servidor, p.ej. `HOME=/opt/hermes`) y editás el vault desde tu PC. Una vez en
el mismo tailnet:

**En el servidor del bot** (por el chat de Telegram, sin delegar):

```bash
# 1. Requisitos: git, python3, keepassxc-cli (keepassxc), curl, tailscale
tailscale ip -4 | head -1                                  # = IP del servidor
# 2. Instalación completa EN EL SERVIDOR (el instalador hace pull solo).
#    KEYGATE_BIND ata el sync web a la IP de Tailscale (nunca 0.0.0.0):
KEYGATE_BIND=100.x.y.z bash ~/Projects/github/hermes-keygate/scripts/keygate-install.sh
# 3. Workaround del browser (bug de socket de Hermes): unit systemd con el
#    chromium DE ESE servidor + cdp_url. Ver sección del bug más arriba.
ls ~/.hermes/tools/ | grep chromium                        # ruta real del binario
```

**Desde tu PC** (cualquier navegador del tailnet):

```text
http://100.x.y.z:8472   → creás la contraseña (primera visita), descargás el
.key UNA VEZ (guardalo 600 acá), bajás el .kdbx, editás en KeePassXC, subís.
```

Reglas que sostienen el patrón:

- **El vault operativo vive en el servidor** (donde keygate lee). Tu PC solo
  edita copias vía la web; subir reemplaza atómicamente con backup.
- **El `.key` de cada máquina nunca viaja**: el del servidor se genera allá y
  se queda allá. El que bajás a tu PC es para editar; si lo perdés, se regenera
  el vault (`keygate-setup`) y se re-sube.
- **Credenciales reales, una sola casa**: no mantengas dos vaultes "activos".
  El otro equipo puede quedarse con el plugin deshabilitado.
- La contraseña del sync y el `.key` **nunca por Telegram/chat**: quedan en
  historial y servidores de la plataforma.

## Regenerar el vault (corrupto, viejo, o empezar de cero)

```bash
bash scripts/keygate-setup --force
```

Mueve la DB actual a `hermes.kdbx.corrupt-<timestamp>` (**nunca borra en
silencio**) y crea una nueva. El `.key` se **reutiliza**: el que descargaste una
vez sigue abriendo la nueva, así que no hay que repetir el onboarding. El sync
lee el archivo por llamada: los cambios se ven sin reiniciar el servicio.

Desinstalar: `hermes plugins disable keygate`, borra
`~/.hermes/plugins/keygate/`, el bloque de config, y (si quieres)
DB/keyfile/pass/audit. Nada queda en Hermes.

## Logins con redirect / OAuth (Google, Microsoft, GitHub…)

Funciona hoy, sin código extra — con una condición: **todos los campos de
credenciales viven en UN origen** (el del proveedor). Google: email y password
se escriben en `https://accounts.google.com` (distintas páginas, mismo origen;
el normalizado ignora el path). El redirect de vuelta a tu app no tiene campos
→ nada que llenar.

- Entrada KeePass con URL = el origen del proveedor
  (ej. `https://accounts.google.com/`), alias opaco igual que siempre.
- Flujo: un fill por paso (email → siguiente página → password), una aprobación
  cada uno. Redirects dentro del origen no rompen nada.
- Lo que se rehúsa **a propósito**: usuario en un origen y password en otro
  (`domain_mismatch`). Eso es la guardia anti-phishing, no un bug — ningún
  proveedor serio parte credenciales entre dominios; si lo ves, sospecha.

Límites honestos con Google en particular:

- **Detección de bots**: un Chromium fresco/desechable suele chocar con *"This
  browser or app may not be secure"*. Si pasa, la vía es tu perfil real ya
  logueado (attach por CDP), donde no hay nada que llenar.
- **Passkeys/WebAuthn**: no se pueden inyectar por diseño. Si la cuenta los
  exige, la automatización se detiene ahí y lo dice.

## Dar cuentas: por la pagina local (camino normal)

El instalador (`keygate-install`) arranca `keygate-sync` y te manda a
**http://127.0.0.1:8472**. La tarjeta *"Primera vez"* guia: ⬇ descarga el
`.kdbx` (+ el `.key` una sola vez) → edita en KeePassXC (copias con alias
opacos, URL exacta, sin notas/adjuntos) → sube el `.kdbx` (confirmacion +
backup). Quitar acceso = borrar la copia (o cerrar la DB).

Alternativa mismo-PC (sin pagina): abre `~/Documentos/hermes.kdbx` directo en
KeePassXC con `~/.keepass-agent.key`. La pagina sigue siendo el camino normal —
un agente que instale esto debe ofrecerla PRIMERO, siempre.

## Uso diario (keygate es el default)

El plugin instala la skill `keygate-default`: ante un *"logueate en <sitio>"*,
Hermes primero mira el vault nativo; si falta el login, te pide el **alias**,
lo importa con `keygate_import` (**una** aprobación) y rellena con el flujo
nativo (ciego al modelo, atado al origen). Después, loguearse es directo.

- `keygate_import(alias)` → copia UNA vez al vault cifrado local
  (`keygate:<alias>`). Rotar = re-importar; quitar = Hermes vault settings.
- `keygate_request_fill(alias, origin)` → modo estricto: aprobación por fill.
- `keygate_search/status/version/doctor` → metadata, conteo, updates, diagnóstico.

Pide en el chat (sesión nueva tras instalar):

```
Usa browser_navigate para abrir <URL-del-login> en el navegador del agente.
Luego usa tool_search para descubrir keygate_request_fill y logueate con
alias <alias> y origin <https://dominio>. Espera mi aprobacion antes del fill.
Tras un fill exitoso haz submit del MISMO formulario sin re-navegar y citame
textual el mensaje de la página. Jamas contraseñas en el chat ni
execute_code/curl con credenciales.
```

- `keygate_search("...")` → hints redactados (nunca secretos).
- Aprobación `Allow credential fill?` en tu pantalla → accept = un solo fill.
- `keygate_version` → instalada vs repo + changelog (el modelo te avisa de updates).
- Sesiones efímeras: `keygate_session_ensure/invalidate` (handles opacos en tmpfs;
  ante 401 se invalida y re-pide aprobación, nunca reintenta con vencidas).

## Probarlo (sitio público de pruebas)

Sin cuentas reales: [the-internet login](https://the-internet.herokuapp.com/login)
(user `tomsmith`, pass `SuperSecretPassword!` — públicas, impresas en la página):

```bash
printf 'SuperSecretPassword!\n' | keepassxc-cli add -k ~/.keepass-agent.key \
  --no-password -q ~/Documentos/hermes.kdbx internet-agent-1 \
  -u tomsmith --url https://the-internet.herokuapp.com/login -p
```

Luego el prompt de arriba con `alias internet-agent-1` y
`origin https://the-internet.herokuapp.com`. Éxito =
`You logged into a secure area!` + audit `allow` + `approval: accept`.

## Sync al host Hermes (mismo PC o remoto)

Edita siempre en tu KeePassXC local. El operativo viaja como ciphertext; el
`.key` **jamás viaja** (vive quieto en cada máquina, 0600). keygate lee el
archivo por llamada: el reemplazo aplica sin reiniciar. Modo local = edita en
su sitio, sin transferir nada.

**Primario: web `keygate-sync`** (solo Tailscale/LAN, stdlib puro):

```bash
KEYGATE_DB=~/Documentos/hermes.kdbx KEYGATE_KEYFILE=~/.keepass-agent.key \
KEYGATE_BIND=127.0.0.1 KEYGATE_PORT=8472 \
python3 ~/hermes-keygate/sync/keygate_sync.py
# NUNCA bindees 0.0.0.0.
```

### La contraseña: se crea en tu primera visita (sin default)

No hay password inicial ni archivo de token: al abrir la pagina por primera
vez TE OBLIGA a crearla (minimo 12 caracteres, una sola vez — despues ese
endpoint muere con 403). Se guarda con PBKDF2-HMAC-SHA256 + salt en
`~/.hermes/keygate-sync-pass` (0600); en tu navegador vive solo en el
`sessionStorage` de esa pestaña.

* **Sin ventana admin/admin**: no existe default adivinable; la primera visita
  sin password solo deja crearla, nada mas (403 al resto).
* **Jamás por Telegram/chat**: quedaría en historial y servidores de Telegram
  (la misma razón por la que nunca viajan passwords).
* Honesto: contra un lector con terminal en el host, password y token empatan
  (puede leer el vault directo, la web le sobra). La contraseña protege el
  acceso web REMOTO sin dejar secreto en disco.

`/api/setup-state` (publico: si falta crearla) · `/api/aliases` redactados ·
`GET /api/download` (baja el `.kdbx` actual: edítalo en KeePassXC y súbelo de
vuelta — round-trip sin terminal) · `POST /api/upload` (valida KDBX+keyfile,
rehúsa vacíos anti-wipe, backup+reemplazo atómico) · `/api/onboarding/keyfile`
(**una sola vez**, luego 410) · `/api/audit`. Todo con Bearer. La página no
tiene ningún campo de password: solo mueve ciphertext.

**Fallback: `croc`** — `scripts/keygate-push [--dry-run]` en tu PC y
`scripts/keygate-pull <CODIGO>` en el host (valida, backup×5, atómico,
rehúsa `*.key` siempre).

## Actualizar y seguimiento

```bash
bash ~/hermes-keygate/scripts/keygate-update   # pull + instala + verifica; rige próxima sesión
```

- Si un update trajera `.kdbx`/`.key`, **aborta** sin tocar nada.
- Issues: [github.com/Elnegraso23/hermes-keygate/issues](https://github.com/Elnegraso23/hermes-keygate/issues)
  (qué esperabas, JSON de la tool, últimas líneas del audit **sin secretos**).
- Regla: los fixes solo tocan código/docs, jamás tu vault.

## Versiones (alfa 0.x: todo puede cambiar)

- La versión vive en `plugin.yaml` (`keygate_version` la reporta: instalada
  vs repo + changelog; el modelo te avisa de updates).
- Desde 0.4.0 el plugin también pregunta a GitHub (raw `plugin.yaml` de main)
  aunque no tengas clon: 1 GET público, stdlib, 10s timeout, cacheado 24h en
  `~/.hermes/keygate-version-check.json`. Sin red responde `unknown` sin
  romper nada. Si hay versión mayor, `update_available: true` + `update_hint`.
- Esquema: `0.x.y` sin promesas — `x` puede renombrar tools, cambiar config o
  el flujo de auth. Lee `CHANGELOG.md` antes de actualizar si algo te importa.
- `1.0` llegará cuando el flujo completo (instalar → primera cuenta por web →
  login → sync) funcione tres veces seguidas sin intervención manual del autor.
  Hasta entonces, asume fallas y reporta.
- Tags `v0.x.y` marcan cada release en GitHub; el updater sigue commits
  (`pull --ff-only`) y deja el marcador `.installed_commit` en tu instalación.

## Límites honestos

- El plugin corre in-process (privilegio de agente): la garantía es "nunca al
  LLM/logs", no sandbox contra root/malware local.
- `fill` exige sesión de browser supervisada; sin ella rehúsa antes que filtrar.
- TOTP: resuelve semillas guardadas en la entrada; pendiente prueba end-to-end
  con cuenta real con 2FA.
- `fetch()` de SecretSource solo hidrata refs `kpx://` que mapees: no mapees
  todo el vault, solo API keys necesarias.
