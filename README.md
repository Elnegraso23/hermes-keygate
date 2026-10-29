# 🔑 hermes-keygate — logins ciegos de KeePassXC para Hermes Agent
**Español** · [English](README.en.md)

[![Version](https://img.shields.io/badge/version-0.6.1-orange.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](README.md)
[![Python: stdlib](https://img.shields.io/badge/python-stdlib%20only-blue.svg)](sync/keygate_sync.py)
[![Tests: selftest 22/22](https://img.shields.io/badge/selftest-32%2F32-success.svg)](scripts/keygate-selftest.sh)

> **⚠️ ALFA (v0.6.1) — software fresco, con fallas conocidas.**
> Funciona en máquinas reales pero cambia rápido y a veces se rompe
> (skills que no cargaban, rutas con comillas, botones mudos — todo real,
> todo corregido en público). **No lo uses todavía para cuentas críticas**:
> prueba con el sitio de pruebas o cuentas desechables, reporta en
> [issues](https://github.com/Elnegraso23/hermes-keygate/issues) (qué esperabas,
> JSON de la tool, últimas líneas del audit **sin secretos**), y actualiza
> seguido (`scripts/keygate-update`). Mientras la versión sea `0.x`, cualquier
> update puede cambiar comportamiento, nombres de tools o formato de config.

Hermes se loguea en tus sitios **sin ver jamás tus contraseñas**: tú apruebas
en tu pantalla, un plugin las inyecta directo en la página. Inspirado en
*1Password for Claude*, 100% open source y self-hosted.

## Índice

- [Cómo funciona](#cómo-funciona-diseño-en-30-segundos)
- [Instalación](#instalación)
- [Primera cuenta](#dar-cuentas-por-la-pagina-local-camino-normal)
- [Uso diario](#uso-diario-keygate-es-el-default)
- [Logins con redirect / OAuth](#logins-con-redirect--oauth-google-microsoft-github)
- [Sync web](#sync-al-host-hermes-mismo-pc-o-remoto)
- [Dos equipos con Tailscale](#dos-equipos-con-tailscale-el-bot-en-un-servidor-vos-desde-tu-pc)
- [Regenerar el vault](#regenerar-el-vault-corrupto-viejo-o-empezar-de-cero)
- [Si el browser de Hermes no abre](#si-el-browser-de-hermes-no-abre-bug-de-socket-upstream)
- [Probarlo](#probarlo-sitio-público-de-pruebas)
- [Actualizar](#actualizar-y-seguimiento)
- [Versiones](#versiones-alfa-0x-todo-puede-cambiar)
- [Herramientas del plugin](#herramientas-del-plugin)
- [Estructura del repo](#estructura-del-repo)
- [FAQ](#faq)
- [Límites honestos](#límites-honestos)

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

- El password/TOTP **nunca** entra al contexto del modelo, logs, SQLite, Telegram ni audit (solo hints `j***@x.com`). Verificado con canario: `scripts/keygate-leakcheck.py` (PASS).
- Sin aprobación explícita no hay fill (fail-closed verificado; ni timeouts ni errores aprueban). La aprobación es lo último: pre-flight de pestaña viva primero. Única excepción: un alias con política de auto-relleno activa para ese origin exacto (ver § Sin aprobación por cuenta).
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

**Requisitos:** `keepassxc` ≥ 2.7 (aporta `keepassxc-cli` con `db-create`; el
preflight lo verifica) + Hermes Agent con browser local. Opcional: `croc`
(solo sync remoto sin web).

```bash
git clone https://github.com/Elnegraso23/hermes-keygate.git ~/Projects/github/hermes-keygate
cd ~/Projects/github/hermes-keygate
bash scripts/keygate-preflight.sh   # ¿esta máquina puede? (binarios, db-create, HOME, dir del vault)
bash scripts/keygate-install.sh     # hace todo; el instalador también corre el preflight
# Flags: --reset (reset total explícito: password web + flag one-shot + vault
#          con respaldo) · KEYGATE_BIND=<IP> (default: auto-detecta Tailscale)
```

Lo que hace el instalador, paso por paso (a mano solo si insistes):

1. clona/pull del repo
2. copia `__init__.py` + `keygate_lib.py` + `plugin.yaml` + `skills/` (sin `skills/` el plugin queda MUDO: el agente no recibe instrucciones)
3. `hermes plugins enable keygate`
4. `scripts/keygate-setup` → `~/.keepass-agent.key` (0600) + `~/Documentos/hermes.kdbx` (keyfile-only, SIN master) + perfil aislado
5. `hermes config set` sin comillas (approvals manual, `secrets.keepass` con rutas, `browser.backend off`)
6. arranca `keygate-sync` (systemd si hay, si no proceso; bindea Tailscale si existe)

Verifica: `hermes plugins list | grep -i keygate` → `enabled`; en el chat,
`keygate_status` debe decir `{locked:false, entries:0}`.

## Dar cuentas: por la pagina local (camino normal)

El instalador arranca `keygate-sync` y te manda a la URL que imprime
(`http://127.0.0.1:8472` o tu IP de Tailscale). La tarjeta *"Primera vez"*
guia: ⬇ descarga el `.kdbx` (+ el `.key` una sola vez) → edita en KeePassXC
(copias con alias opacos, URL exacta, sin notas/adjuntos) → sube el `.kdbx`
(confirmacion + backup). Quitar acceso = borrar la copia (o cerrar la DB).

Alternativa mismo-PC (sin pagina): abre `~/Documentos/hermes.kdbx` directo en
KeePassXC con `~/.keepass-agent.key`. La pagina sigue siendo el camino normal —
un agente que instale esto debe ofrecerla PRIMERO, siempre.

## Sin aprobación por cuenta (auto-relleno)

Si una cuenta te obliga a loguearte muchas veces, puedes marcar **solo esa
cuenta** para que el relleno no pida aprobación cada vez. Se hace desde la web
de `keygate-sync`, con la misma contraseña de la web:

1. Abre `http://<ip-tailscale>:8472/` e inicia sesión.
2. En **“Aliases y auto-relleno”**, cada alias muestra un campo de *origin*
   (prellenado con la URL guardada en la entrada del vault) y una casilla
   **“Sin aprobación”**.
3. Marca la casilla y pulsa **Guardar**.

Qué hace exactamente:

- La política vive en `~/.hermes/keygate-autofill.json` (0600, escritura atómica),
  una entrada por alias: `{ "origin": "https://host", "enabled": true }`.
- En el siguiente fill, si el alias tiene política activa **y el origin coincide
  exacto**, se rellena sin prompt y se audita `approval: "auto-policy"` +
  `policy: "alias-auto"`.
- El origin se compara normalizado (`scheme://host:puerto`). Cambiar de esquema,
  puerto o subdominio **vuelve a pedir aprobación**.
- Al activarlo, la web exige que el host del origin coincida con la URL de la
  entrada en el vault; si no, responde `400 origin host does not match the
  vault entry URL`.
- Sesiones desatendidas (cron / one-shot) siguen rechazadas: la política no
  habilita logins headless.
- Desmarcar la casilla y guardar borra la política (vuelve el prompt normal).

Riesgo que asumes: mientras la política esté activa, cualquier fill de ese alias
en ese origin exacto se ejecuta sin que lo veas. Actívala solo en cuentas y
sitios que controles; para todo lo demás, deja el prompt.

## Uso diario (keygate es el default)

El plugin instala la skill `keygate-default`: ante un *"logueate en <sitio>"*,
Hermes primero mira el vault nativo; si falta el login, te pide el **alias**,
lo importa con `keygate_import` (**una** aprobación) y rellena con el flujo
nativo (ciego al modelo, atado al origen). Después, loguearse es directo.

Pide en el chat (sesión nueva tras instalar):

```text
Usa browser_navigate para abrir <URL-del-login> en el navegador del agente.
Luego usa tool_search para descubrir keygate_request_fill y logueate con
alias <alias> y origin <https://dominio>. Espera mi aprobacion antes del fill.
Tras un fill exitoso haz submit del MISMO formulario sin re-navegar y citame
textual el mensaje de la página. Jamas contraseñas en el chat ni
execute_code/curl con credenciales.
```

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
endpoint muere con 403; para cambiarla: `POST /api/reset-password` con la
actual). Se guarda con PBKDF2-HMAC-SHA256 + salt en
`~/.hermes/keygate-sync-pass` (0600); en tu navegador vive solo en el
`sessionStorage` de esa pestaña.

- **Sin ventana admin/admin**: no existe default adivinable; la primera visita
  sin password solo deja crearla, nada mas (403 al resto).
- **Jamás por Telegram/chat**: quedaría en historial y servidores de Telegram
  (la misma razón por la que nunca viajan passwords).
- Honesto: contra un lector con terminal en el host, password y token empatan
  (puede leer el vault directo, la web le sobra). La contraseña protege el
  acceso web REMOTO sin dejar secreto en disco.

Endpoints: `/api/setup-state` (público) · `/api/reset-password` `{current, new}`
· `/api/health` (público mínimo) · `/api/aliases` redactados ·
`GET /api/download` (round-trip sin terminal) · `POST /api/upload` (valida
KDBX+keyfile, anti-wipe, backup+reemplazo atómico) · `/api/onboarding/keyfile`
(**una sola vez**, luego 410) · `/api/audit`. Todo con Bearer salvo los
marcados públicos.

**Fallback: `croc`** — `scripts/keygate-push [--dry-run]` en tu PC y
`scripts/keygate-pull <CODIGO>` en el host (valida, backup×5, atómico,
rehúsa `*.key` siempre).

## Dos equipos con Tailscale (el bot en un servidor, vos desde tu PC)

Patrón típico: hablás con Hermes por **Telegram** (su gateway corre en un
servidor, p.ej. `HOME=/opt/hermes`) y editás el vault desde tu PC. Una vez en
el mismo tailnet:

**En el servidor del bot** (por el chat de Telegram, sin delegar):

```bash
# 1. Requisitos: git, python3, keepassxc-cli (keepassxc), curl, tailscale
tailscale ip -4 | head -1                                  # = IP del servidor
# 2. Instalación completa EN EL SERVIDOR (el instalador hace pull solo y
#    auto-detecta la IP de Tailscale para el bind):
bash ~/Projects/github/hermes-keygate/scripts/keygate-install.sh
# 3. Workaround del browser (bug de socket de Hermes): ver sección más abajo.
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
silencio**, y la rotación `*.bak` no lo toca) y crea una nueva. El `.key` se
**reutiliza**: el que descargaste una vez sigue abriendo la nueva, así que no
hay que repetir el onboarding. El sync lee el archivo por llamada: los cambios
se ven sin reiniciar el servicio.

```bash
bash scripts/keygate-setup --reset-key   # perdiste tu copia del .key: permite
                                         # bajarlo UNA vez más (acción local
                                         # explícita; quien tenga la password
                                         # web podrá bajarlo de nuevo)
bash scripts/keygate-install.sh --reset  # RESET TOTAL: borra password web +
                                         # flag one-shot + reemplaza el vault
                                         # (con respaldo). Default: seguro.
```

Desinstalar: `hermes plugins disable keygate`, borra
`~/.hermes/plugins/keygate/`, el bloque de config, y (si quieres)
DB/keyfile/pass/audit. Nada queda en Hermes.

## Si el browser de Hermes no abre (bug de socket upstream)

Síntoma: `browser_navigate` falla con *"Session name 'hermes_local-…' is too
long. Socket path would be >103 bytes"*. Es un bug de Hermes (su id de sesión
creció a `local-<64hex>` y el binario agent-browser arma un socket Unix largo);
**no es de keygate**. El fill de keygate no lo toca, pero necesita una pestaña
viva.

Workaround verificado (llenó campos y el password jamás salió al modelo):
apuntá `browser.cdp_url` a un Chromium propio que **tú** controlás — así además
VES el login en vivo.

**Duradero (recomendado): Chromium como servicio systemd de usuario** —
sobrevive cierres de chat y reinicios (con `lingering`):

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

## Probarlo (sitio público de pruebas)

Sin cuentas reales: [the-internet login](https://the-internet.herokuapp.com/login)
(user `tomsmith`, pass `SuperSecretPassword!` — públicas, impresas en la página):

```bash
printf 'SuperSecretPassword!\n' | keepassxc-cli add -k ~/.keepass-agent.key \
  --no-password -q ~/Documentos/hermes.kdbx internet-agent-1 \
  -u tomsmith --url https://the-internet.herokuapp.com/login -p
```

(OJO: esto mete una credencial por el historial del shell — solo aceptable
porque son públicas. Las reales van por KeePassXC o por la web, nunca por
terminal/chat.)

Luego el prompt de uso diario con `alias internet-agent-1` y
`origin https://the-internet.herokuapp.com`. Éxito =
`You logged into a secure area!` + audit `allow` + `approval: accept`.

## Defensas de sesión (H11–H12)

- **El relleno es atómico y solo en el top-level.** La guardia de origen y la de
  `window.top === window.self` viajan dentro del mismo `Runtime.evaluate` que
  escribe en el DOM, así que una redirección tardía o un iframe cross-origin no
  pueden colarse entre la comprobación y el relleno. Errores:
  `frame_not_top_level`, `origin_changed_toctou`.
- **Host allowlist contra DNS rebinding.** El servidor web acepta únicamente el
  `Host` de su IP de bind (y `localhost`/`127.0.0.1` cuando escucha en loopback);
  cualquier otro `Host` recibe 403 antes de tocar una ruta.

## Dependencia: keepassxc-cli (endurecida, H10)

keygate **no** implementa criptografía propia ni incluye binarios: usa el
`keepassxc-cli` del sistema como **frontera criptográfica**. Así heredas los
parches de seguridad de tu distro y se evita AES/Argon2 caseros.

Desde 0.6.3 el binario se resuelve de forma determinista y se valida **antes**
de ejecutarlo:

1. `KEYGATE_KXC_BIN` (ruta absoluta). Si la defines y es inválida o insegura,
   falla con error claro y **no** cae a otro binario.
2. Rutas canónicas: `/usr/bin`, `/usr/local/bin`, `/snap/bin`,
   `/Applications/KeePassXC.app/Contents/MacOS`, `/opt/homebrew/bin`.
3. `PATH`.

Comprobaciones: archivo regular, ejecutable, **sin escritura para group/others**,
propietario `root` o tu uid, y directorio padre no escribible por group/others
(`/tmp` solo se acepta con sticky bit y siendo tuyo el binario y el directorio).

```bash
scripts/keygate-doctor      # o: python3 keygate_lib.py --doctor
```

Devuelve `kxc_found`, `kxc_path`, `kxc_source` (`env:KEYGATE_KXC_BIN` |
`system_path` | `missing`), `kxc_permissions_ok`, `kxc_version`,
`kxc_version_ok` (mínimo 2.7.0) e `install_hint` con el comando de tu distro.
El mismo bloque aparece en `keygate_doctor`.

**Flatpak:** el export `org.keepassxc.KeePassXC` es la GUI, no el CLI. Crea un
wrapper que ejecute `flatpak run --command=keepassxc-cli org.keepassxc.KeePassXC`
y apunta `KEYGATE_KXC_BIN` a ese wrapper.

## Actualizar y seguimiento

```bash
bash ~/hermes-keygate/scripts/keygate-update   # pull + instala + verifica; rige próxima sesión
```

- Si un update trajera `.kdbx`/`.key`, **aborta** sin tocar nada.
- Issues: [github.com/Elnegraso23/hermes-keygate/issues](https://github.com/Elnegraso23/hermes-keygate/issues)
  (qué esperabas, JSON de la tool, últimas líneas del audit **sin secretos** —
  hay [plantilla](.github/ISSUE_TEMPLATE/bug_report.md)).
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

## Herramientas del plugin

| Tool | Qué hace | Secretos |
|---|---|---|
| `keygate_search` | busca alias, devuelve hints redactados | nunca valores |
| `keygate_request_fill` | aprobación + fill ciego por CDP | solo `{success, filled_fields}` |
| `keygate_import` | copia UNA vez al vault nativo (1 aprobación) | handle opaco, nada más |
| `keygate_status` | DB bloqueada + conteo | conteo |
| `keygate_doctor` | versión, DB, canal, transporte browser, audit | redactado |
| `keygate_version` | instalada vs GitHub + changelog | versiones |
| `keygate_session_ensure/invalidate` | sesiones efímeras con TTL | handles opacos |
| `keygate_alias_add` | **siempre rehusado por política** | — |
| `KeepassSource keepass` | refs `kpx://alias/campo` para API keys | vía SecretSource nativo |

## Estructura del repo

```text
hermes-keygate/
├── __init__.py          # plugin: SecretSource + 9 tools + registro de skills
├── keygate_lib.py       # redacción, keepassxc-cli, sesiones, audit, rutas
├── plugin.yaml          # manifiesto (versión canónica)
├── skills/
│   ├── keygate-default/ # flujo de login diario (para el modelo)
│   └── keygate-install/ # instalación desde cero (para el modelo)
├── sync/
│   └── keygate_sync.py  # web de sync (stdlib puro: aliases/download/upload/…)
├── scripts/
│   ├── keygate-install.sh   # una pasada: repo→plugin→vault→config→sync
│   ├── keygate-update       # pull + instala + verifica (fail-closed)
│   ├── keygate-setup        # vault keyfile-only [--force/--reset-key]
│   ├── keygate-preflight.sh # ¿esta máquina puede? (falla barato y claro)
│   ├── keygate-selftest.sh  # 22 regresiones en host fresco simulado
│   ├── keygate-leakcheck.py # canario: ningún secreto llega al modelo
│   ├── keygate-push/pull    # sync por croc (fallback sin web)
│   └── keygate-fetch        # (utilidad)
├── PRIMERA-VEZ.md       # guía del usuario frase por frase
├── CHANGELOG.md         # qué trajo cada versión
├── SECURITY.md          # cómo reportar agujeros
└── config.keygate.example.yaml
```

## FAQ

**¿El bot instaló en `/opt/hermes` y yo esperaba `/home/...`?**
No es un bug: hablás con un Hermes que corre en **otra máquina** (su gateway no
es tu PC). Cada instalación vive donde vive su operador: plugin, vault y config
van con el `HOME` de quien ejecuta. Decidí **una sola casa** para las
credenciales reales (recomendado: la máquina con la que hablás a diario) y
deshabilitá el plugin en la otra.

**¿Por qué me pide aprobación dos veces?**
Una por `keygate_import` (copiar de KeePass al vault, una vez en la vida de la
cuenta) y una por `keygate_request_fill` (modo estricto). Con las nativas
(`browser_vault_fill`) el segundo prompt no existe; donde no están otorgadas,
1 aprobación por login es el contrato.

**¿La web muestra datos viejos tras regenerar el vault?**
Recargá a lo bruto (Ctrl+Shift+R): la página es un shell estático y el DOM
puede ser anterior al reemplazo. Si persiste, compará fechas con
`ls -la ~/Documentos/` y revisá que el servicio apunte al mismo path
(`systemctl --user show keygate-sync.service -p Environment`).

**¿Puedo usar mi `personal.kdbx`?**
No, por diseño: Hermes nunca debe conocer su ruta. Duplicá las entradas que el
agente puede usar al operativo con alias opacos.

**¿Y si pierdo la contraseña de la web?**
`POST /api/reset-password` con la actual. Si la perdiste del todo: borrá
`~/.hermes/keygate-sync-pass` en el host (shell local) y la primera visita te
deja crear otra. Nunca por chat.

## Límites honestos

- El plugin corre in-process (privilegio de agente): la garantía es "nunca al
  LLM/logs", no sandbox contra root/malware local.
- `fill` exige sesión de browser supervisada; sin ella rehúsa antes que filtrar.
- TOTP: resuelve semillas guardadas en la entrada; pendiente prueba end-to-end
  con cuenta real con 2FA.
- `fetch()` de SecretSource solo hidrata refs `kpx://` que mapees: no mapees
  todo el vault, solo API keys necesarias.
