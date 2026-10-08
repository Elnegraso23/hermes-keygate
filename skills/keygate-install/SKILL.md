---
name: keygate-install
description: "Install keygate from scratch when the user says 'instalame este repo'. Clone, install plugin, create vault, configure Hermes, then guide first login. Use for any first-time keygate setup."
version: 0.2.0
license: MIT
platforms: [linux, macos, windows]
---

# Keygate: instalacion desde cero

> **TL;DR innegociable (lee esto primero):**
> 1. Copia codigo **+ `skills/`** (`ls .../skills/*/SKILL.md` debe mostrar 2 archivos).
> 2. La primera credencial va por la **pagina localhost** (`http://127.0.0.1:8472`),
>    NUNCA mandes al usuario a archivos sueltos como primer camino.
> 3. Todo `hermes ...` con `timeout 20` por delante.
> 4. Cierra la instalacion con el **Mensaje de cierre** de abajo, casi literal.

Se activa cuando el usuario dice **"instalame este repo"**, **"instala keygate"**,
**"quiero configurar keygate"** o cualquier variante de primera instalacion.

## Guion exacto (sigue este orden, no te saltes pasos)

### Paso 1 — Detectar que repo instalar

El usuario ya te dio la URL o te dijo "este repo". Si no hay URL clara, pregunta:

> "¿Me pasas la URL del repo? (ej. https://github.com/Elnegraso23/hermes-keygate)"

Una vez con la URL, di:

> "Voy a instalar keygate desde <URL>. Esto va a: clonar el repo, instalar el
> plugin, crear tu vault operativo de KeePass y configurar Hermes. ¿Seguimos?"

Espera confirmacion antes de tocar nada.

### Paso 2 — Clonar (o reutilizar + pull)

Si el clon ya existe, NO lo re-clones: `git pull --ff-only` y sigue. Si no
existe, clona a una ruta sensata (`~/hermes-keygate` o `~/Projects/github/hermes-keygate`):

```bash
git clone <URL> ~/hermes-keygate
```

Guarda la ruta real como `<REPO>` para el resto de los pasos.

### Paso 3 — Instalar el plugin (codigo + skills, ambos obligatorios)

```bash
mkdir -p ~/.hermes/plugins/keygate
cp <REPO>/__init__.py <REPO>/keygate_lib.py <REPO>/plugin.yaml ~/.hermes/plugins/keygate/
rm -rf ~/.hermes/plugins/keygate/skills
cp -r <REPO>/skills ~/.hermes/plugins/keygate/skills
timeout 20 hermes plugins enable keygate
ls ~/.hermes/plugins/keygate/skills/*/SKILL.md
```

Sin `skills/` el plugin queda MUDO: `register()` no encuentra las
instrucciones y el agente no sabe ni instalar ni loguear (fallo real que ya
paso). El `ls` final debe mostrar los dos `SKILL.md`; si no, la instalacion
esta rota — no sigas.

Dile al usuario:

> "Plugin instalado y habilitado. Rige en tu proxima sesion — pero seguimos,
> primero dejamos el vault y la config listos."

### Paso 4 — Crear el vault operativo (SIN master password)

```bash
bash <REPO>/scripts/keygate-setup
```

Esto crea (verifica que existan despues):

- `~/.keepass-agent.key` (0600) — keyfile unico, NUNCA sale de esta maquina
- `~/Documentos/hermes.kdbx` — vault operativo, keyfile-only, sin master
- `~/.config/keepassxc-agent.ini` — perfil aislado de KeePassXC

Dile al usuario:

> "Vault operativo creado. Es keyfile-only: no hay master password que robar.
> Tu vault personal ni lo tocamos — Hermes nunca lo va a conocer."

### Paso 5 — Configurar Hermes (sin secretos)

El agente NO edita `~/.hermes/config.yaml` a mano: usa el CLI (`hermes config
set <clave> <valor>`, claves con puntos). Si una clave la rechaza por
desconocida, reintenta con `--force` solo si la clave es del schema keygate:

```bash
hermes plugins enable keygate
hermes config set approvals.mode manual
hermes config set approvals.timeout 60
hermes config set approvals.single_query_mode deny
hermes config set secrets.keepass.enabled true
hermes config set secrets.keepass.db_path "/home/TU-USUARIO/Documentos/hermes.kdbx"
hermes config set secrets.keepass.keyfile "/home/TU-USUARIO/.keepass-agent.key"
hermes config set secrets.keepass.timeout_seconds 30
hermes config set browser.backend off
hermes config set browser.use_real_profile false
```

(TU-USUARIO = salida de `whoami`, no lo inventes.)

Reglas:

- `secrets.keepass.env` queda vacio/no se toca: nada se expone al entorno.
- `single_query_mode: deny` es intencional: sesiones `-q`/cron nunca auto-aprueban.
- Solo como fallback (si el CLI no trae alguna clave) edita el YAML: lee el
  archivo primero, fusiona — nunca lo sobreescribas completo.

### Paso 6 — Pedir reinicio (obligatorio)

Dile al usuario, literal:

> "Listo la parte tecnica. **Ahora reinicia Hermes** (cierra y reabre el chat).
> Cuando vuelvas dime 'ya reinicie' y verificamos que todo quedo bien."

No intentes verificar nada antes del reinicio — el plugin no carga hasta la
proxima sesion.

### Paso 7 — Verificar (sesion nueva)

Cuando el usuario diga "ya reinicie" o similar, corre:

```bash
hermes plugins list | grep -i keygate
```

y luego `keygate_status` via tool_search. Esperas ver:

- `enabled` en la lista de plugins
- `{locked: false, entries: 0}` (vault vacio, desbloqueado con keyfile)

Si algo falla, corre `keygate_doctor` y lee su JSON — te dice exactamente
que falta (version, DB, canal de aprobacion). Reporta el diagnostico, no adivines.

### Paso 8 — Primera credencial VIA LA WEB (camino principal)

NO mandes al usuario a buscar archivos a mano. La forma de primera vez es la
pagina local `keygate-sync`, que ya trae la guia "Primera vez" integrada.
Arranca el servidor asi (token nuevo solo si no existe; NUNCA imprimas el
token en el chat — el usuario lo lee con `cat`):

```bash
test -f ~/.hermes/keygate-sync-token || { openssl rand -hex 24 > ~/.hermes/keygate-sync-token && chmod 600 ~/.hermes/keygate-sync-token; }
KEYGATE_DB=~/Documentos/hermes.kdbx KEYGATE_KEYFILE=~/.keepass-agent.key \
KEYGATE_SYNC_TOKEN="$(cat ~/.hermes/keygate-sync-token)" \
KEYGATE_BIND=127.0.0.1 KEYGATE_PORT=8472 \
nohup python3 <REPO>/sync/keygate_sync.py >/tmp/keygate-sync.log 2>&1 &
```

(`<REPO>` = donde se clono, ej. `~/Projects/github/hermes-keygate`. Verifica
que el proceso quedo vivo con `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8472/` → debe dar 200.
Corre TODOS los comandos `hermes ...` con `timeout 20` por delante: el CLI
puede quedarse esperando confirmacion y jamas debes bloquear la instalacion
por eso — "rige en la proxima sesion" es suficiente.)

Dile al usuario, literal:

> "Abre http://127.0.0.1:8472 en tu navegador. Te va a pedir el Token de
> keygate-sync: corre `cat ~/.hermes/keygate-sync-token` en tu terminal y
> pegalo (queda solo en esa pestaña). Arriba veras la tarjeta 'Primera vez':
> 1) ⬇ Descarga el .kdbx, 2) Descarga el .key (una sola vez, guardalo 600),
> 3) abre el .kdbx en KeePassXC con ese .key y añade tu cuenta (Titulo = alias
> opaco ej. `internet-agent-1`, URL exacta del login), guarda, 4) sube el
> .kdbx editado en la misma pagina. Avisame cuando la pagina muestre tu alias."

Para probar sin cuentas reales, sugiere el sitio publico de pruebas:

- URL: `https://the-internet.herokuapp.com/login`
- Usuario: `tomsmith` / Password: `SuperSecretPassword!` (publicas, impresas en la pagina)
- Alias sugerido: `internet-agent-1`

Alternativa solo-si el usuario prefiere (mismo PC, KeePassXC a mano): abrir
directo `~/Documentos/hermes.kdbx` con `~/.keepass-agent.key`. La web sigue
siendo el camino por defecto — mencionala primero, siempre.

### Paso 9 — Primer login (flujo keygate-default)

Cuando el usuario diga *"quiero entrar a <url>"*:

1. `browser_vault_list` — ¿ya hay login para ese origin? Si si, fill nativo directo.
2. Si no, pide el **alias** (nunca usuario ni password).
3. `keygate_import` con ese alias → muestra UN prompt
   (`Allow import login ...?`) → espera accept.
4. `browser_vault_fill` con el handle importado + submit del MISMO form sin re-navegar.
5. Cita textual el mensaje de la pagina como prueba.

Exito = `You logged into a secure area!` + audit `approval: accept`.

### Paso 10 — Cierre (mensaje literal, no lo reescribas con tus palabras)

Cuando el login funcione, dile:

> "Ya quedo. Desde ahora keygate es tu default: dime 'quiero entrar a <sitio>'
> y si ya esta importado lo lleno directo; si no, te pido el alias una vez y
> lo importo con una aprobacion. Nada de passwords en el chat, jamas."

Menciona `scripts/keygate-update` para futuras actualizaciones y el archivo
`PRIMERA-VEZ.md` del repo como referencia.

### Mensaje de cierre de INSTALACION (pegalo casi literal al terminar de instalar)

Al terminar los pasos 1–5, ANTES del reinicio, cierra con esto (adapta solo la
ruta real del repo). NO lo sustituyas por instrucciones de KeePassXC manual —
la pagina es el camino:

> "Listo, hermes-keygate instalado: plugin habilitado, vault operativo creado
> (keyfile-only, sin master) y config aplicada.
> Ahora te toca (3 cosas):
> 1. **Reinicia Hermes** (cierra y reabre el chat). Al volver dime 'ya reinicie'.
> 2. **Tu primera cuenta va por la pagina http://127.0.0.1:8472** (la levanto
>    yo al verificar): ahi descargas el .kdbx y el .key (una sola vez), editas
>    en KeePassXC y subes el .kdbx. Sin terminal, sin buscar archivos.
> 3. Cada sitio nuevo te pedira UN Accept. Nada de passwords en el chat, jamas."

## Reglas duras (nunca rompas estas)

- `keygate_alias_add` SIEMPRE se rehusa: las credenciales se crean en KeePassXC, nunca desde el chat.
- Nunca `execute_code`/`curl` con credenciales. Nunca escribas un password tu mismo.
- Si un fill se rehusa por origin mismatch, PARA y avisa (guardia anti-phishing).
- Modo estricto (usuario pide aprobacion por fill): usa `keygate_request_fill`
  en vez de import+fill.
- El `.key` JAMAS viaja (ni sync, ni croc, ni chat). Solo el `.kdbx` como ciphertext.
- El token de keygate-sync JAMAS se imprime en el chat ni en logs: el usuario
  lo lee con `cat ~/.hermes/keygate-sync-token`.
- La pagina localhost (`http://127.0.0.1:8472`) es el camino por defecto para
  la primera credencial — mencionala siempre antes que los archivos sueltos.
