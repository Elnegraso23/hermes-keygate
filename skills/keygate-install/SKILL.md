---
name: keygate-install
description: "Install keygate from scratch when the user says 'instalame este repo'. Clone, install plugin, create vault, configure Hermes, then guide first login. Use for any first-time keygate setup."
version: 0.2.0
license: MIT
platforms: [linux, macos, windows]
---

# Keygate: instalacion desde cero

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

### Paso 2 — Clonar

Con `terminal` (o la tool de shell disponible), clona a `~/hermes-keygate`:

```bash
git clone <URL> ~/hermes-keygate
```

Si el directorio ya existe, pregunta si lo sobreescribes (`git pull`) o usas otro destino.
Reporta el resultado al usuario en una linea.

### Paso 3 — Instalar el plugin

```bash
mkdir -p ~/.hermes/plugins/keygate
cp ~/hermes-keygate/__init__.py ~/hermes-keygate/keygate_lib.py ~/hermes-keygate/plugin.yaml ~/.hermes/plugins/keygate/
hermes plugins enable keygate
```

Dile al usuario:

> "Plugin instalado y habilitado. Rige en tu proxima sesion — pero seguimos,
> primero dejamos el vault y la config listos."

### Paso 4 — Crear el vault operativo (SIN master password)

```bash
bash ~/hermes-keygate/scripts/keygate-setup
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

### Paso 8 — Primera cuenta (la hace el USUARIO en KeePassXC)

Tu NO creas credenciales (`keygate_alias_add` esta bloqueado por politica).
Guia al usuario:

> "Abre KeePassXC y abre `~/Documentos/hermes.kdbx` (usa el keyfile
> `~/.keepass-agent.key`, no pide password). Crea una entrada:
> Titulo = alias opaco (ej. `internet-agent-1`), usuario, password,
> URL exacta del login. Guarda y avisame."

Para probar sin cuentas reales, sugiere el sitio publico de pruebas:

- URL: `https://the-internet.herokuapp.com/login`
- Usuario: `tomsmith` / Password: `SuperSecretPassword!` (publicas, impresas en la pagina)
- Alias sugerido: `internet-agent-1`

### Paso 9 — Primer login (flujo keygate-default)

Cuando el usuario diga *"quiero entrar a <url>"*:

1. `browser_vault_list` — ¿ya hay login para ese origin? Si si, fill nativo directo.
2. Si no, pide el **alias** (nunca usuario ni password).
3. `keygate_import` con ese alias → muestra UN prompt
   (`Allow import login ...?`) → espera accept.
4. `browser_vault_fill` con el handle importado + submit del MISMO form sin re-navegar.
5. Cita textual el mensaje de la pagina como prueba.

Exito = `You logged into a secure area!` + audit `approval: accept`.

### Paso 10 — Cierre

Cuando el login funcione, dile:

> "Ya quedo. Desde ahora keygate es tu default: dime 'quiero entrar a <sitio>'
> y si ya esta importado lo lleno directo; si no, te pido el alias una vez y
> lo importo con una aprobacion. Nada de passwords en el chat, jamas."

Menciona `scripts/keygate-update` para futuras actualizaciones y el archivo
`PRIMERA-VEZ.md` del repo como referencia.

## Reglas duras (nunca rompas estas)

- `keygate_alias_add` SIEMPRE se rehusa: las credenciales se crean en KeePassXC, nunca desde el chat.
- Nunca `execute_code`/`curl` con credenciales. Nunca escribas un password tu mismo.
- Si un fill se rehusa por origin mismatch, PARA y avisa (guardia anti-phishing).
- Modo estricto (usuario pide aprobacion por fill): usa `keygate_request_fill`
  en vez de import+fill.
- El `.key` JAMAS viaja (ni sync, ni croc, ni chat). Solo el `.kdbx` como ciphertext.
