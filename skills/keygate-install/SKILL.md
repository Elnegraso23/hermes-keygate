---
name: keygate-install
description: "Install keygate from scratch when the user says 'instalame este repo'. Run the one-shot installer, then guide first login. Use for any first-time keygate setup."
version: 0.3.0
license: MIT
platforms: [linux, macos, windows]
---

# Keygate: instalación desde cero

> **TL;DR innegociable (lee esto primero):**
> 1. **Tu PRIMERA salida es UN comando**: `bash <repo>/scripts/keygate-install.sh`.
>    No preguntes si ejecutarlo: EJECÚTALO y pega su salida.
> 2. Ese script hace TODO: repo, plugin + `skills/`, vault, config, sync vivo.
> 3. **NO des comandos manuales de `keepassxc-cli add -p`** (los passwords nunca
>    entran al chat, ni de mentira) y **NO ofrezcas `keygate_alias_add`**
>    (está bloqueado por política). Las credenciales van solo por la web o
>    KeePassXC.
> 4. **La primera credencial es por la página http://127.0.0.1:8472** —
>    que el script deja viva. Menciona esa URL en tu primer mensaje, siempre.
> 5. Nunca edites `~/.hermes/config.yaml` a mano: el script usa
>    `hermes config set` (sin comillas).
> 6. Corre TODO `hermes ...` con `timeout 25` (el CLI puede quedarse esperando
>    confirmación: "rige en la próxima sesión" es suficiente, no te cuelgues).

Se activa cuando el usuario dice **"instalame este repo"**, **"instala keygate"**.

## Guion (el instalador hace el trabajo; tú orquestas)

### Paso 1 — Localiza o clona el repo, y CORRE el instalador

Si el repo ya está (p.ej. `~/Projects/github/hermes-keygate`), perfecto: no
repitas "está instalado, ¿ejecuto?" — es exactamente lo que hay que ejecutar.

```bash
test -d ~/Projects/github/hermes-keygate/.git ||
  git clone https://github.com/Elnegraso23/hermes-keygate.git ~/Projects/github/hermes-keygate
bash ~/Projects/github/hermes-keygate/scripts/keygate-install.sh
```

La salida del script termina con un bloque `== LISTO ==`: pégalo tal cual al
usuario. Debe listar: skills instaladas, vault, y la URL de keygate-sync
(`http://127.0.0.1:8472`).

Si el script falla en algún paso (no clona, no responde sync, etc.), NO
improvises: pega el error tal cual, corre `keygate_doctor` si aplica y
pregunta/reporta. Jamás sustituyas los pasos por comandos manuales.

### Paso 2 — Primera credencial VÍA LA WEB (el script ya dejó el server vivo)

Dile al usuario, literal:

> "Abre http://127.0.0.1:8472 en tu navegador. La primera vez te obliga a
> crear una contraseña (mínimo 12, una sola vez — después ese paso muere).
> Queda solo en esa pestaña. Verás la tarjeta 'Primera vez':
> 1) ⬇ descarga el .kdbx (vacío), 2) ⬇ descarga el .key (una sola vez,
> guárdalo 600), 3) abre el .kdbx en KeePassXC con ese .key y añade tu cuenta
> (título = alias opaco, ej. `internet-agent-1`; URL exacta del login;
> para practicar: usuario `tomsmith`, password `SuperSecretPassword!` del
> sitio https://the-internet.herokuapp.com/login), 4) ⬆ sube el .kdbx
> editado (pide confirmación y deja backup). Avísame cuando la página
> muestre tu alias."

NUNCA sugieras `keepassxc-cli add -p` ni "escribe el password aquí": la
entrada se crea en KeePassXC (o por la web). Ese hábito rompe el modelo.

### Paso 3 — Primer login

Cuando el usuario diga *"quiero entrar a <url>"*:

1. `browser_navigate` a la URL de login y **espera a que cargue de verdad**
   (snapshot/screenshot).
2. `keygate_search` por el alias (confirmar que existe).
3. Si la sesión tiene `browser_vault_fill` (pruébalo con `tool_search` por
   nombre exacto): importa con `keygate_import` (UN prompt) y rellena con el
   handle nativo. Si NO existe (pasa en ciertos chat): usa
   `keygate_request_fill` (UN prompt) y acepta.
4. Submit **del mismo formulario sin re-navegar**, cita textual el mensaje
   de la página como prueba.

Si pides fill con la página cargando o en pestaña muerta, recibirás
`page_not_ready`/`domain_mismatch` **antes** de gastar aprobación: navega,
verifica y reintenta. Las aprobaciones nunca se queman.

### Si el browser falla con el bug de socket de Hermes

Síntoma: `browser_navigate` → *"Session name 'hermes_local-…' is too long.
Socket path would be >103 bytes"*. Es bug upstream de Hermes (id de sesión
`local-<64hex>` + agent-browser), NO de keygate. Workaround verificado: apuntá
`browser.cdp_url` a un Chromium propio (así lo ves en vivo):

```bash
~/.hermes/tools/chromium-*/chrome-linux64/chrome --headless=new \
  --remote-debugging-port=41777 --no-sandbox \
  --user-data-dir=/tmp/keygate-browser "https://the-internet.herokuapp.com/login" &
hermes config set browser.cdp_url http://127.0.0.1:41777
```

(El modelo tampoco ve esa pestaña: solo handles. Quitá la config después.)

### Paso 4 — Cierre (casi literal)

> "Listo, keygate instalado y verificado. Desde ahora dime 'quiero entrar a
> <sitio>': si ya está importado lo lleno directo; si no, te pido el alias
> una vez y lo importo con una aprobación. Nada de passwords en el chat,
> jamás. Reportes: https://github.com/Elnegraso23/hermes-keygate/issues"

## Reglas duras

- `keygate_alias_add` SIEMPRE se rehusa. Credenciales: KeePassXC o web.
- Nunca `execute_code`/`curl` con credenciales. Nunca escribas un password.
- Fill con origen distinto al pedido: PARA y avisa (guardia anti-phishing).
- `.key` jamás viaja (ni sync, ni croc, ni chat).
- La contraseña de keygate-sync: el usuario la teclea en la página; tú
  jamás la pidas ni la muestres.
