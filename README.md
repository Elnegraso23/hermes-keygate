# 🔑 hermes-keygate — logins ciegos de KeePassXC para Hermes Agent

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

```bash
# Requisitos: keepassxc (aporta keepassxc-cli) + Hermes Agent con browser local.
# Opcional: croc (solo sync remoto sin web).

# 1. Clona e instala el plugin
git clone https://github.com/Elnegraso23/hermes-keygate.git ~/hermes-keygate
mkdir -p ~/.hermes/plugins/keygate
cp ~/hermes-keygate/__init__.py ~/hermes-keygate/keygate_lib.py ~/hermes-keygate/plugin.yaml ~/.hermes/plugins/keygate/
hermes plugins enable keygate   # rige en la próxima sesión

# 2. Crea el vault operativo (SIN master: Hermes nunca recibe password maestra)
bash ~/hermes-keygate/scripts/keygate-setup
# → ~/.keepass-agent.key (0600) + ~/Documentos/hermes.kdbx + perfil ~/.config/keepassxc-agent.ini

# 3. Configura ~/.hermes/config.yaml (sin secretos):
plugins:
  enabled:
    - keygate
approvals:
  mode: manual
  timeout: 60
  cron_mode: deny
  single_query_mode: deny
secrets:
  keepass:
    enabled: true
    db_path: "/home/TU-USUARIO/Documentos/hermes.kdbx"
    keyfile: "/home/TU-USUARIO/.keepass-agent.key"
    timeout_seconds: 30
    env: {}
browser:
  backend: "off"            # tools browser_* built-in, no Browser Use cloud
  use_real_profile: false   # Chromium empaquetado, no exige tu navegador
# allow_private_urls déjalo en false: el agente no toca loopback/red privada.

# 4. Verifica (sin modelo ni browser):
hermes plugins list | grep -i keygate   # → enabled
# En tu próximo chat, keygate_status debe decir {locked:false, entries:0}
```

Desinstalar: `hermes plugins disable keygate`, borra `~/.hermes/plugins/keygate/`,
el bloque de config, y (si quieres) DB/keyfile/token/audit. Nada queda en Hermes.

## Dar cuentas (30s c/u, manual = seguridad)

En KeePassXC: duplica un ítem de tu personal → muévelo a `hermes.kdbx` →
renómbralo a alias opaco (`github-agent-1`) → URL exacta del login → sin
notas/adjuntos → guarda. Quitar acceso = borrar la copia (o cerrar la DB).

## Uso diario

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
openssl rand -hex 24 > ~/.hermes/keygate-sync-token && chmod 600 ~/.hermes/keygate-sync-token
KEYGATE_DB=~/Documentos/hermes.kdbx KEYGATE_KEYFILE=~/.keepass-agent.key \
KEYGATE_SYNC_TOKEN="$(cat ~/.hermes/keygate-sync-token)" \
KEYGATE_BIND=127.0.0.1 KEYGATE_PORT=8472 \
python3 ~/hermes-keygate/sync/keygate_sync.py
# NUNCA bindees 0.0.0.0. Sin token (>=16) no arranca.
```

### El token: dónde está y cómo conseguirlo (local y remoto)

La web te pedirá `Token de keygate-sync`: es su contraseña. Vive **solo** en
el host, archivo `0600` — pégalo desde ahí:

```bash
cat ~/.hermes/keygate-sync-token
```

* Queda en `sessionStorage` de esa pestaña, en ningún disco más.
* **Remoto sin acceso a archivos**: un SSH por Tailscale, corre ese mismo
  `cat`, guarda el token en el gestor de tu móvil. Una sola vez, para siempre.
* **Jamás por Telegram/chat**: quedaría en historial y servidores de Telegram
  (la misma razón por la que nunca viajan passwords).
* El servidor al arrancar te dice *dónde* está el token; nunca lo imprime ni
  lo loguea.

`/api/aliases` redactados · `POST /api/upload` (valida KDBX+keyfile, rehúsa
vacíos anti-wipe, backup+reemplazo atómico) · `/api/onboarding/keyfile`
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

## Límites honestos

- El plugin corre in-process (privilegio de agente): la garantía es "nunca al
  LLM/logs", no sandbox contra root/malware local.
- `fill` exige sesión de browser supervisada; sin ella rehúsa antes que filtrar.
- TOTP: resuelve semillas guardadas en la entrada; pendiente prueba end-to-end
  con cuenta real con 2FA.
- `fetch()` de SecretSource solo hidrata refs `kpx://` que mapees: no mapees
  todo el vault, solo API keys necesarias.
