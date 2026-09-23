# hermes-keygate — blind KeePassXC injector (Plan A)

Solo la integración KeePass↔Hermes. Sin vault nuevo, sin cripto nueva, sin nube.

- Vault frío: tu `personal.kdbx` (master+keyfile, Hermes no lo conoce).
- Vault operativo: `hermes.kdbx` **keyfile-only, sin master** (sacrificial, solo copias con alias `gh-agent-1`).
- Hermes pide `alias + origin` → tú apruebas en CLI/Telegram (`once/sesión/deny/swap`) → el plugin resuelve vía `keepassxc-cli --no-password -k KEYFILE` en memoria del proceso e inyecta por CDP supervisado **solo si `tab.url == item.URL`**. Retorno al modelo: `{ok, filled_fields}`. Password/TOTP jamás en contexto, logs, SQLite o Telegram (solo hints `j***@x.com`).

## 1. Instalar (procedimiento validado de cero)

Requisitos: `keepassxc` (aporta `keepassxc-cli`), `croc` (opcional, solo sync remoto sin web),
Hermes Agent con browser local.

```bash
# 1. Vault operativo keyfile-only (SIN master: Hermes nunca recibe password maestra)
bash ~/hermes-keygate/scripts/keygate-setup
# crea ~/.keepass-agent.key (0600) + ~/Documentos/hermes.kdbx + perfil ~/.config/keepassxc-agent.ini

# 2. Plugin
mkdir -p ~/.hermes/plugins/keygate
cp ~/hermes-keygate/__init__.py ~/hermes-keygate/keygate_lib.py ~/hermes-keygate/plugin.yaml ~/.hermes/plugins/keygate/
hermes plugins enable keygate   # rige en la próxima sesión

# 3. Config en ~/.hermes/config.yaml (a mano, sin secretos):
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
    db_path: "/home/tu-usuario/Documentos/hermes.kdbx"
    keyfile: "/home/tu-usuario/.keepass-agent.key"
    timeout_seconds: 30
    env: {}
browser:
  backend: "off"        # tools browser_* built-in (browser_navigate), no Browser Use cloud
  use_real_profile: false  # Chromium empaquetado, no exige tu navegador por defecto
# allow_private_urls déjalo en false (default): el agente no toca loopback/red privada.
```

```bash
# 4. Verificar (sin modelo, sin browser):
hermes plugins list | grep -i keygate   # -> enabled
# keygate_status en tu próximo chat debe decir {locked:false, entries:0}

# 5. Web de sync (opcional, Tailscale/LAN; genera token largo):
openssl rand -hex 24 > ~/.hermes/keygate-sync-token && chmod 600 ~/.hermes/keygate-sync-token
KEYGATE_DB=~/Documentos/hermes.kdbx KEYGATE_KEYFILE=~/.keepass-agent.key \
KEYGATE_SYNC_TOKEN="$(cat ~/.hermes/keygate-sync-token)" \
KEYGATE_BIND=127.0.0.1 KEYGATE_PORT=8472 \
python3 ~/hermes-keygate/sync/keygate_sync.py
# abre http://127.0.0.1:8472 (por Tailscale: tu-ip-tailscale:8472). NUNCA 0.0.0.0.
```

Desinstalar: `hermes plugins disable keygate`, borra `~/.hermes/plugins/keygate/`,
el bloque de arriba de `config.yaml`, y (si quieres) DB/keyfile/token/audit.
Nada queda en Hermes.

## 2. Dar cuentas (30s c/u, manual = seguridad)

KeePassXC personal → duplicar ítem → mover copia a `hermes.kdbx` → renombrar `gh-agent-1`, URL exacta, TOTP si toca, sin notas/adjuntos. Quitar = borrar copia o cerrar DB.

## 3. Uso diario

- `keygate_status` → `{locked, entries}` (conteo).
- `keygate_search("gith")` → `[{alias: gh-agent-1, hint: g***-1 (j***@x)}]`.
- Agente llama `keygate_request_fill(alias, origin)` → Telegram: `e*******.com pide g***-1 [once/sesión/deny]` → apruebas → fill + TOTP auto → `{success:true}`.
- Efímeras: `keygate_session_ensure(domain, ttl)` reutiliza handle opaco en tmpfs (`/dev/shm/hermes-keygate`, 0700); ante 401 → `keygate_session_invalidate(domain)` y re-aprobación. Nunca reintenta con vencidas.
- Auto-lock: operativo 8h + lock en screen-lock/suspend; personal 60s. Si bloqueado: `esperando desbloqueo local`, fail-closed.

## 4. Remoto seguro

Sin mandar maestras: vault operativo donde corre Hermes (`hermes-remote.kdbx` mínimo), o `ssh -L` al socket local + click local. Nunca pegar master/keyfile por Telegram.

## 5. Pruebas anti-fuga

```bash
python3 -m pytest ~/hermes-keygate/tests/ -q
grep -ri "password" ~/.hermes/plugins/keygate/__init__.py | grep -v "never\|password/TOTP\|no password" || true
# tras 1 fill: grep -r "<tu-password-real>" ~/.hermes/state.db ~/.hermes/logs/ → debe dar 0
tail ~/.hermes/keygate-audit.jsonl
```

## 6. Sync al host Hermes (local + remoto)

Edita siempre en tu KeePassXC local. El operativo viaja como ciphertext;
el `.key` **jamás viaja** (vive quieto en cada máquina, 0600). keygate lee
el archivo por llamada: el reemplazo aplica sin reiniciar.

**Modo local** (misma máquina): no transfieras nada, edita en su sitio.

**Modo remoto — primario: web `keygate-sync`** (solo Tailscale/LAN):

```bash
KEYGATE_DB=~/Documentos/hermes.kdbx KEYGATE_KEYFILE=~/.keepass-agent.key \
KEYGATE_SYNC_TOKEN='<token-largo>' KEYGATE_BIND=127.0.0.1 KEYGATE_PORT=8472 \
python3 ~/hermes-keygate/sync/keygate_sync.py
# NUNCA bindees 0.0.0.0 — llega por Tailscale. Sin token (>=16) no arranca.
```

* `/` estado, `/api/aliases` hints redactados, `POST /api/upload` (valida
  KDBX+keyfile, rehúsa vacíos anti-wipe, backup+reemplazo atómico),
  `/api/onboarding/keyfile` (**una sola vez**, luego 410), `/api/audit`.
  Todo con `Authorization: Bearer`. Bajas: se hacen borrando en tu KeePassXC
  local y re-subiendo (reemplazo total, sin borrados remotos sueltos).
* Onboarding inicial: descarga el `.key` **una vez** por la web (Tailscale),
  guárdalo 0600 en tu PC editor. Después ese endpoint muere.

**Modo remoto — fallback: `croc`** (sin Tailscale/red especial):

```bash
# tu PC:  scripts/keygate-push [--dry-run]   → imprime sha256 + código
# host:   ssh por tailscale → scripts/keygate-pull <CODIGO> [--dry-run]
# pull valida (abre con keyfile, >=1 entrada), backup (retiene 5),
# reemplazo atómico y verificación. Rehúsa paths *.key siempre.
```

**Telegram**: sin altas ni bajas desde el chat. `keygate_alias_add`
**siempre rechazada por política** (las credenciales nunca salen del chat);
los cambios se hacen en tu KeePassXC local + sync del `.kdbx`.

## Límites honestos

- Plugin corre in-process (privilegio de agente): la garantía es "nunca al LLM/logs", no sandbox contra root/malware local.
- `fill` exige sesión de browser supervisada abierta; sin ella rehúsa antes que filtrar por argv.
- `fetch()` de SecretSource hidrata env al arranque (solo refs `kpx://` que mapees): no mapees todo el vault, solo API keys necesarias.
