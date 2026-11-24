# AGENTS.md — Instructions for AI Agents working on hermes-keygate

## Quick Install (when a user asks "instalame este repo")
Run the one-shot installer and paste its output (never improvise manual steps):
```bash
bash scripts/keygate-install.sh
```
For detailed agent flows, read [skills/keygate-install/SKILL.md](skills/keygate-install/SKILL.md) and [skills/keygate-default/SKILL.md](skills/keygate-default/SKILL.md).

## Updating a Live Installation
```bash
bash scripts/keygate-update
```
This pulls `--ff-only`, validates syntax, copies `__init__.py`, `keygate_lib.py`, `plugin.yaml`, `keygate_web.py`, `keygate_vault.py`, `sync/keygate_sync.py`, and `skills/` into `~/.hermes/plugins/keygate`, and restarts `keygate-sync.service` if active. It NEVER touches `.kdbx` or `.key` files.

## Running Tests
Always run pytest via the wrapper script (it runs from `tests/` so root `__init__.py` does not require the Hermes runtime):
```bash
bash scripts/keygate-test
bash scripts/keygate-selftest.sh < /dev/null
python3 scripts/keygate-leakcheck.py
```

## Non-Negotiable Security Invariants
1. **Secrets never enter model context, chat history, logs, audit, or argv.** Passwords are generated server-side via `keepassxc-cli -g` or supplied via `stdin` only in authenticated web routes, and zeroized in memory.
2. **Strict exact-origin binding.** Always validate with `keygate_lib.normalize_origin()` / `origins_match()`. Never allow substring/suffix matches or `http`↔`https` downgrades.
3. **Fail-closed everywhere.** Vault sealed (`vault_sealed()`), DB locked (`db_locked()`), or unwritable audit (`AuditError` on `audit(..., strict=True)`) must abort immediately.
4. **Atomic DB writes.** Acquire `keygate_lib.db_lock(db)` (`flock`), stage on the **same filesystem** as the `.kdbx` (never `/tmp` — avoids `EXDEV`), verify anti-wipe (`>= 1` entry), rotate backups (`backup_db(keep=5)`), `os.replace()`, and enforce `0600`.
5. **CSP nonce hygiene in `sync/keygate_sync.py`.** Never add inline `style=""` attributes or inline JS event handlers (`onclick`, `onchange`). Use CSS classes and delegated `data-act` / `data-oninput` / `data-enter` listeners.
6. **Never touch `~/.hermes/config.yaml` by hand** (use `hermes config set`) and **never use the native Hermes `browser_vault`** unless `vault_sync: true` is explicitly configured.
