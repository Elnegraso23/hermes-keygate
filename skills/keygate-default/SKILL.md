---
name: keygate-default
description: "Site logins come from the user's KeePass vault via keygate. Use for any 'log into <site>' task."
version: 0.1.0
license: MIT
platforms: [linux, macos, windows]
---

# Keygate: KeePass Is the Default Login Source

When the user asks to log into a website, credentials come from their
KeePass operative vault (`hermes.kdbx`) through keygate — never typed,
never pasted, never in chat.

## Flow (follow in order)

1. `keygate_lookup(origin)` — resolves the page to its alias in ONE call and
   reports whether auto-fill is on (i.e. whether an approval prompt will
   appear). Never guess an alias.
2. Alias found and `auto_fill: true` → `keygate_request_fill(alias, origin)`.
   No prompt is shown; the fill happens server-side over CDP.
3. `auto_fill: false` → send the user the link from `keygate_link(alias)` and
   ask them to enable auto-fill there, instead of burning one approval per
   login. The page keeps its own access password and never shows or accepts
   site passwords.
4. No alias mapped → ask the user for the KeePass **alias** (e.g.
   `github-agent-1`), never for the username or password, then `keygate_import`
   with that alias. It records a secret-free pointer (`keygate-index.json`,
   origin → alias) and copies nothing.
5. Back to step 2. If the site asks for a verification code, resolve it from
   KeePass (TOTP field) or ask the user — it never enters the conversation.

## Hard rules

- **The Hermes native vault is not part of the login path.** With the plugin
  installed, `browser_vault`, `browser_vault_fill` and `save_login` are
  off-limits for credentials; all login work belongs to keygate.
- `keygate_import` never writes to the native vault: `vault_sync` defaults to
  false and only `vault_sync: true` / `KEYGATE_VAULT_SYNC=1` re-enables the old
  mirroring.
- `store_mode` defaults to `live` (no copy anywhere). `mirror` keeps an
  encrypted copy in keygate's own store (key, or key+passphrase via
  `scripts/keygate-store`).
- `keygate_alias_add` is policy-blocked: credentials are never created from chat.
- Never `execute_code`/`curl` with credentials. Never type a password yourself.
- If a fill is refused for origin mismatch, STOP and tell the user (phishing guard).
- Origin matching is strict: `http://` vs `https://`, a suffix or a prefix all
  fail on purpose.
- A DB master password (`KEYGATE_DB_PASSWORD`) travels on stdin only — never in
  argv, never in chat.
