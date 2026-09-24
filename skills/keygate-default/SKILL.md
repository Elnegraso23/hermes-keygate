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

1. `browser_vault_list` — is there already a login for this origin?
   If yes, use native `browser_vault_fill` + submit. Done.
2. If not, ask the user for the KeePass **alias** (e.g. `github-agent-1`).
   Never ask for the username or password themselves.
3. Call `keygate_import` with that alias. It shows ONE approval prompt
   (`Allow import login ...?`) — wait for accept. It copies the entry into
   the encrypted local vault under label `keygate:<alias>`.
4. Then `browser_vault_fill` with the imported handle + submit the SAME form
   without re-navigating. Cite the page's status message.
5. If the site then asks for a verification code and the item has no TOTP
   seed, ask the user for the code (it never enters the conversation either).

## Hard rules

- `keygate_alias_add` is policy-blocked: credentials are never created from chat.
- Never `execute_code`/`curl` with credentials. Never type a password yourself.
- If a fill is refused for origin mismatch, STOP and tell the user (phishing guard).
- Strict mode (user explicitly wants per-fill approval): use
  `keygate_request_fill` instead of import+fill.
