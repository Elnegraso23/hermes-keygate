# 🔑 hermes-keygate — secure KeePassXC logins for Hermes Agent
[Español](README.md) · **English**
[![Version](https://img.shields.io/badge/version-0.6.6-orange.svg)](CHANGELOG.md) [![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-orange.svg)](LICENSE) [![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](README.en.md) [![Python: stdlib](https://img.shields.io/badge/python-stdlib%20only-blue.svg)](sync/keygate_sync.py) [![Tests: selftest 22/22](https://img.shields.io/badge/selftest-32%2F32-success.svg)](scripts/keygate-selftest.sh)

> **⚠️ ALPHA (v0.6.1) — fresh software, with known flaws.**
> Works on real machines but changes fast and sometimes breaks
> (skills that didn't load, quoted paths, mute buttons — all real,
> all fixed in public). **Do not use yet for critical accounts**:
> test with a test site or disposable accounts, report in
> [issues](https://github.com/Elnegraso23/hermes-keygate/issues) (what you expected,
> tool JSON, last lines of audit **without secrets**), and update
> often (`scripts/keygate-update`). As alpha software, any
> update can change behavior, tool names, or config format.

Hermes logs into your sites **without ever seeing your passwords**: you approve
in KeePassXC, a plugin injects them straight into the page. Inspired by
*1Password for Agents*, source-available and self-hosted.

## Table of Contents

- [How it works (30-second design)](#how-it-works-30-second-design)
- [Installation](#installation)
- [Adding accounts: via local page (normal way)](#adding-accounts-via-local-page-normal-way)
- [Per-account auto-approval (auto-fill)](#per-account-auto-approval-auto-fill)
- [Daily use (keygate is the default)](#daily-use-keygate-is-the-default)
- [Logins with redirect / OAuth (Google, Microsoft, GitHub...)](#logins-with-redirect--oauth-google-microsoft-github)
- [Sync to Hermes host (same PC or remote)](#sync-to-hermes-host-same-pc-or-remote)
- [Two machines with Tailscale (bot on server, you from your PC)](#two-machines-with-tailscale-bot-on-server-you-from-your-pc)
- [Regenerating the vault (corrupt, old, or starting from scratch)](#regenerating-the-vault-corrupt-old-or-starting-from-scratch)
- [If Hermes browser doesn't open (upstream socket bug)](#if-hermes-browser-doesnt-open-upstream-socket-bug)
- [Testing it (public test site)](#testing-it-public-test-site)
- [Update and tracking](#update-and-tracking)
- [Versions (alpha 0.x: everything can change)](#versions-alpha-0x-everything-can-change)
- [Plugin tools](#plugin-tools)
- [Repo structure](#repo-structure)
- [FAQ](#faq)
- [Honest limits](#honest-limits)

## How it works (30-second design)

```
You (KeePassXC GUI)                Hermes (model)              Plugin (your machine)
─────────────────                 ──────────────              ───────────────────
hermes.kdbx (keyfile,             requests "alias +           resolves user/pass
 no master)                       origin"                     via keepassxc-cli
      │                                   │                   in local memory
      │                          ┌────────┴────────┐                   │
      │                          │ your screen     │                   │
      │                          └────────┬────────┘                   │
      │                                   │                    YOU APPROVE on
      │                                   │                    KeePassXC prompt
      │                                   │                            │
      │                                   │                    injects via CDP
      │                                   │                    (only if tab URL
      │                           receives {success,           == item URL)
      │                           filled_fields}  ← NEVER the secret ──┘
```

**Guarantees:**

- Password/TOTP **never** enters the model context, logs, SQLite, Telegram, or audit (only hints `user@domain`). Test: `scripts/keygate-leakcheck.py` (PASS).
- No fill without explicit approval (fail-closed verified; neither timeouts nor errors approve). Approval comes last: live-tab pre-flight first. Only exception: an alias with an active auto-approval policy for that exact origin (see § Per-account auto-approval).
- Strict binding (vault-URL == requested origin == tab origin, re-checked inside script against TOCTOU).
- Each fill leaves a redacted audit trail (`~/.hermes/keygate-audit.jsonl`).
- Add/remove credentials **from chat are blocked by policy**: changes are made in your KeePassXC + `.kdbx` sync.

**Two vaults (the heart of the design):**

- `personal.kdbx` — your usual one (master + keyfile). Hermes **doesn't know or touch it**.
- `hermes.kdbx` — operational, **keyfile-only without master password** (no master password to steal/leak), only with copied entries, with opaque aliases (`site-agent-1`).

## Installation

> **🤖 If you are an agent installing this: run
> `bash <repo>/scripts/keygate-install.sh` and paste its output. Do NOT do the
> steps by hand or ask what step to follow: the script does everything (repo,
> plugin + skills, vault, config, sync) and ends with a `== READY ==` block.**
>
> The script is idempotent (you can re-run it), does not touch your personal vault,
> does not ask for or generate master passwords, and never receives credentials.

**Requirements:** `keepassxc` ≥ 2.7 (provides `keepassxc-cli` with `db-create`; the
preflight verifies it) + Hermes with local browser. Optional: `croc`
(remote sync without web only).

```bash
git clone https://github.com/Elnegraso23/hermes-keygate.git ~/Projects/github/hermes-keygate
cd ~/Projects/github/hermes-keygate
bash scripts/keygate-preflight.sh   # can this machine? (binaries, db-create, HOME, vault dir)
bash scripts/keygate-install.sh     # does everything; installer also runs preflight
# Flags: --reset (explicit total reset: web password + one-shot flag + vault
#          with backup) · KEYGATE_BIND=<IP> (default: auto-detects Tailscale)
```

What the installer does, step by step (by hand only if you insist):

1. clone/pull repo
2. copy `__init__.py` + `keygate_lib.py` + `plugin.yaml` + `skills/` (without `skills/` the plugin is MUTE: the agent receives no instructions)
3. `hermes plugins enable keygate`
4. `scripts/keygate-setup` → `~/.keepass-agent.key` (0600) + `~/Documents/hermes.kdbx` (keyfile-only, NO master) + isolated profile
5. `hermes config set` without quotes (manual approvals, `secrets.keepass` with paths, `browser.backend off`)
6. starts `keygate-sync` (systemd if available, otherwise process; binds Tailscale/localhost:8472).

Verification: `hermes plugins list | grep -i keygate` → `enabled`; in chat,
`keygate_status` must say `{locked:false, entries:0}`.

## Adding accounts: via local page (normal way)

The installer starts `keygate-sync` and sends you to the URL it prints
(`http://127.0.0.1:8472` or your Tailscale IP). First-time guide:
⬇ download the `.kdbx` (+ the `.key` once) → edit in KeePassXC
(copies with opaque aliases, exact URL, no notes/attachments) → upload the `.kdbx`
(confirmation + backup). Recommended aftermath: delete the copy (or close the DB).

Same-PC alternative (without web): open `~/Documents/hermes.kdbx` directly in
KeePassXC with `~/.keepass-agent.key`. Native sync — an agent that installs this should offer it FIRST, always.

## Per-account auto-approval (auto-fill)

If an account forces you to log in many times, you can mark **only that
account** so that filling does not prompt for approval. Configured from the web
interface of `keygate-sync`, with the same web password:

1. Open `http://<tailscale-ip>:8472/` and log in.
2. In **"Aliases & Auto-fill"**, each alias shows an *origin* field
   (pre-filled with the URL saved in the vault entry) and an
   **"Auto-approve"** checkbox.
3. Check the box and click **Save**.

Details and invariants:

- The policy lives in `~/.hermes/keygate-autofill.json` (0600, atomic write),
  one entry per alias: `{ "origin": "https://host", "enabled": true }`.
- On the next fill, if the alias has active policy **and the origin matches
  exact**, it fills without prompt and logs audit `approval: "auto-policy"` +
  `policy: "alias-auto"`.
- The origin is strictly `scheme://host:port`. Changing scheme,
  port, or subdomain **triggers approval again**.
- To prevent misuse, the web requires that the origin host matches the URL of the
  vault entry; otherwise, it responds `400 origin host does not match the
  vault entry URL`.
- Unattended sessions (cron / one-shot) are excluded: the policy does not
  enable headless logins.
- Revocation: uncheck on web (returns to normal prompt).

Risk you assume: while the policy is active, any fill for that alias
at the exact origin executes without you seeing it. Activate it only on accounts and
sitios you control; for critical accounts, keep the prompt.

## Daily use (keygate is the default)

The plugin installs the `keygate-default` skill: upon a *"log me in to <site>"*,
Hermes first checks the native vault; if the login is missing, it searches the **alias**,
it imports it with `keygate_import` (**one** approval) and fills with the flow
native (CDP preflight, bound tab). Afterwards, logging in is direct.

Ask in chat (new session after installing):

```text
Use browser_navigate to open <login-URL> in the agent's browser.
Then use tool_search to discover keygate_request_fill and call it with alias <alias> and origin <https://domain>. Wait for my approval before fill.
After a successful fill submit the SAME form without re-navigating and quote me the page message verbatim. Do not use chat history or execute_code/curl with credentials.
```

## Logins with redirect / OAuth (Google, Microsoft, GitHub...)

Works today, no extra code — with one condition: **all steps of the login live in ONE origin** (the provider's). Google: email and password
are typed at `https://accounts.google.com` (different pages, same origin;
normalized ignores path). The redirect back to your app has no fields
→ nothing to fill.

- KeePass entry with URL = provider origin
  (e.g. `https://accounts.google.com/`), opaque alias as always.
- Flow: one fill per step (email → next page → password), one approval
  each. Redirects within the origin break nothing.
- Cross-origin redirect is blocked **on purpose**: user in one origin and password in another
  (`domain_mismatch`). This is an anti-phishing defense, not a bug — no serious
  provider splits credentials across domains; if someone does, suspect.

Honest limits with Google in particular:

- **Bot detection**: a fresh/disposable Chromium usually hits *"This
  browser or app may not be secure"*. As discussed, the way is your real profile already
  logged in (attach via CDP), where there is nothing to fill.
- **Passkeys / Hardware 2FA**: cannot be injected by design. If 2FA prompts,
  automation stops and you take over as the prompt says.

## Sync to Hermes host (same PC or remote)

Always edit in your local KeePassXC. The operational one travels as ciphertext; the
`.key` **never travels** (generated on each machine, 0600). `keygate-sync` replaces
the file per call: the replacement applies without restarting. Same-PC sync = edit in
its place, without transferring anything.

**Primary: web `keygate-sync`** (Tailscale/LAN only, pure stdlib):

```bash
KEYGATE_DB=~/Documents/hermes.kdbx KEYGATE_KEYFILE=~/.keepass-agent.key KEYGATE_BIND=127.0.0.1 KEYGATE_PORT=8472 python3 ~/hermes-keygate/sync/keygate_sync.py
# NEVER bind 0.0.0.0.
```

### The password: created by you (no default)

There is no initial password or token file: when opening the page for the first
time IT FORCES you to create it (minimum 12 characters, once — after that that
endpoint dies with 403; to change it: `POST /api/reset-password` with the
current one). Stored with PBKDF2-HMAC-SHA256 + salt in
`~/.hermes/keygate-sync-pass` (0600); in your browser it lives only in the
`sessionStorage` of that tab.

- **No admin/admin window**: no guessable default exists; visiting
  without password only lets you create it, locks everything else (403 to the rest).
- **Never via Telegram/chat**: would remain in history and Telegram servers
  (reason why passwords never travel).
- **Security model**: against a reader with terminal on the host, password and token tie
  (can read the vault direct, web is redundant). The web password protects REMOTO
  web access without leaving secrets on disk.

Endpoints: `/api/setup-state` (public) · `/api/reset-password` `{current, new}`
· `/api/health` (unauthenticated) · `/api/aliases` redacted ·
`GET /api/download` (round-trip without terminal) · `POST /api/upload` (validates
KDBX+keyfile, anti-wipe, backup+atomic replacement) · `/api/onboarding/keyfile`
(**once**, then 410) · `/api/audit`. All with Bearer except public ones.

**Fallback: `croc`** — `scripts/keygate-push [--dry-run]` on your PC and
`scripts/keygate-pull <CODE>` on the host (validates, backup×5, atomic,
refuses `*.key` always).

## Two machines with Tailscale (bot on server, you from your PC)

Typical pattern: you talk to Hermes via **Telegram** (its gateway runs on a
server, e.g. `HOME=/opt/hermes`) and edit the vault from your PC. Once on
the same tailnet:

**On the bot server** (via Telegram chat, without delegating):

```bash
# 1. Prerequisites: git, python3, keepassxc-cli (keepassxc), curl, tailscale
tailscale ip -4 | head -1                                  # = server IP
# 2. Complete installation ON THE SERVER (installer pulls by itself and
#    auto-detects Tailscale IP for bind):
bash ~/Projects/github/hermes-keygate/scripts/keygate-install.sh
# 3. Browser workaround (Hermes socket bug): see section below.
ls ~/.hermes/tools/ | grep chromium                        # real binary path
```

**From your PC** (any browser on the tailnet):

```text
http://100.x.y.z:8472   → create password (first visit), download the
.key ONCE (keep 600 here), download .kdbx, edit in KeePassXC, upload.
```

Rules to remember:

- **The operational vault lives on the server** (where Hermes runs). Never expose web; Tailscale/LAN only.
- **The `.key` of each machine never travels**: the server's is generated there and
  stays there. The one you download to your PC is for editing; if you lose it, regenerate it locally (`keygate-setup`) and re-upload.
- **Real credentials, one single home**: do not keep two "active" vaults.
  The other team can keep the plugin disabled.
- **Backups, sync and `.key` never via Telegram/chat**: remain in
  history and platform servers.

## Regenerating the vault (corrupt, old, or starting from scratch)

```bash
bash scripts/keygate-setup --force
```

Moves current DB to `hermes.kdbx.corrupt-<timestamp>` (**never deletes in
silence**, and `*.bak` rotation doesn't touch it) and creates a new one. The `.key` is
**reused**: the one you downloaded once still opens the new one, so
onboarding doesn't need repeating. Sync picks up changes without restarting the service.

```bash
bash scripts/keygate-setup --reset-key   # lost your .key copy: allows
                                         # downloading it ONCE more (local action
                                         # explicit; web won't let you download it again)
bash scripts/keygate-install.sh --reset  # TOTAL RESET: deletes web password +
                                         # one-shot flag + replaces vault
                                         # (with backup). Default: safe.
```

Uninstall: `hermes plugins disable keygate`, deletes
`~/.hermes/plugins/keygate/`, config block, and (if you want)
DB/keyfile/pass/audit. Hermes core remains.

## If Hermes browser doesn't open (upstream socket bug)

Symptom: `browser_navigate` fails with *"Session name 'hermes_local-…' is too
long. Socket path would be >103 bytes"*. It's a Hermes bug (its session ID
grew to `local-<64hex>` and agent-browser binary builds a long Unix socket);
**it's not keygate**. Keygate fill doesn't touch it, but needs a live tab.

Verified workaround (filled fields and password never touched LLM/logs): override `browser.cdp_url` to a custom Chromium that **you** control — this way you also SEE the login live.

**Durable (recommended): Chromium as user systemd service** —
survives chat closures and reboots (with `lingering`):

```ini
# ~/.config/systemd/user/hermes-cdp-chromium.service
[Unit]
Description=Headless Chromium for Hermes CDP (endpoint for browser.cdp_url / keygate fills)
After=default.target
[Service]
Type=simple
ExecStart=/home/YOUR-USER/.hermes/tools/chromium-1208/chrome-linux64/chrome   --headless=new --remote-debugging-port=9222   --remote-debugging-address=127.0.0.1   --user-data-dir=/home/YOUR-USER/.local/share/hermes-cdp/profile   --no-first-run --no-default-browser-check --disable-gpu about:blank
Restart=always
RestartSec=3
# Dedicated disposable profile: no extensions, bookmarks or cookies.
[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now hermes-cdp-chromium.service
loginctl enable-linger   # starts at boot without open session
hermes config set browser.cloud_provider local
hermes config set browser.cdp_url http://127.0.0.1:9222
# Useful: systemctl --user status hermes-cdp-chromium.service
#         journalctl --user -u hermes-cdp-chromium -n 50
```

**Temporal (one test):** launch Chromium by hand with
`--remote-debugging-port=41777` and `hermes config set browser.cdp_url
http://127.0.0.1:41777` (tested in chat; remove line afterwards).

Honest: the override skips Hermes local stack completely — the model
doesn't see that tab either (only handles), and you see everything.

## Testing it (public test site)

If you don't want to test with real accounts: [the-internet login](https://the-internet.herokuapp.com/login)
(user `tomsmith`, pass `SuperSecretPassword!` — public, printed on page):

```bash
printf 'SuperSecretPassword!\n' | keepassxc-cli add -k ~/.keepass-agent.key   --no-password -q ~/Documentos/hermes.kdbx internet-agent-1   -u tomsmith --url https://the-internet.herokuapp.com/login -p
```

(NOTE: this injects a credential via shell history — only acceptable
because they are public. Real ones go via web or sync, never via
terminal/chat.)

Then the daily use prompt with `alias internet-agent-1` and
`origin https://the-internet.herokuapp.com`. Expected result =
`You logged into a secure area!` + audit `allow` + `approval: accept`.

## Dependency: keepassxc-cli (hardened, H10)

keygate does **not** implement its own crypto and ships no binaries: it uses the
system `keepassxc-cli` as the **cryptographic boundary**, so you inherit your
distro's security patches instead of hand-rolled AES/Argon2.

Since 0.6.3 the binary is resolved deterministically and validated **before**
execution:

1. `KEYGATE_KXC_BIN` (absolute path). If set and invalid/insecure it fails
   closed and does **not** fall back to another binary.
2. Canonical paths: `/usr/bin`, `/usr/local/bin`, `/snap/bin`,
   `/Applications/KeePassXC.app/Contents/MacOS`, `/opt/homebrew/bin`.
3. `PATH`.

Checks: regular executable file, **not group/world-writable**, owned by `root`
or your uid, and parent directory not group/world-writable (`/tmp` only with the
sticky bit and only when both the binary and the directory are yours).

```bash
scripts/keygate-doctor      # or: python3 keygate_lib.py --doctor
```

Returns `kxc_found`, `kxc_path`, `kxc_source` (`env:KEYGATE_KXC_BIN` |
`system_path` | `missing`), `kxc_permissions_ok`, `kxc_version`,
`kxc_version_ok` (minimum 2.7.0) and an `install_hint` for your distro.
The same block is included in `keygate_doctor`.

**Flatpak:** the `org.keepassxc.KeePassXC` export is the GUI, not the CLI. Wrap
`flatpak run --command=keepassxc-cli org.keepassxc.KeePassXC` and point
`KEYGATE_KXC_BIN` at that wrapper.

## Update and tracking

```bash
bash ~/hermes-keygate/scripts/keygate-update   # pull + installs + verifies; applies next session
```

- If an update brings `.kdbx`/`.key`, **aborts** without touching anything.
- Issues: [github.com/Elnegraso23/hermes-keygate/issues](https://github.com/Elnegraso23/hermes-keygate/issues)
  (what you expected, tool JSON, last lines of audit **without secrets** —
  there is a [template](.github/ISSUE_TEMPLATE/bug_report.md)).
- Rule: fixes only touch code/docs, never user data.

## Versions (alpha 0.x: everything can change)

- Version lives in `plugin.yaml` (`keygate_version` reports it: installed
  vs repo + changelog; model warns you of updates).
- Since 0.4.0 the plugin also queries GitHub (raw `plugin.yaml` from main)
  even if you don't have a clone: 1 public GET, stdlib, 10s timeout, cached 24h in
  `~/.hermes/keygate-version-check.json`. Without network responds `unknown` without
  breaking anything. If newer major/minor, `update_available: true` + `update_hint`.
- Alpha status: `0.x.y` without promises — `x` can rename tools, change config or
  auth flow. Pin version before updating if anything matters to you.
- `1.0` will arrive when the complete flow (install → first account via web →
  login → sync) works three times in a row without author manual intervention.
  Until then, assume failures and report.
- Tags `v0.x.y` mark each release on GitHub; the updater does `pull --ff-only`
  and leaves `.installed_commit` marker on your installation.

## Plugin tools

| Tool | What it does | Secrets |
|---|---|---|
| `keygate_search` | searches alias, lists redacted entries | never values |
| `keygate_request_fill` | approval + blind fill via CDP | only `{success, filled_fields}` |
| `keygate_import` | copies ONE entry (1 approval) | opaque handle, nothing else |
| `keygate_status` | locked DB + count | count |
| `keygate_doctor` | version, DB, channel, browser transport, audit | redacted |
| `keygate_version` | installed vs GitHub + changelog | versions |
| `keygate_session_ensure/invalidate` | ephemeral sessions with TTL | opaque handles |
| `keygate_alias_add` | **always refused by policy** | — |
| `KeepassSource keepass` | refs `kpx://alias/field` for API keys | via native SecretSource |

## Repo structure

```text
hermes-keygate/
├── __init__.py          # plugin: SecretSource + 9 tools + skills registry
├── keygate_lib.py       # redaction, keepassxc-cli, sessions, audit, paths
├── plugin.yaml          # manifest (canonical version)
├── skills/
│   ├── keygate-default/ # daily login flow (for the model)
│   └── keygate-install/ # zero-to-hero installation (for the model)
├── sync/
│   └── keygate_sync.py  # sync web (pure stdlib: aliases/download/upload/…)
├── scripts/
│   ├── keygate-install.sh   # one-pass: repo→plugin→vault→config→sync
│   ├── keygate-update       # pull + installs + verifies (fail-closed)
│   ├── keygate-setup        # vault keyfile-only [--force/--reset-key]
│   ├── keygate-preflight.sh # can this machine? (fails cheap and clear)
│   ├── keygate-selftest.sh  # 22 regressions in simulated fresh host
│   ├── keygate-leakcheck.py # canary: no secret in logs/audit/SQLite
│   ├── keygate-push/pull    # croc sync (fallback without web)
│   └── keygate-fetch        # (utility)
├── PRIMERA-VEZ.md       # phrase-by-phrase user guide
├── CHANGELOG.md         # what each version brought
├── SECURITY.md          # how to report holes
└── config.keygate.example.yaml
```

## FAQ

**Did the bot install in `/opt/hermes` and I expected `/home/...`?**
Not a bug: you are talking to a Hermes running on **another machine** (its gateway is
not your PC). Each installation lives where its operator lives: plugin, vault and config
go with the `HOME` of whoever executes. Recommendation: use **one single home** for real
credentials (recommended: the machine you talk to daily) and disable the plugin on the other.

**Why does it ask for approval twice?**
One for `keygate_import` (copying from KeePass to vault, once in the life of the
account) and one for `keygate_request_fill` (CDP fill). With native ones
(`browser_vault_fill`) the second prompt does not exist; where not granted,
1 approval per login is the contract.

**Does the web show old data after regenerating the vault?**
Hard reload (Ctrl+Shift+R): the page is a static shell and the DOM
may predate the replacement. If in doubt, compare dates with
`ls -la ~/Documents/` and check that the service points to the correct path
(`systemctl --user show keygate-sync.service -p Environment`).

**Can I use my `personal.kdbx`?**
No, by design: Hermes must never touch your main vault. `keygate-setup` creates a
secondary dedicated operational vault and copies only the entries the
agent can use.

**How do I change the web sync password?**
`POST /api/reset-password` with the current one. To reset completely: delete
`~/.hermes/keygate-sync-pass` on the host (local shell) and the first visit lets
you create another. Never via Telegram/chat.

## Honest limits

- Plugin runs in-process (agent privilege): the guarantee is "never to LLM/logs",
  not sandbox against root/local malware.
- `fill` requires supervised browser session; TOTP: resolves seeds stored in entry;
  end-to-end test with real 2FA account pending.
- `fetch()` from SecretSource only hydrates `kpx://` refs you map: don't map
  the whole vault, only necessary API keys.

## License

**PolyForm Noncommercial 1.0.0.** You may use, modify and share keygate for any
**noncommercial** purpose: personal use, study, research, and internal projects
without commercial advantage. You may **not** sell it, resell it, or offer it as
a paid service without a separate commercial license.

This is not an OSI license (it restricts commercial use). The code remains
public, auditable and self-hosted. Versions published up to v0.6.1 under MIT
stay MIT for whoever already downloaded them; this change applies going forward.

## Contributing

Found a bug or want to send a patch? Note: **pull requests are closed for now** — use issues or Discussions. Read **[CONTRIBUTING.md](CONTRIBUTING.md)**
(Spanish; PRs in English are welcome too). Security issues go through
**[SECURITY.md](SECURITY.md)**, not a public issue. Signed commits are welcome but
not required.
