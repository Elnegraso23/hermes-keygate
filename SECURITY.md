# Seguridad — hermes-keygate

Este proyecto es **alfa**: la superficie cambia rápido. Esta política dice
cómo reportar y qué esperar.

## Cómo reportar

- **Agujero con impacto real** (ejecución remota, bypass de aprobación,
  exfiltración de secretos al modelo/logs): **NO lo publiques**. Abrí un
  [GitHub Security Advisory](https://github.com/Elnegraso23/hermes-keygate/security/advisories)
  privado o escribí al dueño del repo por el canal que tengas. Incluye: versión
  (`keygate_version`), pasos mínimos, y qué esperabas vs qué pasó. **Nunca
  pegues passwords, TOTP, `.key`, ni el contenido del vault** — ni siquiera
  redactado a medias: los hints (`i**************1`) alcanzan.
- **Todo lo demás** (bugs, UX, docs): [issue público](https://github.com/Elnegraso23/hermes-keygate/issues)
  con la [plantilla](.github/ISSUE_TEMPLATE/bug_report.md).

No hay bug bounty. Se agradece en el CHANGELOG.

## Qué está en scope

- `sync/keygate_sync.py` (web: auth, upload, download, one-shot `.key`)
- `__init__.py` + `keygate_lib.py` (límites modelo/secreto, redacción, audit)
- `scripts/` (instalación, updates, reset — nunca deben tocar tu vault personal)

## Qué NO es vulnerabilidad (diseño declarado)

- Un lector con **terminal en el host** puede leer el vault directo: la
  garantía es "nunca al LLM/logs", no sandbox contra root/malware local
  (ver "Límites honestos" en el README).
- El **identificador** (usuario/email) es metadata visible al modelo por
  diseño del vault nativo; solo el password/TOTP es secreto.
- `GET /api/health` y `/api/setup-state` son públicos a propósito (monitoreo).
- Denegar aprobaciones no es un bug: es el sistema funcionando (fail-closed).

## Higiene del repo

- `.gitignore` bloquea `*.kdbx`, `*.key`, `*-audit.jsonl`: un vault o secreto
  **nunca** debe llegar a un commit. `keygate-update` aborta si un rango trae
  esas extensiones.
- Los tests (`keygate-selftest.sh`, `keygate-leakcheck.py`) corren contra
  vaults temporales con centinelas, jamás contra tu vault real.
