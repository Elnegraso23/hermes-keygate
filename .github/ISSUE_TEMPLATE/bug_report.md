---
name: Bug report
about: Reportar un fallo de hermes-keygate (sin secretos)
title: "[bug] "
labels: bug
---

## Qué esperabas

<!-- una línea: el comportamiento correcto -->

## Qué pasó

<!-- una línea: el comportamiento real -->

## Evidencia (SIN secretos — jamás pegues passwords, TOTP, `.key` ni contenido del vault)

- Versión (`keygate_version` → installed_version):
- Tool y JSON de respuesta (recortado, hints como `i**************1` están bien):
- Últimas líneas del audit (`tail ~/.hermes/keygate-audit.jsonl`):
- `keygate_doctor` (si aplica):

## Contexto

- Instalación: [ ] script `keygate-install.sh` / [ ] manual / [ ] update
- Dónde corre Hermes: [ ] misma PC / [ ] servidor remoto (Telegram) / [ ] otro:
- Browser: [ ] Chromium propio por `cdp_url` / [ ] agent-browser local / [ ] cloud:
