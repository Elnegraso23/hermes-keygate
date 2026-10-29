# Contribuir a hermes-keygate

> **Estado: contribuciones cerradas por ahora.** No se aceptan pull requests.
> Los PRs que lleguen se cierran automáticamente con un mensaje. Sí se aceptan
> **issues** (bugs, riesgos) y **Discussions** (ideas, preguntas). Si traes un
> parche, pégalo como diff dentro del issue y se revisa ahí.

Gracias por querer aportar. Este proyecto es alfa y pequeño: un issue bien escrito
vale tanto como un PR.

**Regla de oro:** nunca pegues contraseñas, tokens, semillas TOTP ni el contenido
de tu vault en un issue, un PR o un comentario. Si el reporte necesita un dato
sensible, descríbelo (forma, longitud, qué campo) en vez de copiarlo.

## Reportar un bug

Abre un issue con la plantilla de bug. Incluye:

- Versión (`keygate_version` o el badge del README) y cómo instalaste.
- Sistema operativo, versión de `keepassxc-cli` y de Python.
- Qué esperabas que pasara y qué pasó.
- El **JSON de la tool** que falló, con los valores redactados.
- Las últimas líneas del audit (`~/.hermes/keygate-audit.log`), **sin secretos**.
- Si es reproducible: los pasos mínimos.

Si el fallo es de seguridad (fuga de credenciales, bypass de aprobación, ejecución
no autorizada), **no abras un issue público**: sigue `SECURITY.md`.

## Si quieres proponer un parche

Estas pruebas son las que hay que pasar antes de pegar un diff en un issue:

1. Haz fork y trabaja en una rama descriptiva (`fix/fill-timeout`, `feat/…`).
2. Mantén el cambio acotado: un PR = un problema. Los PR gigantes no se revisan.
3. Corre las pruebas antes de abrir el PR:

```bash
bash scripts/keygate-selftest.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile __init__.py keygate_lib.py sync/keygate_sync.py
for f in scripts/*.sh scripts/keygate-*; do bash -n "$f" || exit 1; done
```

4. Si tocas comportamiento visible, actualiza `README.md` **y** `README.en.md`, y
   agrega la entrada en `CHANGELOG.md`.
5. Abre el PR contra `main` y llena la plantilla.

### Qué revisa el CI en tu PR

- `selftest` en un host limpio, con KeePassXC instalado.
- Compilación de Python y sintaxis de todos los scripts de bash.
- Tests de la política de autofill.
- **Bandit** (medium/high), **Semgrep** (`p/python`, `p/secrets`) y **Gitleaks**.

Un PR con el CI en rojo no se mergea, aunque el cambio sea bueno.

## Firma de commits

No es obligatoria. Si ya firmas con SSH o GPG, perfecto; si no, tu PR se acepta
igual. Lo único que se exige es que el commit tenga autor identifiable.

## Licencia de tus aportaciones

El proyecto está bajo **PolyForm Noncommercial 1.0.0**. Al enviar un PR aceptas que
tu aportación se distribuya bajo esa misma licencia (inbound = outbound). No hay
CLA que firmar.

Ten en cuenta la consecuencia: al ser una licencia no comercial, si en el futuro
el proyecto quisiera cambiar de licencia, haría falta el permiso de cada persona
que haya aportado código.

## Alcance

Bienvenido: compatibilidad con más sitios y flujos OAuth, endurecimiento,
cobertura de tests, documentación, traducciones.

Fuera de alcance por diseño: convertir keygate en un gestor de contraseñas
completo (para eso está KeePassXC), o prometer aislamiento contra root/malware
local — el plugin corre in-process y eso está documentado en *Límites honestos*.
