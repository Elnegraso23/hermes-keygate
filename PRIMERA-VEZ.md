# Primera vez con keygate — lo que TU haces

Esta guia es para ti, el usuario. Todo lo tecnico lo hace Hermes cuando le dices
**"instalame este repo"**. Aqui solo ves tu parte: que decir, que clics dar,
que esperar.

## Lo unico que tienes que decir para empezar

En un chat nuevo de Hermes, pega esto (cambia la URL si es otro fork):

> instalame este repo: https://github.com/Elnegraso23/hermes-keygate

Hermes te va a pedir confirmacion, dira que va a clonar, instalar el plugin,
crear el vault y configurar todo. Dile que si.

## Lo que va a pasar (tu no haces nada aqui)

| # | Hermes hace | Tu ves |
|---|-------------|--------|
| 1 | Clona el repo a `~/hermes-keygate` | "Repo clonado" |
| 2 | Copia el plugin a `~/.hermes/plugins/keygate/` y lo habilita | "Plugin instalado y habilitado" |
| 3 | Crea `~/.keepass-agent.key` + `~/Documentos/hermes.kdbx` (sin master) | "Vault operativo creado" |
| 4 | Agrega el bloque keygate a `~/.hermes/config.yaml` (sin secretos) | "Config lista" |

## Lo que SI haces tu (3 cosas manuales)

### 1. Reiniciar Hermes (obligatorio)

Hermes te va a decir: **"cierra y reabre el chat"**. Hazlo. El plugin no carga
hasta la proxima sesion — sin reinicio nada funciona.

Cuando vuelvas, dile:

> ya reinicie

Hermes verifica (`keygate_status` debe decir `{locked:false, entries:0}`).

### 2. Crear tu primera cuenta en la pagina local (2 minutos)

Hermes NO puede crear credenciales (bloqueado por politica — es tu seguridad).
El camino es la pagina **http://127.0.0.1:8472** (Hermes la arranca por ti
durante la instalacion; si no esta viva, pidela: "levanta la pagina de keygate"):

1. Abre http://127.0.0.1:8472. La PRIMERA vez te obliga a crear una
   contraseña (minimo 12 caracteres, una sola vez — despues ese paso muere
   para siempre). Queda solo en esa pestaña, en ningun disco mas.
2. Arriba veras la tarjeta **"Primera vez"**:
   - ⬇ **Descarga el .kdbx** (vacio la primera vez).
   - **Descarga el .key (una sola vez)** — guardalo con permisos 600 en tu PC.
3. Abre el `.kdbx` en KeePassXC con ese `.key` (no pide password) y crea tu entrada:
   - **Titulo:** alias opaco, ej. `internet-agent-1`
     (opaco = que no revele el sitio si alguien ve la lista)
   - **Usuario / Password:** tus credenciales reales
   - **URL:** la URL EXACTA del login
4. Guarda (Ctrl+S), vuelve a la pagina y **sube el .kdbx editado**
   (pide confirmacion, deja backup automatico). Veras tu alias en la lista.
5. Avisale a Hermes: `ya la subi`.

> **Para probar sin cuentas reales:** usa el sitio publico
> https://the-internet.herokuapp.com/login
> con usuario `tomsmith` y password `SuperSecretPassword!`
> (estan impresas en la pagina, son para practicar).
> Alias sugerido: `internet-agent-1`.

> **Alternativa (mismo PC, sin pagina):** abre directo
> `~/Documentos/hermes.kdbx` en KeePassXC con `~/.keepass-agent.key`.
> La pagina sigue siendo el camino normal.

### 3. Aprobar con un clic (cada login nuevo)

Cuando le pidas a Hermes entrar a un sitio por primera vez, te va a salir un
prompt en tu pantalla:

> **Allow import login internet-agent-1?**

Le das **Accept**. Eso es todo. Hermes copia la entrada al vault cifrado local
(una sola vez) y rellena el formulario sin ver jamas tu password.

## Tu primer login, frase por frase

Tu dices:

> quiero entrar a https://the-internet.herokuapp.com/login

Hermes pregunta (si aun no esta importado):

> ¿que alias usas para este sitio?

Tu respondes:

> internet-agent-1

Hermes muestra el prompt de aprobacion → le das **Accept** → rellena el form.

Hermes te dice que hagas submit (o lo hace el). Ves en la pagina:

> You logged into a secure area!

Listo. La proxima vez que pidas ese sitio, Hermes lo llena directo sin preguntar
(ya quedo importado).

## De aqui en adelante (uso diario)

Solo di:

> quiero entrar a <sitio>

- Si ya esta importado → fill directo, sin prompts.
- Si es nuevo → te pide el alias una vez → UN prompt de aprobacion → fill.
- Jamas escribas passwords en el chat. Si Hermes te pide un password en texto,
  algo esta mal — paralo y reporta.

## Preguntas que siempre hacen

**¿Hermes ve mi password?**
No. Viaja KeePass → vault cifrado → pagina, por CDP supervisado. El modelo solo
recibe `{success, filled_fields}`. Nunca entra al contexto, logs, memoria ni Telegram.

**¿Y mi vault personal?**
Ni lo toca. Hermes solo conoce `hermes.kdbx` (el operativo, keyfile-only).
Tu `personal.kdbx` con master password Hermes no sabe que existe.

**¿Como quito acceso a un sitio?**
Borra la copia en KeePassXC (o cierra la DB). Para quitar el importado del vault
de Hermes: vault settings del agente.

**¿Como actualizo el plugin?**
```bash
bash ~/hermes-keygate/scripts/keygate-update
```
Nunca toca tu `.kdbx` ni tu `.key` (aborta si un update los trajera).

**¿Y si algo no jala?**
Pidele a Hermes `keygate_doctor` y pasa el JSON a un issue en
https://github.com/Elnegraso23/hermes-keygate/issues (sin secretos — el doctor
nunca los muestra).
