# La sesión de declaración

*[English](declaration-session.md) · [Français](declaration-session.fr.md) — la
chuleta para tener en la mano durante la sesión está
[aquí](session-script.es.md).*

El único experimento que puede matar este proyecto, hecho a propósito y no por
accidente.

Cada veredicto de cada informe descansa sobre una cifra que ningún escáner sabe
leer: cuánto tiempo debe permanecer confidencial cada tipo de dato. El estudio
de alcance lo dice, y dice qué falsificaría la tesis: *la persona no consigue
responder a «cuánto tiempo debe seguir siendo secreto» en la mayoría de sus
dominios*. Mientras no haya una sesión fuera de este repositorio, eso es una
opinión.

Esta página existe para hacer la sesión medible, y está escrita **antes** de la
primera, para que el resultado no pueda racionalizarse después.

## Lo que se mide, decidido de antemano

| | Qué | Quién lo registra |
|---|---|---|
| **El tiempo** | El total y el tiempo por asunto. La duda *es* la medida, y pedirle a alguien que se cronometre mientras piensa es impedirle pensar. | la herramienta, con `--log` |
| **La seguridad** | Respondido sin dudar, respondido tras discusión, o bloqueado. Los segundos por asunto son un buen indicio; la cruz es su juicio. | usted |
| **Los desacuerdos** | Cada vez que la respuesta contradice lo que habríamos supuesto. Los minutos más instructivos de la sesión: dicen que nuestros valores por defecto están mal, y no se adivinan desde un escritorio. | usted |

```bash
sablier declare /ruta/del/proyecto --log=session.json --lang=es
```

El registro contiene, por asunto: el nombre que dio la persona, las dos cifras,
la duración que se deduce de ellas, los asuntos saltados y los segundos
empleados. Una cifra transcrita después es una cifra redondeada hacia el
resultado que se esperaba.

## Qué falsificaría la tesis

Si la mayoría de los asuntos acaban **bloqueados**, el problema no es la
herramienta y ningún detector adicional lo arregla. Habría que plantear la
pregunta de otra manera —partiendo de otra cosa, o con otra persona— y lo que
debe cambiar es el producto, no la documentación.

Registrarlo honestamente es todo el objetivo. Una sesión que solo produce una
declaración rellena no demuestra nada; una que produce tres bloqueos de seis
enseña más que un mes de trabajo.

## El desarrollo

**Antes**, a solas, diez minutos:

```bash
sablier scan /ruta/del/proyecto --out=antes.html --lang=es
```

Guarde ese informe: es la comparación de «después», y las zonas que figuran
como no declaradas son las preguntas que hará la entrevista.

**Durante**, con la persona:

```bash
sablier declare /ruta/del/proyecto --log=session.json --lang=es
```

La entrevista avanza asunto por asunto. Cada uno se abre con una descripción en
lenguaje llano de **lo que la herramienta ha encontrado ahí** —una caja fuerte
de secretos, ajustes leídos al arrancar, una huella calculada sobre contenido—
con los nombres de archivo debajo para quien los conozca. Ningún nombre de
algoritmo, ninguna ruta como título: una primera prueba en vacío mostraba
«`.env` — criptografía detectada: sin cifrado», lo que pierde a una persona no
técnica en dos líneas y se lleva la sesión por delante.

Luego tres preguntas, ninguna de las cuales es una duración de
confidencialidad:

- **si alguien obtuviera una copia, ¿de qué estaríamos hablando, en sus
  palabras?** La respuesta nombra el dominio, y es suya, no nuestra;
- **¿cuántos años debe guardar esto?** La conservación es un hecho legal que
  alguien ya conoce: una obligación contable, un reglamento, un contrato. Nadie
  duda en eso;
- **si esto saliera hoy, ¿cuántos años seguiría causando daño?** Normalmente
  menos que la conservación. A veces mucho más, y esa diferencia vale por sí
  sola toda la sesión.

La duración retenida es la mayor de las dos, porque un dato que hay que guardar
es un dato que todavía se puede robar. La herramienta dice cuál de las dos ha
ganado, para que se discuta el razonamiento y no la cifra.

Dos reglas para quien dirige la sesión:

- **no responda en su lugar.** La tentación es enorme, sobre todo sobre código
  que usted ha escrito. Una duración que usted ha sugerido no mide nada;
- **deje saltar.** Un asunto sin respuesta queda sin declarar y se calcula con
  la duración por defecto, cosa que el informe escribe en sus puntos ciegos. Es
  un resultado, no un fracaso, y es precisamente el que falsifica la tesis.

**Después**, delante de ella:

```bash
sablier scan /ruta/del/proyecto --out=despues.html --audit=audit.html --lang=es
```

Abra los dos informes uno al lado del otro. Los veredictos que han cambiado son
lo que ha producido su hora; y si no ha cambiado nada, dígalo: significa que las
duraciones por defecto ya eran correctas, y conviene saberlo.

## La hoja

Cópiela, rellénela durante la sesión, guárdela con la declaración.

```
Proyecto:                       Fecha:
Persona:                        Su puesto:
Duración total:                 minutos

Asunto                 Nombre dado          Conservación  Daño  Duración  Segura / Discutida / Bloqueada
─────────────────────  ───────────────────  ────────────  ────  ────────  ──────────────────────────────

Desacuerdos con lo que habríamos supuesto:
  ·

Lo que ha preguntado y la herramienta no ha sabido decir:
  ·

Veredictos que han cambiado entre antes.html y despues.html:
  ·
```
