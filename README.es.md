# Sablier

Lo que está cifrado en su proyecto, y **cuánto tiempo aguanta**.

*[English](README.md) · [Français](README.fr.md) — la versión inglesa es la que da
fe; esta es una traducción, y la desviación se detecta en integración continua.*

## Para empezar

**Qué hace.** Sablier lee un proyecto — su código, sus dependencias, sus
Dockerfiles, su Terraform y, si se lo permite, el TLS que un servidor negocia
realmente — enumera toda la criptografía que encuentra, y da a cada una una
**fecha de caducidad**. No «esto es débil», sino: *este algoritmo protege datos
que deben seguir siendo secretos hasta 2041, y deja de ser fiable en 2030.* Lo
que sale es una página HTML que un humano lee, firmada, con una fecha atestiguada
por un tercero.

**Cómo usarlo, en tres comandos.**

```bash
sablier init /ruta/del/proyecto       # 1. una declaración, rellenada desde el código
sablier declare /ruta/del/proyecto    # 2. la entrevista — el único dato que ningún escáner tiene
sablier scan /ruta/del/proyecto       # 3. el informe
```

El paso 1 escribe `sablier.json` adivinando a partir de lo que ve, para que parta
de algo que corregir en lugar de un formulario vacío. El paso 3 funciona por sí
solo si tiene prisa: `sablier scan .` y ya tiene un informe.

**El paso 2 es la herramienta.** Todo lo demás es leer archivos. Un escáner ve
que usa AES-256; nada en su repositorio dice cuánto tiempo deben permanecer
confidenciales los datos que protege, y ese único número decide si un hallazgo es
urgente o irrelevante. Así que Sablier lo pregunta, en lenguaje de negocio,
dominio por dominio — una nómina, un historial médico, un token de sesión — y
registra quién respondió y cuándo. Un cuarto de hora con quien lo sabe, una vez
al año.

**Por qué importa, en un párrafo.** Un adversario que graba hoy su tráfico
cifrado lo descifrará el día en que exista la máquina. Para datos que deben
permanecer secretos más allá de la caducidad de RSA y de las curvas elípticas,
**la fecha del compromiso es el día del cifrado, no el del ataque** — migrar más
tarde protege lo que venga después, y no esos datos. Por eso la pregunta nunca es
«¿es sólido este algoritmo?» sino «¿su caducidad cae antes o después del fin de
la confidencialidad que transporta?».

**Qué no es.** No es un escáner de vulnerabilidades: lee lo que usted *eligió*,
no lo que está roto hoy. No es un informe de conformidad: produce un artefacto,
un inventario criptográfico. En la Unión ese artefacto es una de las medidas que
pide NIS 2; fuera de ella, el mismo inventario responde al marco que usted
adopte — la herramienta lleva NIST IR 8547, el CNSA 2.0 de la NSA y la hoja de
ruta europea, y cuál se aplica es un campo de la declaración y no un valor por
defecto. En ambos casos no dice nada sobre el registro ante una autoridad ni
sobre la notificación de incidentes.
Y no tiene ninguna opinión que no le muestre: cada hallazgo imprime su prueba, su
huella, y una forma ya rellenada de impugnarlo.

**Y después.** Firme el informe y haga atestiguar su fecha por alguien que no sea
usted (`--sign`, `--timestamp`), archive el documento de auditoría (`--audit`),
ponga las fechas de cambio en un calendario (`--calendar`), y vuelva a ejecutarlo
una vez al año: los plazos se mueven, y una vida confidencial de nueve años es
conforme este año y ya no el siguiente.

La fórmula es la **desigualdad de Mosca** (2015), simplificada: el marco es estándar
y tiene nombre, y otras herramientas lo implementan.
[`docs/scoping.md`](docs/scoping.md) las cita honestamente y dice qué queda de
nuestro — sobre todo un conjunto de negativas, y una sonda que lee lo que un
servidor negocia realmente en lugar de lo que un archivo afirma.

Estado: **prototipo**.

## Probarlo

```bash
make demo                                   # proyecto de prueba + informe
sablier init /ruta/del/proyecto             # una declaración que corregir, no un formulario que rellenar
make scan DIR=/ruta/del/proyecto LANG=es    # un proyecto real
make scan DIR=/ruta/del/proyecto PDF=1      # …y un PDF al lado
make scan DIR=/ruta/del/proyecto AUDIT=1    # …y el documento de auditoría
make probe HOST=example.org                 # lo que un servidor negocia realmente
make test                                   # ¿sigue discriminando el modelo de riesgo?
```

**¿Sin PHP en esta máquina?** `./sablier` es la misma herramienta a través de un
contenedor: usa el intérprete local cuando es 8.4 o posterior, y si no ejecuta el
código sin cambios dentro de `php:8.4-cli-alpine`, **fijada por digest** y no por
esa etiqueta: una etiqueta es un puntero que otro mueve, y el lanzador ejecutaría
si no bytes que nadie aquí ha verificado. El mismo digest está en el `Makefile`, y
la suite de pruebas rechaza un commit donde ambos discrepen. `make images` muestra
a qué apunta la etiqueta hoy, para actualizar la fijación a propósito. No se
instala nada, el informe lo escribe su propio usuario, y las rutas se resuelven
desde el directorio en el que usted está — el que se monta, de modo que el
lanzador rechaza una ruta fuera de él en lugar de escribir un informe que
desaparece con el contenedor.

```bash
cd /ruta/del/proyecto && /ruta/a/sablier scan . --out=informe.html
```

Los informes existen en francés, inglés y español (`--lang=fr|en|es`).

**Sin ejecutar nada:** [`examples/report.html`](examples/report.html) es el informe
técnico del proyecto de prueba, y [`examples/audit.html`](examples/audit.html) el
documento de auditoría del mismo análisis. Ambos se regeneran en cada versión y cada
uno cabe en un solo archivo autónomo: ábralos desde el disco.
[`examples/report.pdf`](examples/report.pdf) y
[`examples/audit.pdf`](examples/audit.pdf) son esos mismos dos documentos tal como
los compone la herramienta, trece y veintiséis kilobytes: es lo que pesa un PDF que
ningún navegador ha impreso. [`examples/worksheet.html`](examples/worksheet.html) es la
entrevista sin conexión tal como se entrega, [`examples/cbom.json`](examples/cbom.json)
el mismo inventario en CycloneDX, y [`examples/crossings.ics`](examples/crossings.ics)
las fechas de cruce como calendario. [`CHANGELOG.md`](CHANGELOG.md) dice qué cambió cada
versión.

El informe es un archivo HTML autónomo: ninguna fuente remota, ningún script,
ninguna petición. Una herramienta que lee dónde están las claves no tiene por qué
abrir un socket para mostrar su propia salida.

## Documentación

El README se detiene aquí a propósito. Todo lo que sigue es una página por tema, en los tres idiomas.

| | |
|---|---|
| [`docs/detection.es.md`](docs/detection.es.md) | Lo que detecta, y hasta qué punto está seguro |
| [`docs/declaring.es.md`](docs/declaring.es.md) | Declarar las duraciones de confidencialidad |
| [`docs/reports.es.md`](docs/reports.es.md) | Qué dicen los informes, y a quién se dirigen |
| [`docs/judging.es.md`](docs/judging.es.md) | Juzgar el inventario de otro |
| [`docs/advisories.es.md`](docs/advisories.es.md) | Vulnerabilidades publicadas |
| [`docs/breach.es.md`](docs/breach.es.md) | Después de una filtración |
| [`docs/pipeline.es.md`](docs/pipeline.es.md) | En una cadena de integración |
| [`docs/signing.es.md`](docs/signing.es.md) | Firmar un informe, y fecharlo |
| [`docs/closed-network.es.md`](docs/closed-network.es.md) | En una red cerrada |
| [`docs/design.es.md`](docs/design.es.md) | Cómo está montado, y qué se niega a hacer |
| [`docs/how-it-works.md`](docs/how-it-works.md) | Cómo funciona, en tres esquemas |
| [`docs/airgap.md`](docs/airgap.md) | La postura de red cerrada, en detalle |
| [`docs/scoping.md`](docs/scoping.md) | Estudio de alcance: las otras herramientas, y qué queda de nuestro |
| [`docs/false-positives.md`](docs/false-positives.md) | Falsos positivos: cómo se impugna uno, y qué pasa después |
| [`docs/declaration-session.es.md`](docs/declaration-session.es.md) | Llevar la entrevista de declaración con alguien |

## Primeros resultados

Primer análisis sobre un proyecto real (Show me the REX, ~1.900 archivos): 17 hallazgos,
**ninguna alerta roja** — y tres lecciones que cambiaron la herramienta de inmediato.

1. El cifrado de las copias de seguridad, la operación más sensible del proyecto, **no
   está en el repositorio**: vive en un script en el servidor. El análisis estático por
   sí solo nunca verá lo que más importa, a menos que usted lo declare.
2. La primera versión reportaba un `md5()` en una prueba y una dependencia TOTP —cuyo
   SHA-1 impone la especificación— como roturas. Dos falsos positivos sobre quince
   hallazgos bastan para perder al lector. De ahí la separación entre *inventario* y
   *uso*, y el código de prueba archivado como fuera de tema.
3. La sonda encontró lo que ningún archivo podía decir: el sitio ya negocia
   **X25519MLKEM768**, un intercambio de claves post-cuántico híbrido. Nada en el
   repositorio lo menciona.
