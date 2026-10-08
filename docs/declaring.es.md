# Declarar las duraciones de confidencialidad

*← volver al [README](../README.es.md)*

## Declarar las duraciones de confidencialidad

```bash
sablier declare /ruta/del/proyecto
```

La entrevista que rellena el único dato que ningún escáner sabe leer, realizada con
la persona que conoce la respuesta y no con la que escribió el código. Nunca pide
una duración de confidencialidad: pregunta **cuánto tiempo debe guardar esto** —un
hecho legal que alguien ya conoce— y **si se filtrara hoy, cuánto tiempo seguiría
haciendo daño**, y se queda con la mayor de las dos, porque un dato que hay que
guardar es un dato que todavía se puede robar. Dice cuál de las dos ganó, para que
se discuta el razonamiento y no la cifra.

Las preguntas tratan de las zonas que el análisis encontró realmente sin declarar,
en orden de cuánto código cubren, y una zona se puede saltar: queda entonces sin
declarar y el informe lo dice en sus puntos ciegos. Una duración que nadie eligió
sería peor que un hueco, porque el veredicto de encima llevaría la misma tipografía
segura que el resto.

**Para una sesión con alguien en la sala**, `sablier serve /ruta` abre la misma
entrevista en un navegador: un asunto por página, un cronómetro que la persona ve,
un botón que lo arranca, y al final el informe que sus respuestas produjeron —más
dos preguntas sobre la entrevista misma, porque la sesión existe tanto para corregir
la herramienta como para rellenar una declaración. El servidor queda atado al bucle
local y muere con el comando.

**A distancia**, añada `--expose` y el servidor genera una clave dentro del enlace;
`--public=` imprime la dirección que hay que entregar, para cuando un túnel y un
proxy inverso transportan un servidor que nunca sale del bucle local. Una dirección
de escucha juzga mal la exposición: por eso lo dice el operador. Termine el TLS en el
proxy — `docs/declaration-session.es.md` da las tres maneras de llevar la sesión
cuando la persona no está en la sala, y lo que cada una le cuesta a la medición.

Cada duración lleva **quién la declaró y cuándo**: el informe de auditoría imprime
ambas cosas junto a la cifra, y una duración que nadie ha revisado en dos años se
convierte en un punto ciego — las aceptaciones caducan, las fechas reglamentarias
llevan una fecha de verificación, y hasta ahora el único dato que decide cada
veredicto no tenía ninguna de las dos.

El protocolo —qué medir durante la sesión, y qué resultado falsaría toda la tesis de
esta herramienta— existe en [inglés](docs/declaration-session.md),
[francés](docs/declaration-session.fr.md) y
[español](docs/declaration-session.es.md), porque no todos los auditores leen inglés
y una sesión llevada desde una página entendida a medias mide la cosa equivocada.
Cada uno enlaza con una chuleta de una página para la sesión en sí: [qué preguntar, y
qué responder cuando se atasca](docs/session-script.es.md).

Sin declaración, la herramienta aplica una duración por defecto y lo dice. Con una,
se vuelve útil. Véase [`examples/declaration.json`](examples/declaration.json).

```json
{
  "expiry_year": 2035,
  "probe": ["example.org"],
  "domains": {
    "copias":           { "paths": ["deploy/backup.sh"], "lifetime_years": 10 },
    "contenido público":{ "paths": ["templates/*"],      "lifetime_years": 0 }
  }
}
```

Este archivo es el único artefacto del proyecto que compromete a personas y no a
herramientas. Se lee, se discute y se versiona.

[`examples/starter.json`](examples/starter.json) es una declaración que **corregir**
y no un archivo que rellenar: una docena de dominios habituales con sus duraciones
usuales y una nota que explica qué pesa en cada respuesta. Corregir una propuesta
saca a la luz desacuerdos que un archivo vacío esconde, y es más rápido.

Un dominio también puede declararse `"hybrid": true`, lo que significa que sus
algoritmos clásicos están emparejados con uno post-cuántico. Un hallazgo trata de
una línea, y la hibridación es una propiedad de la composición: nada en el código
muestra que otra llamada firme los mismos bytes. Así que lo dice la declaración,
el veredicto deja de pedirle que retire la mitad clásica —lo que equivaldría a
deshacer la hibridación que piden las referencias— y los puntos ciegos registran
que el emparejamiento se afirma y no se observa. Este repositorio declara así su
propio dominio de firma, ya que la v0.5.0 firma cada informe con Ed25519 y
ML-DSA-65 sobre los mismos bytes.

Una de esas notas importa más que las demás: **la duración de una copia de seguridad
es el máximo de todo lo que contiene.** Hereda el dominio más largo que usted haya
declarado, sea cual sea. Esa única línea es el origen de la mayoría de los veredictos
rojos.

## Los datos de salud, donde la duración está escrita en la ley

```bash
cp examples/health.json /ruta/del/proyecto/sablier.json   # corregir, y hacerlo firmar por el DPD
sablier scan /ruta/del/proyecto --out=informe.html
```

El dato que esta herramienta normalmente tiene que ir a buscar —cuánto tiempo
debe permanecer confidencial— está, en salud, fijado por el Código de la salud
pública francés. Un historial clínico se conserva **veinte años** desde la última
estancia o consulta externa (R1112-7), diez años desde el fallecimiento si el
paciente muere menos de diez años después de su última visita, y el plazo corre
hasta el 28º cumpleaños del titular si fuera a terminar antes. Una dispensación
de vacuna en el historial farmacéutico son **veintiún años** (R1111-20-12). Un
historial médico compartido, diez años desde su cierre (L1111-18). Las vigilancias
sanitarias, a falta de otra regla, **setenta años** desde la retirada del producto
del mercado.

`"regime": "hds"` sitúa el otro lado de la desigualdad en 2030 —la fecha de la
ANSSI, puesto que son datos sensibles. La aritmética no está entonces reñida:

```
FECHAS DE CRUCE
  · copias — 70 años — cruce superado desde 1961
  · historial clínico — 20 años — cruce superado desde 2011
```

Un historial clínico cifrado hoy con RSA, y que debe seguir siendo confidencial
veinte años, superó su cruce hace quince años. Es una resta entre un texto legal
y un plazo reglamentario, no una predicción.

[`examples/health.json`](examples/health.json) es una declaración que
**corregir**: cada duración lleva el artículo que la fundamenta, y `declared_by`
se deja vacío a propósito — el informe de auditoría imprime quién firmó cada
cifra y cuándo, y en este contexto esa persona es el delegado de protección de
datos.

**Lo que esto no hace: auditar una certificación HDS.** Ese marco cubre el
alojamiento —seguridad física, personal, continuidad, gestión de incidentes,
sobre una base ISO 27001 / 20000-1 / 27018— y la criptografía es solo una franja
estrecha. Sablier responde a una pregunta que plantea el expediente HDS, y la
documenta en una forma que resiste ante un auditor; no certifica nada.

## Cuando el plazo se lee del dato

Todos los regímenes anteriores son un par de años. Uno no lo es:

```bash
# sablier.json: { "regime": "eu" }
cp examples/eu.json /ruta/del/proyecto/sablier.json
```

La *hoja de ruta coordinada para la transición a la criptografía post-cuántica*
del Grupo de Cooperación NIS (23 de junio de 2025) no fija una fecha para todos.
Clasifica cada caso de uso por la confidencialidad que debe, y da a cada clase su
propio final:

> « this document considers a use case as **high-risk if compromising
> confidentiality after 10 years or more would still cause significant damage** »
>
> « For high-risk use cases, quantum-vulnerable public-key mechanisms **shall not
> be used stand-alone after the end of 2030**, analogously **after the end of 2035
> for medium-risk** »

Esa clasificación funciona con la única entrada que esta herramienta pide y que
nadie más recoge. Bajo `eu`, el plazo se lee por dominio: diez años o más de
confidencialidad — o un `trust_anchor` que firma software, el ejemplo que la hoja
de ruta da del caso de alto impacto — sitúan un dominio en **riesgo alto, 2030**;
más corto es **riesgo medio, 2035**. Dos dominios en un repositorio, dos plazos, a
partir de la declaración ya escrita. El informe de auditoría imprime el nivel al
lado de cada dominio, y las dos fechas en lugar de un único año retenido.

Lo que la herramienta no toma prestado es el juicio. El criterio de la hoja de
ruta es si un compromiso después de esa duración *seguiría causando un daño
significativo* — y declarar diez años **es** ese juicio. El documento lo dice allí
donde se imprime el nivel, en lugar de presentar un nivel calculado como un
hallazgo.

Una razón más en 2026: el **Milestone 1, el 31/12/2026**, enumera entre sus First
Steps «Support mature cryptographic asset management», «Create dependency maps» y
«Perform quantum risk analysis» — y recomienda el CBOM como formato de inventario.
Un escaneo produce el inventario y el análisis de riesgo. El mapa de dependencias
no, y eso queda escrito en los puntos ciegos en vez de insinuado.

### La obligación que el estándar no sabe escribir

CycloneDX 1.6 describe la criptografía y no la duración que debe. Ningún campo
dice «esto debe seguir siendo confidencial diez años» — la entrada sobre la que se
apoya cada veredicto aquí, y la razón por la que se puede recomendar el CBOM como
formato dejando la clasificación del riesgo a un humano.
[CycloneDX/specification#1126](https://github.com/CycloneDX/specification/issues/1126)
propone `protectionPeriod` en `relatedCryptoMaterialProperties`, con claves
`confidentiality` e `integrity` y una duración ISO 8601, previsto para la 2.0.

Mientras tanto, nuestro CBOM lleva la misma forma bajo su propio espacio de
nombres, para que un consumidor que implemente el campo real la traslade
mecánicamente en lugar de analizar nuestro entero:

```json
{ "name": "sablier:protectionPeriod.confidentiality", "value": "P10Y" }
```

La propuesta lleva además un `until` absoluto, y nosotros no: esa fecha depende de
cuándo se escribió cada registro, que es exactamente lo que la herramienta dice en
otro lugar que no puede saber.

## Qué país le audita, que no es qué plazo adopta

Dos preguntas distintas, y compartían un solo campo. Un **régimen** responde a
*cuándo caduca esta criptografía* — tomado de la autoridad que el declarante
acepte, y por eso una entidad alemana es perfectamente libre de adoptar el 2030
de la ANSSI. Una **jurisdicción** responde a *qué transposición nacional me va a
auditar*. `hds` era la prueba de que ambas estaban enredadas: la ley francesa de
alojamiento de datos de salud, archivada junto al CNSA 2.0 de la NSA.

```jsonc
// sablier.json
{ "regime": "eu", "jurisdiction": "fr" }
```

Un código ISO de dos letras, y se **declara, nunca se deduce de `--lang`**: los
documentos lo dicen con todas las palabras. Un idioma no es un país: un informe
en inglés para una entidad alemana, uno en español para la filial mexicana de un
grupo belga. Leer la jurisdicción en el idioma del lector sería exactamente la
suposición silenciosa que esta herramienta rechaza en todo lo demás.

Lo que aporta la capa europea es idéntico para los veintisiete, y el documento de
auditoría ya lo nombra: **Directiva (UE) 2022/2555**, del 14 de diciembre de 2022,
DO L 333/80, a transponer *«by 17 October 2024»* según su artículo 41, y cuyo
artículo 21 §2 h) incluye entre las medidas de gestión del riesgo *«policies and
procedures regarding the use of cryptography and, where appropriate,
encryption»*. Esa es la obligación a la que sirve este inventario, y vale
cualquiera que sea el estado de cada transposición — varias siguen inacabadas.

**Sablier conoce los veintisiete Estados miembros.** Declare `jurisdiction: de`
y el documento de auditoría imprime la autoridad alemana, su portal de registro y
la fecha en que se tomó cada uno; declare `jurisdiction: pl` e imprime la de
Polonia. Lo que conoce de cada uno es la autoridad nacional de ciberseguridad que
publica ENISA, y la fecha de ese registro.

Siete Estados miembros dicen hoy algo más, cada uno leído en el sitio de su
propia autoridad:

| | |
|---|---|
| **Francia** | ANSSI · ReCyF · MesServicesCyber |
| **Alemania** | BSI · NIS-2-Umsetzungsgesetz, en vigor el 6 de diciembre de 2025 · portal.bsi.bund.de, registro en tres meses |
| **Bélgica** | CCB · CyberFundamentals, donde una implementación validada otorga una presunción de conformidad · Safeonweb@Work |
| **Italia** | ACN · Decreto legislativo 138/2024, en vigor el 16 de octubre de 2024 · la plataforma de la ACN, y hasta el 0,1 % de la facturación por registrarse tarde |
| **Países Bajos** | NCSC · Cyberbeveiligingswet, en vigor el 15 de agosto de 2026 · mijn.ncsc.nl — mientras la RDI supervisa nueve sectores |
| **Portugal** | CNCS · Decreto-Lei 125/2025, en vigor el 3 de abril de 2026 · Medidas Mínimas de Cibersegurança · MyCiber |
| **España** | Consejo Nacional de Ciberseguridad · transposición todavía un anteproyecto, y INCIBE escribe ella misma que las autoridades competentes y el punto de contacto único tienen que esperarla |

Los Países Bajos ilustran mejor que nadie la reserva que lleva cada marco: uno se
registra ante el NCSC y es la RDI quien inspecciona. La ventanilla de registro no
es necesariamente la autoridad que audita su sector.

Los otros veinte imprimen su autoridad y nada más. Eso significa que nadie ha
leído aún su sitio — no que no haya nada que leer allí.

Lo que **deliberadamente no** guarda es un estado de transposición. Las
páginas por país de la Comisión daban una situación de mediados de 2025, varios
Estados miembros han cambiado desde entonces, y un estado congelado en una
release es un hecho normativo que caduca entre dos versiones de esta herramienta
y se sigue leyendo como actual. Así que los documentos citan la página viva de la
Comisión — una sola dirección para los veintisiete, que se actualiza sola — en
lugar de copiar de ella un veredicto.

Dos cosas más se imprimen para cada Estado miembro. La fecha en que se tomó el nombre de la autoridad,
por la misma razón por la que existe `deadlines_checked_on`: un hecho normativo
sin fecha es un hecho que nadie puede envejecer. Y una reserva, porque varios
Estados miembros designan además autoridades sectoriales: esta es la puerta por la
que se empieza, no necesariamente la que le audita.

Una jurisdicción declarada fuera de la Unión — `ch`, `uk`, `us` — no tiene fila, y
el documento lo dice en lugar de agarrar la agencia más plausible.

Y este inventario no es un informe de conformidad NIS 2. Produce una de las
medidas que pide la directiva. El registro ante la autoridad y la notificación de
incidentes son obligaciones que pesan sobre la entidad, y la herramienta no dice
nada de ninguna de las dos.

## La entrevista en un solo archivo

```bash
sablier worksheet /ruta/del/proyecto --out=cuestionario.html   # [--lang=fr|en|es]
# … la persona lo rellena, donde sea, y devuelve un archivo
sablier declare /ruta/del/proyecto --import=respuestas.json
```

Una página que no habla con nada: los asuntos y las preguntas incrustados, sin
servidor, sin puerto, sin petición. Se abre desde una memoria USB o un adjunto, se
responde en un navegador con el cable fuera, y lo que vuelve es un bloque de JSON que la
persona puede guardar o copiar.

Existe para las salas en las que la entrevista servida no puede entrar —una red cerrada,
un cliente que no va a ejecutar un comando, una máquina a la que nadie puede
conectarse— y elimina el túnel, el certificado y la pregunta de si el portátil del
auditor es seguro, también para todos los demás.

Lo que viaja es el punto: el archivo no lleva **ninguna ruta absoluta** de la máquina
que lo escribió, y lo que vuelve lleva duraciones y los nombres que dio la persona,
nunca el inventario que los produjo. Ambas cosas se comprueban en cada ejecución. El
informe lo calcula después el auditor, donde corresponde.

Las reglas de fusión no se reimplementan en el navegador. La página recoge respuestas;
`--import` las hace pasar por el mismo código que usa una entrevista tecleada, de modo
que un nombre dado dos veces significa lo mismo —un dominio, ambas rutas, la duración
más larga— se haya dado donde se haya dado.

### Lo que la persona lee, y su presupuesto

Tres sesiones con el mismo directivo acabaron en *«es jerga para mí, no entiendo
las frases, estoy perdido»*. La tercera vez, el documento había llegado a **986
palabras** que atravesar para responder dos preguntas por tema — con *huella*
cinco veces, y *algoritmo*, *plazo*, *régimen*, *declaración*, *fontanería* en
el camino. Casi todo se había añadido de buena fe, un párrafo defendible a la
vez, cada uno explicando lo que la herramienta no podía saber o por qué se hacía
una pregunta.

Todo lo retirado se sigue diciendo — en el informe de auditoría, que es donde
una reserva pertenece: lo lee quien debe pesar las cifras, no quien aporta una.
Quedan **235 palabras**, y un test falla por encima de 260. Un presupuesto en
lugar de una relectura, porque la prosa llega un párrafo justificado a la vez y
nada más lo habría detectado. Un segundo test falla si una palabra del oficio
vuelve al camino.

Dos preguntas también se fueron. La criptografía hallada en un lugar está ahora
detrás de un pliegue, con los nombres de archivo: cierto, y sin utilidad para
quien responde sobre datos. Y **no se pregunta qué régimen regulatorio aplica**
— nadie fuera del campo elige entre NIST IR 8547, CNSA 2.0 y una posición de la
ANSSI, y la pregunta imprimía cinco líneas de siglas, y luego plazos de 2030 y
2035 bajo un año que la persona acababa de dar como 2029. Es del auditor
fijarlo, en la declaración, donde es revisable; la importación lo dice cuando se
queda en el valor por omisión.

Lo que sobrevive es lo único de lo que la persona enfrente es la autoridad: de
qué datos se trata, en sus palabras, y qué costaría si salieran.
