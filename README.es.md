# Sablier

Lo que está cifrado en su proyecto, y **cuánto tiempo aguanta**.

*[English](README.md) · [Français](README.fr.md) — la versión inglesa es la que da
fe; esta es una traducción, y la desviación se detecta en integración continua.*

*Estudio de alcance: [docs/scoping.md](docs/scoping.md)*

Sablier lee un proyecto, inventaría su criptografía y cruza ese inventario con el
único dato que ningún escáner puede encontrar por sí mismo: **cuánto tiempo debe
permanecer confidencial cada categoría de dato.** De ese cruce sale la única
pregunta que importa hoy sobre lo post-cuántico:

> Un dato cifrado hoy con RSA o con una curva elíptica, y que deba seguir siendo
> secreto más allá de la caducidad de esos algoritmos, está **ya perdido**. La
> migración protege lo que viene después, no ese dato.

Es el modelo *recolectar ahora, descifrar después*: un adversario captura hoy lo
que descifrará mañana. Para el dato afectado, la fecha de compromiso es el día en
que se cifró, no el día del ataque.

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
código sin cambios dentro de `php:8.4-cli-alpine`. No se instala nada, el informe lo
escribe su propio usuario, y las rutas se resuelven desde el directorio en el que
usted está — el que se monta, de modo que el lanzador rechaza una ruta fuera de él
en lugar de escribir un informe que desaparece con el contenedor.

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

`--pdf=ARCHIVO` escribe también un PDF, compuesto aquí en lugar de impreso por un
navegador prestado. A4, las tres fuentes que todo lector ya tiene, las diez secciones
numeradas, las duraciones declaradas y la cronología dibujada con operadores
vectoriales: la única figura que sostiene el argumento, así que viaja en lugar de
quedarse atrás.

Esto sustituyó a una búsqueda de Chrome en catorce ubicaciones y a un contenedor
Chromium fijado. El archivo es más sobrio: sin color más allá de las barras, sin
tipografía digna de ese nombre. También es dieciocho veces más pequeño, lleva **un
número de página en cada página** —lo que el navegador nunca nos habría dado, ya que
Chrome ignora el CSS que lo imprimiría— y no puede fallar por falta de algo que
tomar prestado. Esa última propiedad era la que importaba: en un sitio cerrado no hay
navegador que encontrar ni imagen que descargar, y un informe que no se puede
imprimir no se puede firmar ni archivar.

Necesita la extensión PHP `dom`, activada en cualquier instalación estándar y en el
contenedor que este proyecto incluye. Sin ella, la herramienta lo dice, y el HTML
sigue imprimiéndose a PDF desde cualquier navegador, porque incluye una hoja de
impresión que fuerza la paleta clara y mantiene gráficos, hallazgos y el bloque de
sonda fuera de los saltos de página.

## Lo que dice de sí mismo

Este repositorio lleva su propia declaración y se analiza en cada construcción,
comparando el resultado con `.sablier/baseline.json`. Nueve hallazgos: seis firmas
Ed25519, dos resúmenes SHA-256 que hace bien en dejar en paz, y uno que clasifica
como identificador y no como control — nuestra propia función de huella, que es
exactamente eso.

La declaración excluye cuatro rutas, y el lector merece la razón de cada una:

| excluido | por qué |
|---|---|
| `src/Detector/*` | los detectores contienen los patrones: la cadena `rsa` ahí es lo que encuentra RSA, no un uso de RSA |
| `src/Probe.php` | lo mismo, para el saludo que lee |
| `tests/fixtures/*` | criptografía plantada a propósito, para que las pruebas tengan algo que encontrar |
| `tests/run.sh` | el `openssl genrsa` que la suite ejecuta para fabricarse una clave |

Analizado quitando esa lista, el repositorio produce 47 hallazgos en lugar de nueve
y **ninguno es rojo**: doce cadenas de patrones en los detectores, veintitrés en los
ficheros de prueba, y el resto ya reportado. La lista no oculta nada; pasó de ocho
entradas a cuatro el día en que se comprobó, porque cuatro de ellas excluían archivos
que no contenían nada.

La declaración también tuvo que ponerse al nivel que esta herramienta exige a los
demás. Ahora lleva `declared_by` y `declared_on`, y un `service_until`, porque el
informe imprimía nuestro propio horizonte ausente en sus puntos ciegos — es la
herramienta funcionando, y no fue una manera cómoda de enterarse.

## Con qué frecuencia se equivoca

Medido, no afirmado: **31 repositorios PHP públicos, 959 hallazgos, 21 rojos, 3 de
ellos equivocados — 14 %.** Antes de esta medición era el 92 %, y los nueve rojos de
cada diez que estaban mal se debían al mismo puñado de errores: `mcrypt_*` reportado
como DES, códigos de hash de objetos y nombres de cerrojos leídos como controles de
seguridad, HMAC-MD5 declarado roto, una llamada encontrada dentro de un comentario.

[`docs/false-positives.md`](docs/false-positives.md) tiene el método, las
correcciones, el juicio sobre cada rojo restante y los repositorios para reproducirlo
— incluidos los seis que nunca se usaron para ajustar, donde la tasa volvía al 63 %
hasta que las reglas se hicieron generales en lugar de particulares.

Quedan tres falsos positivos, documentados en lugar de ocultados. La cobertura no se
movió: cada hallazgo real del primer corpus se sigue reportando.

## Los servicios gestionados, hasta donde un archivo puede decirlo

Cada informe lleva la misma admisión: la criptografía de su base de datos, de su
almacenamiento de objetos y de su terminación TLS no aparece en ningún archivo del
repositorio. Eso es cierto de una aplicación. Deja de serlo en cuanto la
infraestructura está declarada como código a su lado.

Los archivos `.tf` se leen buscando las decisiones que alguien escribió:
`storage_encrypted = false`, un `minimum_protocol_version` por debajo de lo que
todavía se negocia, el cifrado del lado del servidor de un bucket y de quién es la
clave, las claves que la infraestructura se crea, una clave KMS asimétrica. Una base
gestionada que guarda diez años de contabilidad con el cifrado desactivado es el
mismo hallazgo que un script de copia sin cifrado: el proveedor no cambia la
aritmética.

Lo que se lee ahí es la **intención**, no el resultado, así que el punto ciego se
reformula en vez de eliminarse: lo que el proveedor hace realmente con esa
declaración —sus propias claves, sus algoritmos, su terminación TLS— sigue fuera del
informe.

## Dos fuentes, porque un repositorio puede equivocarse

La sonda cubre HTTPS, SMTP, IMAP, POP3, PostgreSQL, MySQL, LDAP y los puertos de TLS
implícito de AMQP, Redis y MQTT — más **SSH**, que nunca se convierte en TLS y por eso
tiene su propio lector: toma el banner y el KEXINIT del servidor, que es donde aparece
`sntrup761x25519` cuando alguien activó un intercambio de claves post-cuántico que
ningún archivo del repositorio menciona. Envía un banner, lee un paquete y cuelga:
nunca una clave, nunca una contraseña, nunca lo bastante lejos para ser un intento de
autenticación.

**El análisis estático** lee lo que el código declara. **La sonda** realiza un saludo
TLS corriente e informa de lo que el servidor negocia realmente — se contradicen con
suficiente frecuencia como para que informar solo de lo primero resulte engañoso. Un
proyecto sin criptografía post-cuántica en ninguna parte de su código puede estar ya
protegido por su CDN; un proyecto que lo configuró todo bien puede terminar en manos
de un intermediario que lo deshace.

```
$ make probe HOST=example.org

  protocolo negociado          TLSv1.3
  suite criptográfica          TLS_AES_256_GCM_SHA384 (256 bits)
  grupo negociado              X25519MLKEM768
  firma del certificado        ecdsa-with-SHA256
  versiones aceptadas          TLSv1.2, TLSv1.3
```

La sonda solo tiene sentido contra equipos de los que usted es responsable.

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

Una de esas notas importa más que las demás: **la duración de una copia de seguridad
es el máximo de todo lo que contiene.** Hereda el dominio más largo que usted haya
declarado, sea cual sea. Esa única línea es el origen de la mayoría de los veredictos
rojos.

## Cómo está montado

Dos puntos de extensión, porque el estudio de alcance nombra dos ejes que de verdad
van a crecer — y nada más recibe una interfaz.

```
DetectorInterface   una manera de encontrar criptografía en un tipo de archivo
  PhpDetector · ShellDetector · KeyMaterialDetector
  ServerConfigDetector · DependencyDetector

ReporterInterface   una manera de representar un análisis
  HtmlReporter · AuditReporter · CbomReporter · JsonReporter
```

`Scanner` recorre un árbol y no sabe nada de criptografía; la lista de detectores se
compone en `bin/sablier` y se le pasa. Añadir un lenguaje significa escribir un
detector y registrarlo, nunca editar el escáner. `Analysis` lleva todo lo que un
reportero necesita, de modo que añadir un hecho al informe no cambia la firma de
todos los renderizadores.

Todo lo demás permanece concreto. `Catalogue`, `Assessor`, `Declaration` y `Lang`
tienen una implementación cada uno y ninguna segunda a la vista: una interfaz con una
sola implementación y sin perspectiva de otra es un coste sin comprador.

## El informe concluye

Unos hallazgos no son una decisión. La última sección es un plan de acción ordenado,
derivado de lo que realmente se encontró: qué hacer primero, y por qué va primero.

Toma posiciones que la mayoría de los inventarios evita. Cuando un dato ya es
recolectable, la primera acción no es «migrar»: es decidir qué pasa con el dato ya
enviado, porque la migración no puede alcanzarlo. Cuando nada arde, lo dice sin
rodeos, porque sustituir criptografía que aguanta cuesta tiempo y no mejora nada. Y
cuando la mayoría de los hallazgos están en dominios sin declarar, terminar la
declaración va antes que todo lo demás: hasta entonces, los veredictos de arriba son
aproximaciones servidas con tipografía segura.

Un botón de compartir entrega el resumen a **Threema**, que abre una aplicación local
con texto plano. Nada llega a un servidor de terceros, que es el único tipo de
compartición que esta herramienta puede ofrecer sin contradecir su propio pie de
página.

Threema es el canal de la casa para todo lo que esta herramienta entrega, y la razón
es aritmética más que una preferencia: está cifrado de extremo a extremo, autentica a
la persona y no a un dominio, y la clave que importa se comprueba escaneando un
código delante de alguien. Es exactamente la propiedad que necesita una auditoría
cuando envía una **huella** —véase más abajo: el informe puede ir por correo, la
huella no debe ir por el mismo camino.

`threema://` es un esquema de teléfono. En un ordenador que nunca lo ha registrado el
navegador rechaza el enlace, así que el resumen que habría llevado se imprime en un
desplegable bajo el botón, seleccionable con un clic.

## Hallazgos erróneos

Dos cosas distintas se llaman falso positivo, y no van al mismo sitio. El informe lo
dice bajo cada hallazgo, con el texto exacto que hay que usar.

**La herramienta tiene razón, pero el hallazgo se acepta aquí.** Es una decisión de
proyecto, así que vive en la declaración junto a las duraciones de los datos: un
archivo versionado, lo que significa que la revisión ocurre en la revisión de código,
sin servicio y sin base de datos:

```bash
sablier accept a3f1c2 --reason="SHA-1 impuesto por la especificación TOTP" --until=2027-04-01
```

Tres reglas se aplican en lugar de sugerirse, porque un archivo de supresión fácil de
escribir es la manera en que estas herramientas se vacían solas en seis meses:

- **un hallazgo aceptado no desaparece.** Pasa a su propia sección, con el veredicto
  que habría tenido, la razón dada y la fecha;
- **una aceptación caduca.** `until` es obligatorio, y el hallazgo vuelve solo el día
  en que vence, igual que la ventana se cierra sola;
- **la razón es obligatoria y está escrita para un humano.** Es lo que lee de verdad
  la persona que aprueba el cambio.

Una aceptación se indexa por la evidencia y no por el número de línea: decae cuando la
línea a la que se refería cambia materialmente. Es lo deseado: el código se movió, la
decisión merece una segunda mirada.

**La herramienta se equivoca.** Eso es una regla que corregir, y su sitio está aquí.
Cada hallazgo lleva un enlace que abre un informe pre-rellenado — el enlace abre su
navegador en un formulario que usted mismo completa; el archivo sigue sin enviar nada.

## La fecha, no la barra

Una barra frente a una marca vertical le pide al lector que haga la resta. Esa resta
tiene una sola respuesta y es una fecha, así que el informe la imprime bajo el
gráfico:

```
FECHAS DE CRUCE
  · copias — 10 años — cruce superado desde 2026
  · autenticación — 3 años — cruce el 1 de enero de 2033
```

Un dato cifrado el año Y sigue siendo sensible hasta Y más su duración, así que el año
de cruce es `caducidad − duración + 1`: el primer año cuya producción sobrevive al
algoritmo que la protege. Antes de él el dominio aguanta; a partir de él, todo lo
emitido está ya perdido el día en que el algoritmo cae — y migrar más tarde no llega
hacia atrás.

Dos condiciones, porque una fecha sobre el dominio equivocado es peor que ninguna
fecha. Trata de la **confidencialidad**, ya que una firma no se recolecta; y de un
algoritmo **que un ordenador cuántico rompe**, ya que un dominio protegido por AES o
ML-KEM puede guardar datos un siglo sin cruzar nada. Colorear solo por duración fue un
error que este proyecto ya corrigió una vez, en el gráfico; este es el mismo error en
palabras, y la prueba de regresión verifica el silencio.

El plan de acción deja de decir «repita esto una vez al año» y nombra la cita:
*Próximo cruce: autenticación, el 1 de enero de 2033.*

```bash
sablier scan . --calendar=cruces.ics
```

`--calendar` escribe los que aún están por venir en iCalendar: un evento de día
completo por dominio, plegado a 75 octetos como exige la especificación, porque una
herramienta que dedica su informe a decirle a la gente que lea la norma no tiene
derecho a ignorar ninguna. Una fecha en un informe se lee una vez; una fecha en una
agenda interrumpe a alguien en 2033, y es la única versión que funciona.

## Dos informes, para dos salas

`--audit=ARCHIVO` escribe un segundo documento a partir del mismo análisis. No es un
modo del primero: es otro documento, para otro lector.

El informe técnico se lee junto a un editor, por alguien que puede actuar. El informe
de auditoría lo lee un cliente, un comité, una aseguradora, un abogado: gente que no
escribió el código y que quizá tenga que sopesarlo en un litigio. Toma su forma de los
informes periciales y no de los cuadros de mando:

- **los hechos y la opinión están separados, y numerados.** La sección 5 constata, en
  una tabla numerada; la sección 7 concluye, citando los números en los que se apoya.
  Un lector puede aceptar un hecho y discutir la opinión construida sobre él, que es
  exactamente lo que hace un contrainterrogatorio;
- **el dato que decide el resultado se imprime entero.** Cada veredicto depende de
  duraciones que declaró un humano, así que la sección 6 las reproduce y dice
  claramente que la herramienta no puede ni verificarlas ni deducirlas del código;
- **los límites forman una sección numerada**, del mismo tamaño que el resto;
- **las referencias se citan con la fecha de su última comprobación**: un plazo citado
  de memoria no vale nada ante alguien pagado para comprobarlo;
- **un glosario** de los siete términos que el documento necesita, para no pedirle al
  lector que ya sepa qué es la recolección;
- **nada del auditor se inventa.** Un nombre ausente se imprime como un campo que
  completar, y una declaración ausente como una declaración que queda por redactar,
  fechar y firmar. Un informe que rellena un auditor plausible es una falsificación
  con buenas intenciones.

La identidad viene de dos archivos, porque se le estaban pidiendo dos cosas distintas
a un solo bloque. **El encargo** cambia en cada misión y se revisa con el proyecto al
que concierne, así que vive en la declaración versionada:

```json
"audit": {
  "client": "Example SAS",
  "reference": "AUD-2026-014",
  "mandate": "Establecer la exposición de los datos confidenciales a la recolección."
}
```

**El auditor** pertenece a una persona y no a un proyecto, y teclear su nombre en el
repositorio de cada cliente es la manera de que quede obsoleto en uno de ellos. Se
pone una vez en `~/.config/sablier/identity.json` (o donde apunte
`SABLIER_IDENTITY`), y se rellena solo en cada encargo:

```json
{
  "auditor": "A. Lambert",
  "organisation": "Lambert & Co",
  "statement": "Los hallazgos de la sección 5 fueron producidos por la herramienta nombrada en la sección 1…"
}
```

El archivo de identidad rellena lo que la declaración deja vacío y pierde todos los
conflictos: el archivo versionado es el que alguien revisó. `examples/identity.json`
es la plantilla.

Aquí no hay YAML y no lo habrá: PHP no incluye analizador de YAML, así que admitirlo
significa o una dependencia que este proyecto rechaza o un analizador escrito a mano —
y un analizador de YAML casero es un pasivo, no una funcionalidad.

```bash
sablier scan . --out=informe.html --audit=auditoria.html --pdf=informe.pdf --sign=sablier.key
```

Con `--pdf`, el documento de auditoría obtiene su propio PDF junto al técnico: es el
que se imprime, se firma y se archiva. Ambos existen en francés, inglés y español, y
ambos llevan la misma huella: la sección 10 la imprime, con el comando que un tercero
ejecuta para verificar la firma.

Lo que la herramienta no pretende: nada de esto hace admisible un documento en ninguna
parte. El auditor lo firma y lo defiende; Sablier produce los hechos, el método, los
límites y la aritmética, en una forma que sobrevive a ser leída por alguien que busca
un agujero en ella.

## Juzgar el inventario de otro

Los detectores no son el terreno donde esta herramienta puede ganar. CycloneDX 1.6 es
un formato publicado, varios escáneres lo emiten y tienen equipos detrás. Lo que nadie
más hace es cruzar un inventario con **cuánto tiempo debe seguir siendo secreto el dato
que protege**. Así que el inventario puede venir de cualquier parte:

```bash
sablier judge cbom.json --declare=sablier.json --out=informe.html
```

Un CBOM producido por otro escáner —en Java, en Python, en Go, un lenguaje que este
proyecto nunca analizará— sale de ese comando con un dominio, una duración y un
veredicto adjuntos a cada componente. Las ubicaciones del CBOM se confrontan con los
`paths` de su declaración exactamente como lo haría un análisis local:

```
  example-service — inventario importado de another-scanner 2.1.0, 3 ubicaciones, 5 hallazgos

    COMPROMETIDO             1
    ROTO HOY                 1
    VIGILAR                  2
    CONFORME                 1
```

Tres cosas se rechazan a la entrada, y son las que hacen que la importación sea
utilizable en lugar de halagadora:

- **la detección no es nuestra, y el informe lo dice** — en los puntos ciegos, con el
  nombre de la herramienta que la produjo. Juzgamos lo que nos entregaron; que ese
  escáner leyera bien el código es la afirmación de su autor;
- **un algoritmo que esta herramienta no conoce nunca se adivina.** Se cuenta y se
  nombra en el informe (`Componentes del CBOM sin juzgar … : 2 (Camellia, TLS)`),
  porque un importador que descarta en silencio lo que no entendió fabrica exactamente
  la falsa seguridad que este proyecto existe para rechazar;
- **la huella se recalcula, nunca se lee del archivo.** Un CBOM capaz de afirmar la
  huella de una aceptación existente atravesaría directamente la decisión asociada a
  ella.

Una distinción sobrevive al viaje, y la mayoría de los inventarios la pierden:
CycloneDX registra la **primitiva**, así que RSA firmando llega como firma y RSA
cifrando como transporte de clave — y esta herramienta trata la primera como no
recolectable y el segundo como recolectable, que es todo el modelo de riesgo.

El otro sentido es `--cbom=ARCHIVO`, tanto en `scan` como en `judge`:

```bash
sablier scan . --cbom=cbom.json --out=informe.html
```

Los hallazgos salen como componentes `cryptographic-asset` de CycloneDX 1.6, con el
veredicto, el dominio, la duración que lo produjo y la huella llevados como propiedades
`sablier:`. Dos cosas no se escriben deliberadamente: un `nistQuantumSecurityLevel`
distinto de cero —cero es lo que rompe un ordenador cuántico, y reivindicar los niveles
1 a 5 para todo lo demás sería inventar cifras— y un OID, que nunca se adivina. El
soporte de activos criptográficos es reciente en las herramientas que consumen CBOM; si
la suya rechaza algo que emitimos, es una regla que corregir y su sitio está en este
repositorio.

## Lo que se esconde en los archivos que nadie lee

Las imágenes, fuentes y archivos comprimidos de un repositorio se copian, nadie los
revisa y se entregan. También son un lugar cómodo para dejar algo. Tres comprobaciones,
graduadas por lo que realmente demuestran:

- **material de clave dentro de un activo binario.** Una cabecera PEM en un `.png` no es
  un accidente — y ya se encontraba, porque el detector de claves lee todos los archivos
  y no solo los que tienen nombre de clave. Lo nuevo es la frase que dice dónde: *«Bloque
  de clave encontrado en el byte 73 de un archivo .png. Un activo binario no es un sitio
  al que el material de clave llegue por accidente.»*;
- **bytes después del final de la imagen.** Un PNG termina en `IEND`, un JPEG en `FFD9`,
  y un archivo que continúa más allá lleva otra cosa. Se informa como **a confirmar**,
  con el número de bytes, nunca como veredicto: un perfil de color y un archivo
  exfiltrado se parecen vistos desde aquí, y solo uno de los dos es un problema;
- **una extensión que miente sobre el contenido.** Los bytes mágicos dicen qué es un
  archivo. Un `.png` que empieza por `PK\x03\x04` es un zip, lo que merece una mirada y
  nada más.

Esto deliberadamente **no** es detección de esteganografía, y el informe lo dice en sus
puntos ciegos. Un mensaje escondido en los bits bajos de una imagen es un problema de
investigación cuya tasa de falsos positivos enterraría cada hallazgo real que esta
herramienta imprime. Una herramienta que grita que viene el lobo por unas fotos de
vacaciones pierde el derecho a ser creída sobre una clave de copia de seguridad — por
eso la prueba de regresión que más importa aquí es la que verifica el silencio ante una
imagen corriente.

## Un agujero que alguien ya encontró

El resto de este informe discute sobre 2035. Un aviso de seguridad dice que alguien
encontró una vía de entrada antes de que se imprimiera el informe, lo que lo supera por
una década.

```bash
sablier advisories .                       # recoger, una vez, a propósito
sablier scan . --advisories=.sablier/advisories.json
```

El primer comando es el único de esta herramienta que alcanza la red, y la alcanza para
una base de datos y no con su inventario: el escáner corre en un contenedor fijado, lee
sus archivos de bloqueo desde un montaje de solo lectura, y escribe un archivo que usted
puede leer y versionar. Un análisis nunca hace nada de eso: ningún nombre de paquete
suyo sale de la máquina mientras se ejecuta.

Una biblioteca declarada con una vulnerabilidad publicada alta o crítica deja de ser
mero inventario y pasa a ser **ROTO HOY**, en la misma categoría que MD5 y SHA-1: un
defecto que no debe nada a lo cuántico y que va antes de cualquier migración. Los
números de aviso se imprimen con ella, enlazados a NIST, GitHub u OSV según quién los
emitiera.

Tres líneas lo sujetan:

- **solo se juzgan las bibliotecas que esta herramienta ya inventaría.** Un proyecto
  tiene decenas de dependencias vulnerables, y un informe que las lista todas entierra
  la criptografía por la que se le preguntaba. Las demás se cuentan en los puntos
  ciegos, para que el lector sepa que se vieron y se dejaron;
- **alto y crítico elevan un veredicto; medio y bajo se adjuntan, no se promueven.** El
  mismo umbral que `make cve` aplica a nuestros propios contenedores;
- **sin el archivo, el informe dice que la pregunta no se hizo** en lugar de dar a
  entender que la respuesta era no. Esa frase está en los puntos ciegos de todo análisis
  ejecutado sin él.

## Citar un defecto, y no citar un plazo

Un hallazgo roto hoy lleva el defecto publicado en el que se apoya —SHA-1 su CVE de
colisión, MD5 el suyo, RC4 y 3DES los suyos, TLS 1.0 y 1.1 los dos ataques que los
retiraron— impreso junto al veredicto, enlazado a la entrada de NIST que un lector puede
ir a comprobar sin creernos nada.

RSA y las curvas elípticas no llevan ninguno, y ese es el punto. Un CVE es un hecho
fechado que otro publicó; la caducidad post-cuántica es un horizonte reglamentario,
citado como tal en las referencias normativas del informe de auditoría. Archivar lo
segundo bajo lo primero convertiría un plazo en una acusación, y es el tipo de
deslizamiento que esta herramienta existe para rechazar.

Los números viajan con el inventario: `references` en la salida JSON, y
`externalReferences` de tipo `advisories` en el CBOM, donde todo consumidor ya sabe
leerlos.

## En una cadena de integración

Un informe que nadie compara es un veredicto sobre el que nadie actúa, y todo el
argumento de esta herramienta es que la ventana se cierra sola: el mismo código,
analizado el año que viene, puede ponerse rojo sin que se haya movido una línea, y una
aceptación vence en una fecha elegida meses antes. Así que la segunda ejecución es la
que importa.

La referencia es el informe JSON de una ejecución anterior —sin segundo formato, y un
archivo pensado para versionarse junto a la declaración:

```bash
sablier scan . --json=.sablier/baseline.json --out=informe.html   # una vez
git add .sablier/baseline.json                                    # revisado como cualquier archivo
```

Luego cada ejecución se compara con ella:

```bash
sablier scan . --baseline=.sablier/baseline.json --out=informe.html
```

```
  referencia: .sablier/baseline.json (12 hallazgos)

    + 1 hallazgo nuevo
        36d82f61  ROTO HOY             sha1  src/NewToken.php:3
    ↑ 1 veredicto empeorado
        d45d9d61  VIGILAR → COMPROMETIDO  rsa   deploy/backup.sh:3
    ● 1 hallazgo rojo ya conocido, sin decisión
        d87d2d2b  ROTO HOY             sha1  src/Tokens.php:17
    − 2 hallazgos desaparecidos: toca refrescar la referencia

  ✗ hay que revisarlo: 3 decisiones pendientes.
     Corrija, o decida: sablier accept <huella> --reason="…" --until=AAAA-MM-DD
```

Tres cosas detienen la construcción, y son las tres que requieren un humano: un
hallazgo **nuevo**, un veredicto **empeorado** —una aceptación vencida aparece aquí— y
un **hallazgo rojo sobre el que nadie ha decidido**. Los hallazgos desaparecidos se
imprimen y no detienen nada; son la razón para refrescar la referencia.

| Código | Significado |
|---|---|
| `0` | nada nuevo, nada rojo pendiente — adelante |
| `2` | hay una decisión pendiente |
| `1` | error de uso: ruta ausente, referencia ilegible |

**La referencia no es un archivo de supresión.** Un hallazgo rojo que ya registra sigue
deteniendo la construcción, en cada ejecución, hasta que alguien lo corrija o lo acepte
—con una razón, una fecha de caducidad y un revisor, como se describe más arriba. Una
referencia que silencia lo que registra es la manera en que estas herramientas se vacían
solas en seis meses, y las fechas de esta vuelven por sí mismas.

Refrescar la referencia es por tanto un commit deliberado, revisado como cualquier
otro. Una cadena que la regenera tras cada fallo no registra nada.

```yaml
name: criptografía

on: [push, pull_request]

jobs:
  sablier:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          extensions: sodium, openssl, json
          coverage: none

      - name: Obtener Sablier
        run: git clone --depth 1 --branch v0.5.0 https://github.com/mesa-black/sablier.git "$RUNNER_TEMP/sablier"

      - name: Inventariar la criptografía
        run: |
          php "$RUNNER_TEMP/sablier/bin/sablier" scan . \
            --baseline=.sablier/baseline.json \
            --out=sablier-report.html \
            --no-probe

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sablier-report
          path: sablier-report.html
```

Fije una etiqueta y no una rama: esta herramienta decide si su construcción pasa.
`--no-probe` es deliberado: un ejecutor sondea sus servidores desde la red de otro, lo
que mide el camino de ese otro y no el suyo; lance la sonda desde una máquina que
alcance sus propios servicios, de forma programada. Y suba el informe `if: always()`,
porque la ejecución que más querrá leer es la que falló.

Sin `--baseline`, el código de salida es `2` solo cuando hay un hallazgo
`COMPROMETIDO`. Es suficiente para probar la herramienta, no para vivir en una cadena.

`--quiet` **no escribe ningún informe salvo que usted nombre uno**. Lanzado a mano,
`scan` deja un `report.html` a su lado porque es a lo que vino; lanzado con `--quiet`,
responde en el código de salida y solo escribe los archivos que usted pidió por su ruta.
Una herramienta que deja una página no solicitada en la raíz del repositorio de alguien
en cada construcción está dejando estado detrás.

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

## En una red que no la tiene

```bash
sablier scan /ruta/del/proyecto --airgap --out=informe.html --pdf=informe.pdf
```

`--airgap` rechaza en lugar de desactivar. `--no-probe` es una comodidad: salta un paso
que usted podría haber ejecutado; en un sitio cerrado esa es la forma equivocada,
porque una bandera que se puede olvidar es una bandera que se olvidará. Así que
`sablier probe` y `sablier advisories` se detienen con un mensaje que nombra qué hacer
en su lugar, todo contenedor se rechaza puesto que un contenedor se descarga, y un
host de sonda declarado se salta y **se escribe en los puntos ciegos** en lugar de
descartarse en silencio. Un sitio lo fija una vez para todos con `SABLIER_AIRGAP=1`.

El PDF no tiene entonces navegador que tomar prestado ni contenedor del que sacar uno,
así que se compone aquí: A4, las tres fuentes que todo lector ya tiene, y un número de
página en cada página — lo único que la exportación por navegador no sabe hacer, porque
Chrome ignora el CSS que lo llevaría. Más sobrio que el HTML impreso, y existe, que es
todo el argumento: un informe que no se puede imprimir no se puede firmar ni archivar.

Nada en esta herramienta alcanza la red salvo que usted nombre un host. Los sockets
existen en exactamente cuatro archivos —`Probe.php`, `SshProbe.php` y los dos
transportes— todos ellos detrás de `sablier probe` y del paso de sonda de un análisis,
que `--no-probe` elimina. `sablier advisories` es el único comando que sale, y sale a
por una base de vulnerabilidades y no con su inventario.

Esa afirmación está fijada por una prueba en lugar de afirmarse: la lista de archivos
autorizados a abrir un socket se comprueba en cada ejecución, y la construcción falla el
día en que un detector adquiere uno. Donde el núcleo lo permite, la suite ejecuta además
un análisis completo con la pila de red retirada (`unshare -rn`) y compara el resultado.

Importa porque lo sensible es la salida. Un inventario de dónde vive la criptografía de
un sistema es tan sensible como el sistema, así que en una red cerrada la pregunta no es
si una herramienta promete no enviar nada, sino si *puede*. No hay telemetría, ni
comprobación de actualizaciones, ni dependencia que descargar: cuatro líneas de
autocargador, PHP 8.4, y un repositorio que alguien puede leer en una tarde antes de
llevarlo dentro.

## Firmar un informe, con la firma que le decimos que adopte

```bash
sablier keygen                                   # dos claves, Ed25519 y ML-DSA-65
sablier scan /ruta --sign=sablier.key --out=informe.html
sablier verify informe.html.sig --declare=sablier.json
```

Durante tres versiones esta herramienta dijo a la gente que migrara sus firmas antes de
2030 y firmó sus propios informes solo con Ed25519 — y lo decía, en sus propios
hallazgos. La razón no era pereza: **PHP no sabe hacerlo.** libsodium no expone ninguna
firma post-cuántica, y ext-openssl lee una clave ML-DSA pero se niega a firmar con ella,
porque su interfaz toma un resumen y ML-DSA es un esquema puro, sin nada que pre-hashear.
`openssl_sign` responde `invalid digest`.

El **binario** openssl sí puede, desde la 3.5, y es el que la sonda ya toma prestado.
Así que un informe lleva ahora dos firmas: Ed25519, verificable en cualquier sitio donde
corra PHP, y ML-DSA-65 además. Tres reglas lo mantienen honesto:

- **además, nunca en lugar de** — sustituir una por otra haría los informes
  inverificables para quien tenga la biblioteca más antigua, que es casi todo el mundo.
  Es también lo que pide la ANSSI y lo que esta herramienta cita: la hibridación;
- **prestado, nunca implementado** — una firma basada en retículos escrita a mano, en
  una herramienta cuyo crédito entero descansa en no inventar criptografía, sería lo
  peor que podría entregar;
- **dicho en voz alta cuando falta** — en un OpenSSL más antiguo el informe indica que
  lleva una sola firma y por qué, y `verify` distingue *no coincide* de *no se ha podido
  comprobar aquí*. Confundir ambas convertiría una biblioteca ausente en una acusación
  de falsificación.

### Una clave que firma una vez

```bash
sablier scan /ruta --sign=ephemeral --out=informe.html
#   Clave creada para este informe, usada una vez, destruida. Huella de ambas claves:
#       7D52 D126 6B6B EA5D 58D4 1FE8 48D4 AFD9
sablier verify informe.html.sig --fingerprint="7D52 D126 …"
```

`--sign=ephemeral` fabrica el par para este informe, firma y destruye las mitades
privadas antes de que el comando devuelva el control. Nada que guardar, nada que robar,
nada que rotar — y una clave que nunca podrá firmar un segundo documento, propiedad que
una clave de larga duración no tiene.

Lo que ata entonces el informe a una persona es la **huella**, no un archivo: una línea,
llevada por un canal que ya prueba quién habla. Una clave pública ML-DSA ocupa 2,7 kB y
nadie pega eso en un mensaje; dieciséis bytes de SHA-256 sobre ambas claves caben en una
frase, y el destinatario coteja el archivo con ellos. Las claves de host SSH se
autentican así desde hace treinta años.

**El informe y la huella no deben viajar por la misma vía.** Quien pueda alterar uno en
tránsito puede alterar la otra, y toda la garantía se derrumba. El informe por correo,
la huella por Threema o de viva voz — no ambos por correo.

El informe de auditoría imprime la huella en su sección de integridad, para que un
lector que tenga el documento meses después siga teniendo con qué comparar.

Para una clave de larga duración, ambas mitades están reconocidas por la declaración
versionada, `signing_public_key` y `signing_public_key_pq`. Una clave post-cuántica
afirmada solo por el archivo que firma no valdría nada para el único lector para el que
esta firma existe: el que ya sabe falsificar la otra mitad.

### Qué se firma realmente

**Una huella de los hallazgos, no el archivo.** Dos ejecuciones del mismo inventario
difieren byte a byte —una fecha de renderizado, una duración— mientras dicen exactamente
lo mismo; dos renderizados en dos idiomas dan la misma huella.

**Cada informe nombra al anterior.** Una segunda ejecución sobre la misma ruta de salida
lee la firma que va a reemplazar y registra esa huella dentro de lo que firma, sin
bandera que recordar — de modo que una carpeta de informes es un rastro de auditoría y
no un montón de archivos, y `sablier verify nuevo.sig --previous=antiguo.sig` dice si el
eslabón aguanta. Un informe que reclama un predecesor lo dice aunque el archivo anterior
no esté a mano: quien tiene un documento se entera de que existe otro.

Con una clave efímera cada eslabón está firmado por un par distinto, así que la cadena
es una sucesión de declaraciones autenticadas por separado que se citan entre sí, y no
una clave que responde por todas. El destinatario necesita cada huella, y el informe de
auditoría imprime la suya.

Aquí no hay cadena de bloques y no la habrá. Una cadena propia es un nodo, es decir una
persona: no más digna de confianza que la firma que sustituiría. Una cadena pública
significa que la huella sale de la máquina, lo que rompe la promesa del pie de página
del propio informe. Cuando una fecha debe ser oponible a alguien que no confía en usted,
una autoridad de sellado de tiempo lo resuelve en una petición.

## Los tres contenedores, y qué se afirma sobre ellos

Una herramienta que lee dónde están sus claves no tiene por qué decirle que ejecute
imágenes que no ha mirado. Tres se nombran en este repositorio —`php:8.4-cli-alpine`
para máquinas sin PHP, `ghcr.io/phpstan/phpstan` para el análisis estático, y el propio
escáner— y un comando las vuelve a comprobar las tres:

```bash
make cve
```

Falla ante cualquier vulnerabilidad alta o crítica, en **ambas arquitecturas**: una
etiqueta multiarquitectura son varias imágenes reconstruidas en momentos distintos, y una
afirmación que solo vale para el portátil donde se hizo no es una afirmación. Se ejecuta
en integración continua en cada envío **y cada lunes**, porque una imagen sin
vulnerabilidades conocidas hoy no es una imagen sin vulnerabilidades conocidas en marzo.
Ya ha atrapado una: un aviso de pcre2 que llegó a la imagen de PHPStan entre dos
ejecuciones, horas antes de que la reconstruyeran aguas arriba.

Que es el caso que la barrera tiene que sobrevivir sin ser desactivada, y llegó el mismo
día. `.trivyignore.yaml` lleva esa decisión: una declaración que alguien escribió y una
fecha en la que deja de ser cierta, exactamente las dos cosas que `sablier accept` exige
a quien use esta herramienta. Hoy se mantiene una entrada: **CVE-2026-103111**, pcre2 en
la imagen de PHPStan, corrección publicada aguas arriba e imagen aún sin reconstruir;
las únicas expresiones regulares que llegan a ese contenedor son las de este
repositorio. Caduca el 2026-10-22, tras lo cual la barrera vuelve a ponerse roja en vez
de quedarse verde en silencio — que es toda la diferencia entre una decisión y un
archivo de supresión.

La afirmación es exactamente esa, y no más amplia: *ninguna vulnerabilidad alta o crítica
conocida, según la base de Trivy en el momento del análisis*. No se afirma nada sobre las
desconocidas, ni sobre los hallazgos bajos y medios, visibles en la misma salida.

La imagen Alpine no es un gusto: al escribir esto, Trivy reporta **162 vulnerabilidades
altas o críticas en `php:8.4-cli`** —46 de ellas con corrección disponible— y **ninguna**
en `php:8.4-cli-alpine`. Las versiones fijadas en el `Makefile` son las que usan
`make cve`, el lanzador y la integración continua, de modo que la cifra de arriba está a
un comando de ser contradicha.

El análisis estático corre a **nivel máximo** (`make phpstan`), en un contenedor por la
misma razón: este proyecto no entrega ningún directorio `vendor/`, y una herramienta de
calidad no es motivo para empezar uno.

## Lo que la herramienta se niega a hacer

- **Adivinar.** Un algoritmo que viene de una variable se reporta como indeterminado,
  con su ubicación. Un inventario equivocado es peor que uno incompleto, porque nadie
  comprueba un inventario dos veces.
- **Predecir.** La fecha de caducidad usada es el plazo reglamentario (2035 por defecto,
  configurable), no una profecía sobre cuándo llega un ordenador cuántico.
- **Gritar.** La criptografía simétrica fuerte se reporta como conforme, una firma no se
  trata como una fuga, un `md5()` usado como clave de caché se archiva como fuera de
  tema, y una dependencia declarada nunca es una alerta roja: es un uso a confirmar.
- **Corregir por su cuenta.** Reescribir criptografía sin entender el contexto es un
  generador de incidentes.
- **Irse.** Sin cuenta, sin subida, sin telemetría, sin dependencias.

## Lo que no ve

El informe imprime sus propios puntos ciegos, al mismo tamaño que todo lo demás: la
criptografía de los servicios gestionados, la negociación TLS real de los hosts no
declarados, las claves guardadas en un HSM, y las duraciones de datos que nadie declaró.

Un inventario que no dice lo que no ha mirado no es un inventario.

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
