# Qué dicen los informes, y a quién se dirigen

*← volver al [README](../README.es.md)*

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

## El tercer factor, contado y no estimado

El riesgo cuántico de la hoja de ruta europea se apoya en tres cosas: la debilidad
de la criptografía, el impacto de una ruptura, y *"the estimated time and effort
required to migrate"*. Esta herramienta medía las dos primeras y no decía nada de
la tercera — la única con la que un equipo planifica de verdad, y la que cada
proveedor responde con una cifra que nadie puede comprobar.

El informe cuenta ahora lo que hay que cambiar, por algoritmo: llamadas, archivos,
dominios, cuántas entradas están declaradas en lugar de observadas en una llamada,
y cuántas nombran el algoritmo en una variable o una configuración en vez de en la
llamada misma. Ese último recuento es la definición que la hoja de ruta da de la
agilidad criptográfica — *"a modular way that enables replacing the cryptographic
components"* — observada en lugar de afirmada, y señala las llamadas más baratas
de cambiar.

Cada cifra está ya en el inventario; ninguna es una inferencia. Dos entradas del
catálogo que comparten etiqueta se distinguen por su uso, porque dos filas que
dicen «RSA» son la forma en que un lector deja de creer una tabla. Un algoritmo
sano, o una huella usada como clave de caché, no es trabajo y no se lista. Sin
nada que cambiar, el bloque no se muestra.

**Lo que no hará es convertir eso en una duración.** Ocho llamadas en un archivo
detrás de una misma función son una tarde; ocho repartidas en seis servicios con
un protocolo entre ellos son un trimestre, y nada en un repositorio distingue
ambos casos. Una herramienta que imprimiera «tres semanas» inventaría la única
cifra del informe que no se puede comprobar — y sería creída, precisamente porque
es la cifra que alguien necesitaba. El recuento es nuestro; la estimación es del
lector, y el bloque lo dice donde están las cifras.

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

## Componer el informe en PDF

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
