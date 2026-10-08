# Firmar un informe, y fecharlo

*← volver al [README](../README.es.md)*

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

Aquí no hay blockchain y no la habrá. Una cadena propia es un nodo, es decir una
persona: no más digna de confianza que la firma que sustituiría. Una cadena pública
significa que la huella sale de la máquina, lo que rompe la promesa del pie de página
del propio informe. Cuando una fecha debe ser oponible a alguien que no confía en usted,
una autoridad de sellado de tiempo lo resuelve en una petición — que es la sección
siguiente.

### Una fecha atestiguada por otro

Todas las firmas anteriores prueban dos cosas y no una tercera: **qué clave firmó y qué
hallazgos firmó.** El campo `signed_at` está cubierto por la firma, así que no se puede
editar después — y se lee del reloj de la máquina que firmó, la suya. Antedatar un
informe no cuesta nada, y el encadenamiento no ayuda: una sola clave sostiene todos los
eslabones, así que la cadena entera puede reconstruirse en orden y se comprobará
perfectamente. Estos sellos responden a *quién* y a *qué*. Nada en ellos responde a
*cuándo*.

```bash
sablier scan . --sign=sablier.key --timestamp=https://tsa.ejemplo.org/tsr
```

Una autoridad de sellado de tiempo recibe la huella, nunca el documento, y devuelve un
token firmado que dice que esa huella le fue presentada en ese instante. No tiene
ningún interés en sus conclusiones, y ahí está todo el interés.

**Lo que se atestigua es la huella** — no la firma, no el archivo. Está impresa en el
informe, así que la atestiguación se comprueba sin referencia alguna a esta herramienta:

```bash
openssl ts -verify -digest <la huella impresa en el informe> \
  -in report.html.tsr -CAfile <la raíz de la autoridad>
```

Por eso también el token es un archivo aparte, en DER puro junto al `.sig`: es
exactamente lo que lee el comando `openssl ts` de serie. Y sobrevive a una clave
efímera — la clave se destruye, la fecha atestiguada no.

**No hay autoridad por omisión.** Quién atestigua sus fechas es una decisión, como el
régimen y las duraciones, y un valor por omisión la tomaría por usted en una
jurisdicción que no eligió. La opción toma una URL o no hace nada.

`sablier verify` recoge el token por su cuenta cuando está depositado junto a la firma,
e informa de cuatro estados en lugar de dos, porque confundirlos sería mentir:

| | sentido |
|---|---|
| fecha atestiguada, comprobada | la firma de la autoridad aguanta, hasta una raíz de confianza de esta máquina |
| fecha atestiguada, cadena no comprobada | la huella corresponde a este informe; no se pudo construir ninguna cadena hasta una raíz de confianza — autoridad autofirmada o intermedio ausente, no una falsificación. Pase `--timestamp-ca=<archivo>` |
| inválido | el token atestigua otra huella, o fue manipulado. Esto hace fallar el comando |
| no comprobable aquí | sin openssl, o sin almacén de certificados contra el que comprobar |

La huella se compara **antes** de cualquier cuestión de confianza, y ese orden es el
punto: `openssl ts -verify` se detiene ante una cadena que no sabe construir, así que
sin esa comparación «no logro establecer la cadena» y «este token habla de otro
documento» volvían como la misma respuesta.

**El límite, impreso en el informe en vez de dejarse para descubrir.** Una autoridad de
sellado de tiempo firma con RSA o ECDSA, que el propio catálogo de esta herramienta
clasifica como vulnerables al cuántico. Un token es prueba para un litigio en los
próximos años, no para 2040; conservar una fecha más allá significa volver a
atestiguarla mientras el esquema aguante. Una herramienta que dedica cuarenta páginas a
decir que las firmas caducan no se concede una excepción para aquella de la que depende.

### Firmar la entrada, no solo la salida

Un informe se firma, se verifica, se encadena — y las duraciones sobre las que se
apoya cada uno de sus veredictos eran una cadena de texto que cualquiera podía
escribir en `declared_by`. El único artefacto aquí que compromete a personas era
el único que nadie firmaba.

```bash
sablier endorse sablier.json         # clave efímera, destruida antes de volver
sablier verify sablier.json.sig --declare=sablier.json
```

Lo que se firma son las **decisiones y no los bytes**: el régimen, las duraciones,
las rutas, los trust anchors, las notas y los autores, con dominios y rutas
ordenados. Reformatear el archivo, reordenar sus claves, recomponer una nota — el
respaldo se mantiene. Corregir una duración, añadir una ruta, cambiar de régimen —
se rompe, que es lo que espera quien respaldó ese archivo.

El informe de auditoría imprime entonces una de tres cosas, en la misma sección
que reproduce las duraciones: respaldada en tal fecha, con la huella de las
claves; **sin firmar**, con el comando que lo arregla; o — el caso interesante —
una firma que ya no concuerda, es decir que el archivo sobre el que se apoya este
informe no es el que alguien refrendó.

La clave es efímera por omisión, como la de los informes. Una declaración
respaldada al final de una entrevista, ante la persona que la declaró, es
exactamente el caso para el que se inventó esa clave: nada que almacenar, nada que
rotar, y la huella viaja por el canal que ya prueba quién es.
