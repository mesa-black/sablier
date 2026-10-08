# Lo que detecta, y hasta qué punto está seguro

*← volver al [README](../README.es.md)*

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

## Lo que declara un framework

La mayor parte de esta herramienta lee código. Los hechos criptográficos más
útiles de una aplicación web no están en su código: nadie escribe `RS256` en un
controlador. Se escribe una vez en un firewall, y todos los inicios de sesión
de los cinco años siguientes lo usan.

```
config/packages/security.yaml      hash de contraseñas · OIDC · tokens
config/packages/lexik_jwt_*.yaml   la firma detrás de cada token de API
config/packages/doctrine.yaml      si la conexión a la base está cifrada
config/app.php · hashing.php       el cifrado y el hash de Laravel
config/jwt.php · database.php      tymon/jwt-auth, y sslmode
config/filesystems.php             el cifrado en reposo pedido al almacenamiento
config/passport.php                las claves RSA que firman los tokens OAuth2
config/broadcasting.php            si el tiempo real va por TLS
app/Config/Encryption.php          el cifrado y el digest de CodeIgniter
config/web.php                     las cookies firmadas de Yii
```

Laravel recibe una cosa más, y habla de esfuerzo más que de algoritmos.
`Crypt::encryptString()`, `Hash::make()` y la función suelta `encrypt()` no
nombran ningún algoritmo — el cifrado está en `config/app.php`, el driver en
`config/hashing.php` — así que la configuración por sí sola da un hallazgo por
aplicación y no dice nada de cuánto depende de ella. Esas llamadas también se
registran, con **confianza media** y sin pretender nunca nombrar el cifrado,
porque el día en que haya que cambiarlo lo que cuenta es cuántos sitios hay que
abrir. Ese es el tercer factor del modelo de riesgo, contado en sitios en lugar de
estimado en días. Las funciones sueltas solo se leen en un archivo que importa
`Illuminate`: `encrypt()` es el nombre de función más genérico del lenguaje, y
fuera de Laravel pertenece a otro.

Symfony necesitó un detector propio, porque es el único framework aquí que pone su
configuración de seguridad en YAML — y mientras este no existió, una herramienta
que solo abría archivos `.php` pasaba de largo por toda ella.

**Decide el valor, no la clave.** `algorithm:` aparece en una docena de sitios sin
relación en una configuración de Symfony, así que un patrón solo coincide cuando
el valor es un algoritmo de hash o un algoritmo JOSE que esta herramienta conoce.
El coste de equivocarse ahí se midió en vez de imaginarse: una primera versión
leyó `cookie_secure: auto` en una aplicación real e informó de un hash de
contraseñas que no existe, porque `auto` es también el nombre de uno. La fixture
contiene ahora esa línea exacta, en un archivo que no declara ningún hash, y una
prueba falla si alguna vez se vuelve a leer como tal.

**`HS256` y `RS256` no son lo mismo**, y un informe que imprime el nombre JOSE y
se detiene no le ha dicho nada a su lector. El primero es un secreto compartido y
sobrevive a un computador cuántico; el segundo es una firma RSA y no.

**OIDC es el caso que justifica por sí solo este detector.** Un firewall que
delega el inicio de sesión en un proveedor de identidad nombra al proveedor y
nunca la firma: el algoritmo viene de las claves que ese proveedor publica, así
que no está en el repositorio ni puede estarlo. Es toda la tesis de esta
herramienta enunciada por el formato de configuración de otro — todo el camino de
autenticación descansa en un algoritmo que nadie aquí eligió — así que se informa
como indeterminado y pide ser declarado.

Y se queda en su carril. `verify_peer: false` bajo `http_client` es un defecto real
y deliberadamente no se informa: es un problema de la autenticación de hoy, no de
cuándo deja de aguantar un cifrado, y una herramienta que empieza a informar de
todos los olores de seguridad pierde el derecho a ser creída sobre 2035.

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
