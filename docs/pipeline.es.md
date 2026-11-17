# En una cadena de integración

*← volver al [README](../README.es.md)*

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
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@v5

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          extensions: sodium, openssl, json
          coverage: none

      - name: Obtener Sablier
        run: git clone --depth 1 --branch v0.12.1 https://github.com/mesa-black/sablier.git "$RUNNER_TEMP/sablier"

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
Fije el ejecutor por la misma razón: `ubuntu-latest` es un nombre que pasa a un sistema
nuevo según el calendario de otro, por eso este proyecto nombra `ubuntu-26.04` y lo
cambia en un commit propio.
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

## Los tres contenedores, y qué se afirma sobre ellos

Una herramienta que lee dónde están sus claves no tiene por qué decirle que ejecute
imágenes que no ha mirado. Tres se nombran en este repositorio —`php:8.5-cli-alpine`
para máquinas sin PHP, `ghcr.io/phpstan/phpstan` para el análisis estático, y el propio
escáner— y un comando las vuelve a comprobar las tres:

```bash
make cve
```

Cada una de las tres está fijada **por huella**, no solo por etiqueta. Una
etiqueta es un nombre y un nombre puede reapuntarse; `make cve` prueba algo sobre
bytes, y esa prueba no valdría nada si los bytes pudieran cambiar bajo el nombre
sobre el que se hizo. `make images` muestra a qué apuntan hoy esas etiquetas,
para que mover una fijación sea una decisión que alguien toma y no algo que le
ocurre.

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
a quien use esta herramienta. Las entradas no se enumeran aquí, porque no se quedan
quietas: cada una nombra un aviso, dice por qué no alcanza el uso que este proyecto hace
de la imagen, y caduca en semanas y no en meses. La ejecución programada del lunes
vuelve a hacer la pregunta, y una entrada vencida pone la barrera roja otra vez en vez
de dejarla verde en silencio. Así que cada entrada se renueva, con una fecha nueva y una
declaración comprobada de nuevo, o se retira en cuanto una imagen reconstruida la
vuelve inútil — que es toda la diferencia entre una decisión y un archivo de supresión.
El archivo y su historial dicen qué se mantiene hoy.

La afirmación es exactamente esa, y no más amplia: *ninguna vulnerabilidad alta o crítica
conocida, según la base de Trivy en el momento del análisis*. No se afirma nada sobre las
desconocidas, ni sobre los hallazgos bajos y medios, visibles en la misma salida.

La imagen Alpine no es un gusto. Cuando se tomó la decisión, el 2026-10-01, Trivy
reportaba **162 vulnerabilidades altas o críticas en `php:8.4-cli`** —46 de ellas con
corrección disponible— y **ninguna** en `php:8.4-cli-alpine`. Esa cifra es una medida
pasada, conservada porque es la razón; el lanzador ha pasado después a
`php:8.5-cli-alpine`. Las versiones fijadas en el `Makefile` son las que usan
`make cve`, el lanzador y la integración continua, de modo que la respuesta de hoy está
a un comando, y la contradicción también.

El análisis estático corre a **nivel máximo** (`make phpstan`), en un contenedor por la
misma razón: este proyecto no entrega ningún directorio `vendor/`, y una herramienta de
calidad no es motivo para empezar uno.
