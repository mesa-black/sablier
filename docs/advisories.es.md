# Vulnerabilidades publicadas

*← volver al [README](../README.es.md)*

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
