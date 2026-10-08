# En una red cerrada

*← volver al [README](../README.es.md)*

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
