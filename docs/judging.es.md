# Juzgar el inventario de otro

*← volver al [README](../README.es.md)*

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
