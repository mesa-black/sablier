# Cómo está montado, y qué se niega a hacer

*← volver al [README](../README.es.md)*

## Cómo está montado

Dos puntos de extensión, porque el estudio de alcance nombra dos ejes que de verdad
van a crecer — y nada más recibe una interfaz.

```
DetectorInterface   una manera de encontrar criptografía en un tipo de archivo
  PhpDetector · ShellDetector · KeyMaterialDetector · AssetDetector
  EnvDetector · ServerConfigDetector · SshConfigDetector · TerraformDetector
  FrameworkConfigDetector · FrameworkYamlDetector · LaravelDetector
  SymfonyVaultDetector · DependencyDetector

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
