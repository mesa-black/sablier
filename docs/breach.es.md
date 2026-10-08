# Después de una filtración

*← volver al [README](../README.es.md)*

## Cuando el agujero ya se usó

Un aviso de seguridad dice que alguien encontró una entrada. Una fuga dice que
alguien pasó por ella, y toda la aritmética de esta herramienta se lee entonces
al revés.

```bash
sablier scan . --breached=2026-07-29
```

En todo lo demás aquí el razonamiento va hacia adelante: un adversario captura
hoy lo que leerá cuando el algoritmo caiga. Después de una fuga ya no espera —
lo tiene — y la única pregunta que queda es cuánta de la confidencialidad pedida
puede todavía sostener la criptografía. Datos salidos en el año F deben seguir
secretos hasta F + duración; el algoritmo que los protege deja de ser creíble al
caducar el régimen; lo que queda entre ambos es la parte que pasa a ser legible,
y migrar después no la alcanza.

La fecha se pone en el dominio, porque una tabla robada no es una afirmación
sobre todo el sistema:

```json
{ "name": "backups", "lifetime_years": 10, "breached": "2026-07-29" }
```

En la línea de comandos se aplica a todos los dominios a la vez, que es el peor
caso y debe leerse como tal. Cada dominio afectado recibe entonces una línea:

- **el texto en claro pierde toda la duración.** Nada tiene que caer para que
  esos datos sean legibles, porque nada los protegía;
- **un algoritmo al que el cuántico alcanza pierde la cola.** Diez años pedidos,
  una salida en 2026, un algoritmo creíble hasta 2035: un año de lo robado pasa
  a ser legible, y ninguna migración lo alcanza;
- **un algoritmo al que el cuántico no alcanza no pierde nada**, y la línea lo
  dice en lugar de callarse.

Tres negativas evitan que esto se convierta en un generador de notificaciones de
brecha. La herramienta **cuenta años, nunca personas** — cuántos registros
salieron es asunto del equipo de incidentes, cuánto tiempo siguen haciendo daño
es la pregunta que nadie más hace. Solo habla de los **dominios que alguien
declaró afectados**. Y **dice lo que no puede saber**: ignora qué salió
realmente, si salió cifrado, y si las claves se fueron con ello, y esa frase se
imprime junto a la cifra.

Tampoco es una pretensión de prevención. Las fugas que llegan a los titulares
son credenciales robadas y equipos sin parchear, y nada en esta herramienta
habría detenido una. Lo que sabe hacer es responder a la pregunta de la semana
siguiente: cuánto dura el daño.

### El documento de la semana siguiente

El bloque anterior vive en el informe técnico, que se lee junto a un editor. La
semana que sigue a una fuga, la pregunta se plantea en otra sala — un DPD, un
departamento jurídico, un comité — y la respuesta debe ser lo bastante corta para
leerse de una vez:

```bash
sablier scan . --breached=2026-07-29 --incident=incident.html
```

Seis secciones, una página o dos: lo que el documento es y no es, lo que se
declaró afectado y por quién, cuánto tiempo queda protegido cada dominio, lo que
aún puede hacerse, el método y sus límites, la huella. No se parece al informe de
auditoría — sans serif, sin índice — porque dos documentos del mismo análisis que
se parecen es como se archiva el equivocado.
[`examples/incident.html`](examples/incident.html) es uno, con su
[PDF](examples/incident.pdf).

Tres negativas:

- **no es una notificación.** El artículo 33 pide las categorías y el número
  aproximado de personas y registros afectados. Este documento no contiene
  ninguno, lo dice en la sección 1, y nombra a quién pertenece esa obligación;
- **se niega a escribirse sin fecha.** Sin fuga declarada, no hay documento: un
  informe posfuga producido por una herramienta que decidió por sí misma que
  había una fuga es peor que no tener informe;
- **clasifica las medidas por lo que alcanzan.** Renovar las claves, volver a
  cifrar lo que aún se conserva y notificar son todas necesarias, y ninguna toca
  los datos que ya salieron. Una medida sí lo hace — reducir la conservación allí
  donde la duración es una elección y no un mínimo legal — y el documento dice
  cuál, en lugar de alinear cuatro medidas que se leen como equivalentes.
