# Conducir la entrevista — chuleta

*[Français](session-script.fr.md) · [English](session-script.en.md)*

Una página para tener delante durante la sesión. El protocolo y lo que hay que
medir están en [`declaration-session.es.md`](declaration-session.es.md); esto
es el guion.

```bash
sablier declare /ruta/del/proyecto --log=session.json --lang=es
```

## Lo que oye la persona

Cada asunto se abre con lo que la herramienta ha encontrado, sin una sola
palabra técnica, y luego tres preguntas. Un ejemplo real:

> **Asunto 1 de 4 · 3 archivos**
>
> Aquí la aplicación guarda ajustes que lee al arrancar: a qué se conecta, con
> qué cuenta y con qué contraseña. Nada de eso está cifrado: es un archivo de
> configuración.
> *En: .env, .env.dev, .env.test*
>
> 1. **Si alguien obtuviera una copia de esto, ¿de qué estaríamos hablando, en sus palabras?**
> 2. **¿Cuántos años debe guardar esto?** (una ley, un contrato o su propia norma; 0 si nada lo exige)
> 3. **Si esto saliera hoy, ¿durante cuántos años seguiría causando daño?** (0 si es público o inocuo)

La duración retenida es **la mayor de las dos** —un dato que hay que guardar es
un dato que todavía se puede robar— y la herramienta dice cuál de las dos ha
ganado, para que se pueda discutir el razonamiento y no la cifra.

## Cuando se atasca

| Lo que dice | Lo que usted responde |
|---|---|
| «No lo sé.» | «¿Quién lo sabría, en la casa?» Apunte el nombre y salte el asunto. **Un asunto saltado es un resultado**, no un fracaso. |
| «Para siempre.» | «¿Lo dice alguna ley o algún contrato?» Si no: «Dentro de treinta años, ¿le molestaría a alguien todavía?» Una cifra, aunque sea grande, vale más que una palabra. |
| «Eso no saldrá nunca.» | «De acuerdo: la pregunta es *si* saliera.» No negocie este punto, es todo el método. |
| «Tres meses.» | Redondee a 1 año, o ponga 0 si es realmente efímero. Dígalo en voz alta. |
| «Usted es el experto, ¿qué pondría?» | «No puedo responder por usted: es exactamente lo que la herramienta no sabe leer.» **Esta es la trampa que anula la medición.** |
| Una cifra que le parece falsa | No la corrija. **Anote el desacuerdo**: es el minuto más instructivo de la sesión. |
| «¿Por qué me pregunta esto?» | «Porque es lo único que ninguna herramienta puede adivinar, y cambia el veredicto del informe.» |

## Lo que no hay que hacer

- **Responder en su lugar.** Una duración que usted ha sugerido no mide nada.
- **Defender la herramienta.** Una pregunta mal entendida es un dato que anotar,
  no un malentendido que reparar.
- **Pedir disculpas por las preguntas.** Son cortas y son las correctas.
- **Llenar el silencio.** Las dudas se cronometran, y son lo que se mide.

## Al final, delante de ella

```bash
sablier scan /ruta/del/proyecto --out=despues.html --audit=audit.html --lang=es
```

Abra los dos informes uno al lado del otro y enseñe lo que ha cambiado. Si no
ha cambiado nada, dígalo: significa que las duraciones por defecto ya eran
correctas, y eso es información.

Tres frases para cerrar, en este orden:

1. «Esto es lo que ha producido su hora: *tal* veredicto ha cambiado.»
2. «El archivo se puede leer y está versionado: puede discutirlo más adelante.»
3. «Lo que ha quedado sin responder figura como tal en el informe: no hemos
   inventado nada en su lugar.»

## La hoja

```
Proyecto:                       Fecha:
Persona:                        Su puesto:
Duración total:                 minutos

Asunto                 Nombre dado          Conservación  Daño  Duración  Segura / Discutida / Bloqueada
─────────────────────  ───────────────────  ────────────  ────  ────────  ──────────────────────────────

Desacuerdos con lo que habríamos supuesto:
  ·

Lo que ha preguntado y la herramienta no ha sabido decir:
  ·

Veredictos que han cambiado entre antes.html y despues.html:
  ·
```
