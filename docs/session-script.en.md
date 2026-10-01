# Running the interview — crib sheet

*[Français](session-script.fr.md) · [Español](session-script.es.md)*

One page to keep in front of you during the session. The protocol and what to
measure are in [`declaration-session.md`](declaration-session.md); this is the
script.

```bash
sablier declare /path/to/project --log=session.json --lang=en
```

## What the person hears

Each subject opens with what the tool found, without a technical word, then
three questions. A real example:

> **Subject 1 of 4 · 3 files**
>
> Here the application keeps settings it reads when it starts: what it connects
> to, with which account, and with which password. None of it is encrypted — it
> is a configuration file.
> *In: .env, .env.dev, .env.test*
>
> 1. **If somebody got a copy of this, what would we be talking about, in your words?**
> 2. **How many years must you keep this?** (a law, a contract, or your own rule; 0 if nothing requires it)
> 3. **If this got out today, for how many years would it still cause harm?** (0 if it is public or harmless)

The lifetime is **the larger of the two** — data you must keep is data that can
still be stolen — and the tool says which one won, so the reasoning can be
argued with rather than the number.

## When it stalls

| What they say | What you answer |
|---|---|
| "I don't know." | "Who would know, in the company?" Write the name down, skip the subject. **A skipped subject is a result**, not a failure. |
| "Forever." | "Does a law or a contract say so?" If not: "In thirty years, would it still bother anybody?" A number, even a big one, beats a word. |
| "That will never get out." | "Agreed — the question is: *if* it did." Do not negotiate this one; it is the whole method. |
| "Three months." | Round up to 1 year, or put 0 if it is genuinely ephemeral. Say which, out loud. |
| "You're the expert, what would you put?" | "I cannot answer for you: this is exactly the thing the tool cannot read." **This is the trap that voids the measurement.** |
| A number that looks wrong to you | Do not correct it. **Record the disagreement** — it is the most instructive minute of the session. |
| "Why are you asking me this?" | "Because it is the one thing no tool can guess, and it changes the verdict in the report." |

## What not to do

- **Answer for them.** A lifetime you supplied measures nothing.
- **Defend the tool.** A misunderstood question is data to record, not a
  misunderstanding to repair.
- **Apologise for the questions.** They are short and they are the right ones.
- **Fill the silence.** Hesitations are being timed, and they are what the
  session measures.

## At the end, in front of them

```bash
sablier scan /path/to/project --out=after.html --audit=audit.html --lang=en
```

Open the before and after reports side by side and show what moved. If nothing
moved, say so: it means the default lifetimes were already right, and that is
information.

Three sentences to close, in this order:

1. "Here is what your hour produced: *this* verdict changed."
2. "The file is readable and versioned — you can argue with it later."
3. "What stayed unanswered is written as unanswered in the report: nothing was
   invented on your behalf."

## The sheet

```
Project:                        Date:
Person:                         Their job:
Total time:                     minutes

Subject                Name given           Retention  Harm  Lifetime  Confident / Discussed / Stalled
─────────────────────  ───────────────────  ─────────  ────  ────────  ───────────────────────────────

Disagreements with what we would have assumed:
  ·

What they asked that the tool could not answer:
  ·

Verdicts that moved between before.html and after.html:
  ·
```
