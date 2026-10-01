# The declaration session

The one experiment that can kill this project, run on purpose rather than by
accident.

Every verdict in every report rests on a number no scanner can read: how long
each kind of data has to stay confidential. The scoping study says so, and says
what would falsify the thesis — *the person cannot answer "how long must this
stay secret" for most of their domains*. Until a session happens outside this
repository, that is an opinion.

So this page exists to make the session measurable, and it is written **before**
the first one, so the result cannot be rationalised afterwards.

## What is measured, decided in advance

Three numbers, written down during the session rather than reconstructed later.

| | What to record |
|---|---|
| **Time** | Wall clock from the first question to the written file. The tool prints it at the end. |
| **Confidence** | For each area: answered without hesitating, answered after discussion, or stalled. Three columns, one tick each. |
| **Disagreements** | Every time the person's answer contradicts what we would have assumed. These are the most instructive minutes of the session — they say our defaults are wrong, and they are the only part that cannot be guessed from a desk. |

## What would falsify the thesis

If most areas end in **stalled**, the problem is not the tool and no additional
detector fixes it. The question would have to be asked differently — starting
from something else entirely, or by a different person — and the product has to
change rather than the documentation.

Recording that honestly is the point. A session that only produces a filled
declaration proves nothing; a session that produces three stalls out of six
teaches more than a month of work.

## Running it

**Before**, alone, ten minutes:

```bash
sablier scan /path/to/project --out=before.html
```

Keep that report. It is the "after" comparison, and the areas it lists as
undeclared are the questions the interview will ask.

**During**, with the person:

```bash
sablier declare /path/to/project
```

The interview asks about each undeclared area, in the order of how much code it
covers. It never asks for a confidentiality lifetime. It asks two things people
answer every week:

- **how long must you keep this?** Retention is a legal fact somebody already
  knows — an accountant's obligation, a regulation, a contract. Nobody
  hesitates on it;
- **if it leaked today, how long would it still hurt?** Usually shorter than
  retention. Occasionally much longer, and that gap is worth the whole session.

The lifetime is the larger of the two, because data that must be kept is data
that can still be stolen. The tool says which of the two answers won, out loud,
so the person can disagree with the reasoning rather than with a number.

Two rules for whoever runs it:

- **do not answer for them.** The temptation is enormous, especially on an area
  you wrote yourself. A lifetime you supplied measures nothing;
- **let them skip.** An area with no answer stays undeclared and is computed
  with the default, which the report says in its blind spots. That is a
  result, not a failure — and it is the result that falsifies the thesis.

**After**, in front of them:

```bash
sablier scan /path/to/project --out=after.html --audit=audit.html
```

Open both reports side by side. The verdicts that moved are what their hour
produced — and if nothing moved, say so: it means the defaults were already
right, which is also worth knowing.

## The sheet

Copy this, fill it during the session, keep it with the declaration.

```
Project:                        Date:
Person:                         Their job:
Time, first question to file:              minutes

Area                     Name given          Retention  Harm  Lifetime  Confident / Discussed / Stalled
───────────────────────  ──────────────────  ─────────  ────  ────────  ───────────────────────────────

Disagreements with what we would have assumed:
  ·

What they asked that the tool could not answer:
  ·

Verdicts that moved between before.html and after.html:
  ·
```

## Show me the REX, first session

The areas the scan reports as undeclared today, in the order the interview will
raise them:

| Area | What is there |
|---|---|
| `config/secrets/prod` | the Symfony vault — X25519, and the one that turns red if the answer is long |
| `.env`, `.env.dev`, `.env.test` | connection strings with no TLS mode declared |
| `src/Identity/Application/OAuth` | SHA-256 in the OAuth exchange |
| `src/Feedback/Application` | SHA-256 over feedback content |
| `assets/images/partners`, `public/assets/images/partners` | two files whose extension does not match their content |

The first line is the one to watch. With a short answer the project stays
green; declared at ten years, the vault finding becomes COMPROMISED and the
crossing date moves to "already past". The arithmetic is not the interesting
part — what the person says before giving the number is.
