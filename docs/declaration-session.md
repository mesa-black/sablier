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

| | What to record | Who records it |
|---|---|---|
| **Time** | Wall clock overall, and per subject. Hesitation is the measurement, and asking somebody to time themselves while they think is how you stop them thinking. | the tool, with `--log` |
| **Confidence** | Answered without hesitating, answered after discussion, or stalled. The per-subject seconds are a decent proxy, the tick is the judgement. | you |
| **Disagreements** | Every time the answer contradicts what we would have assumed. The most instructive minutes of the session: they say our defaults are wrong, and they cannot be guessed from a desk. | you |

```bash
sablier declare /path/to/project --log=session.json
```

The log holds, per subject, the name the person gave, the two numbers, the
lifetime derived from them, whether it was skipped, and the seconds spent. A
number transcribed after the fact is a number somebody rounded towards the
result they hoped for.

## What would falsify the thesis

If most subjects end in **stalled**, the problem is not the tool and no additional
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

The interview goes subject by subject. Each one opens with a plain-language
description of **what the tool found there** — a vault of secrets, settings
read at startup, a fingerprint over content — with the file names underneath
for whoever in the room knows them. No algorithm name, no path as a heading: a
first dry run showed a subject as "`.env` — cryptography found: no encryption",
which loses a non-technical person in two lines and takes the session with
them.

Then it asks three things, none of which is a confidentiality lifetime:

- **if somebody got a copy of this, what would we be talking about, in your
  words?** The answer names the domain, and it is theirs rather than ours;
- **how long must you keep this?** Retention is a legal fact somebody already
  knows — an accountant's obligation, a regulation, a contract. Nobody
  hesitates on it;
- **if this got out today, how long would it still hurt?** Usually shorter than
  retention. Occasionally much longer, and that gap is worth the whole session.

The lifetime is the larger of the two, because data that must be kept is data
that can still be stolen. The tool says which of the two answers won, out loud,
so the person can disagree with the reasoning rather than with a number.

Two rules for whoever runs it:

- **do not answer for them.** The temptation is enormous, especially on code
  you wrote yourself. A lifetime you supplied measures nothing;
- **let them skip.** A subject with no answer stays undeclared and is computed
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

Subject                  Name given          Retention  Harm  Lifetime  Confident / Discussed / Stalled
───────────────────────  ──────────────────  ─────────  ────  ────────  ───────────────────────────────

Disagreements with what we would have assumed:
  ·

What they asked that the tool could not answer:
  ·

Verdicts that moved between before.html and after.html:
  ·
```

## Show me the REX, first session

Four subjects, in the order the interview raises them. Count twenty minutes.

| Subject | What the person will be shown |
|---|---|
| `.env`, `.env.dev`, `.env.test` | settings read at startup: what it connects to, with which account and password |
| `config/secrets` | a vault of secrets — passwords, keys, tokens, encrypted, protecting everything else |
| `src/Feedback` | a fingerprint computed over content |
| `src/Identity` | a fingerprint in the OAuth exchange |

The two mislabelled images are deliberately **not** in the list: a `.png` that
is a JPEG is a developer's confirmation, not a business decision, and spending
one of twenty minutes on it would be a waste of the only hour that matters.

The vault is the line to watch. A dry run answering "fifteen years" to the harm
question turns that finding **COMPROMISED** and moves its crossing date to
*already past* — a report that went from no red at all to one red, on the
strength of a sentence somebody said out loud. The arithmetic is not the
interesting part. What they say before giving the number is.
