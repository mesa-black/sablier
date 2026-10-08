# Declaring confidentiality lifetimes

*← back to the [README](../README.md)*

## Declaring confidentiality lifetimes

```bash
sablier declare /path/to/project
```

The interview that fills the one input no scanner can read, run with the person
who knows the answer rather than the one who wrote the code. It never asks for
a confidentiality lifetime: it asks **how long must you keep this** — a legal
fact somebody already knows — and **if it leaked today, how long would it still
hurt**, then takes the larger of the two, because data that must be kept is
data that can still be stolen. It says which answer won, so the reasoning can
be argued with rather than the number.

The questions are about areas the scan actually found undeclared, in the order
of how much code they cover, and an area can be skipped: it then stays
undeclared and the report says so in its blind spots. A lifetime nobody chose
would be worse than a gap, because the verdict above it would wear the same
confident typeface as the rest.

**For a session with somebody else in the room**, `sablier serve /path` opens
the same interview in a browser: one subject per page, a clock the person can
see, a button that starts it, and at the end the report their answers produced
— plus two questions about the interview itself, because the session exists to
correct the tool as much as to fill a declaration. The server is bound to the
loopback and dies with the command.

**Remotely**, add `--expose` and the server mints a key into the link; `--public=`
prints the address to hand over, for when a tunnel and a reverse proxy carry a
server that never leaves the loopback. A bind address is a bad judge of
exposure, so the operator says it. Terminate TLS at the proxy —
`docs/declaration-session.md` has the three ways to run the session when the
person is not in the room, and what each one costs the measurement.

Each lifetime carries **who declared it and when**: the audit report prints
both next to the number, and a lifetime nobody has revisited for two years
becomes a blind spot — acceptances expire, regulatory dates carry a
verification date, and until now the one input that decides every verdict had
neither.

The protocol — what to measure during the session, and what result would
falsify this tool's whole thesis — is in
[English](docs/declaration-session.md), [French](docs/declaration-session.fr.md)
and [Spanish](docs/declaration-session.es.md), because not every auditor reads
English and a session run from a half-understood page measures the wrong thing.
Each one links to a one-page crib sheet for the session itself:
[what to ask, and what to answer when it stalls](docs/session-script.en.md).


Without a declaration the tool applies a default lifetime and says so. With one,
it becomes useful. See [`examples/declaration.json`](examples/declaration.json).

```json
{
  "expiry_year": 2035,
  "probe": ["example.org"],
  "domains": {
    "backups":       { "paths": ["deploy/backup.sh"], "lifetime_years": 10 },
    "public content":{ "paths": ["templates/*"],      "lifetime_years": 0 }
  }
}
```

This file is the one artefact in the project that commits people rather than
tooling. It gets read, argued over, and versioned.

[`examples/starter.json`](examples/starter.json) is a declaration to **correct**
rather than a file to fill: a dozen common domains with their usual lifetimes
and a note explaining what drives each answer. Correcting a proposal surfaces
disagreements that a blank file hides, and it is faster.

A domain can also be declared `"hybrid": true`, meaning its classical
algorithms are paired with a post-quantum one. A finding is about a line, and
hybridation is a property of the composition: nothing in the code shows that
another call signs the same bytes. So the declaration says it, the verdict stops
telling you to retire the classical half — which would be telling you to undo
the hybridation the references ask for — and the blind spots record that the
pairing is asserted and not observed. This repository declares its own signing
domain that way, since v0.5.0 signs every report with Ed25519 and ML-DSA-65 over
the same payload.

One of those notes matters more than the rest: **a backup's lifetime is the
maximum of everything inside it.** It inherits the longest domain you declared,
whatever that is. That single line is where most red verdicts come from.

## Health data, where the lifetime is written in law

```bash
cp examples/health.json /path/to/project/sablier.json   # correct, then have the DPO sign it
sablier scan /path/to/project --out=report.html
```

The input this tool normally has to go and ask for — how long must this stay
confidential — is, in health, set by the Code de la santé publique. A patient
record is kept **twenty years** from the last stay or consultation (R1112-7),
ten years from death if the patient dies within ten years of their last visit,
and the period runs to the holder's 28th birthday if it would end before. A
vaccine dispensation in the pharmaceutical record is **twenty-one years**
(R1111-20-12). A shared medical record is ten years from closure (L1111-18).
Pharmacovigilance, absent any other rule, is **seventy years** from the day the
product left the market.

`"regime": "hds"` sets the other side of the inequality to 2030 — ANSSI's date,
because this is sensitive data. The arithmetic is then not close:

```
DATES DE BASCULE
  · sauvegardes — 70 ans — bascule franchie depuis 1961
  · dossier patient — 20 ans — bascule franchie depuis 2011
```

A patient record encrypted today with RSA, and required to stay confidential for
twenty years, is already past its crossing by fifteen years. That is a
subtraction between a legal text and a regulatory deadline, not a prediction.

[`examples/health.json`](examples/health.json) is a declaration to **correct**:
every duration carries the article that sets it, and `declared_by` is left empty
on purpose — the audit report prints who signed each number and when, and in
this setting that person is the data protection officer.

**What this does not do: it does not audit HDS certification.** That framework
covers hosting — physical security, personnel, continuity, incident management,
on an ISO 27001 / 20000-1 / 27018 base — and cryptography is a narrow slice of
it. Sablier answers one question the HDS file raises, and documents it in a
shape that survives an auditor; it certifies nothing.

## When the deadline is read off the data

Every regime above is a pair of years. One is not:

```bash
# sablier.json: { "regime": "eu" }
cp examples/eu.json /path/to/project/sablier.json
```

The NIS Cooperation Group's *Coordinated Implementation Roadmap for the Transition
to Post-Quantum Cryptography* (23 June 2025) does not set one date for everybody.
It classifies each use case by the confidentiality it owes, and gives each class
its own end:

> « this document considers a use case as **high-risk if compromising
> confidentiality after 10 years or more would still cause significant damage** »
>
> « For high-risk use cases, quantum-vulnerable public-key mechanisms **shall not
> be used stand-alone after the end of 2030**, analogously **after the end of 2035
> for medium-risk** »

That classification runs on the one input this tool asks for and nobody else
collects. So under `eu` the expiry is read per domain: ten years or more of
confidentiality — or a `trust_anchor` that signs software, the roadmap's own
example of the high-impact case — puts a domain at **high risk, 2030**; anything
shorter is **medium, 2035**. Two domains in one repository, two deadlines, from
the declaration you already wrote. The audit report prints the level beside each
domain, and both dates instead of one retained year.

What the tool will not borrow is the judgement. The roadmap's test is whether a
break after that duration *would still cause significant damage* — and declaring a
ten-year lifetime **is** that judgement, made by the person who declared it. The
document says so where the level is printed, rather than presenting a computed
level as a finding.

One more reason this regime matters in 2026: the roadmap's **Milestone 1, due
31.12.2026**, lists among its First Steps *"Support mature cryptographic asset
management"*, *"Create dependency maps"* and *"Perform quantum risk analysis"* —
and recommends CBOM as the inventory format. A scan produces the inventory and the
risk analysis. The dependency map it does not, and that is said in the blind spots
rather than implied.

### The obligation the standard cannot express

CycloneDX 1.6 describes the cryptography and not the duration it owes. There is no
field for *"this must stay confidential for ten years"* — which is the input every
verdict here rests on, and the reason a CBOM can be recommended as a format while
the risk classification is still left to a human.
[CycloneDX/specification#1126](https://github.com/CycloneDX/specification/issues/1126)
proposes `protectionPeriod` on `relatedCryptoMaterialProperties`, keyed
`confidentiality` and `integrity`, holding an ISO 8601 duration, targeted at 2.0.

Until it lands our CBOM carries the same shape under its own namespace, so a
consumer implementing the real field maps it mechanically instead of parsing our
integer:

```json
{ "name": "sablier:protectionPeriod.confidentiality", "value": "P10Y" }
```

The proposal also carries an absolute `until`, and this does not: that date depends
on when each record was written, which is exactly what the tool says elsewhere it
cannot know.

## Which country audits you, which is not which deadline you adopt

Two different questions, and they used to share one field. A **regime** answers
*when does this cryptography expire* — borrowed from whichever authority the
declarer accepts, which is why a German entity is perfectly free to adopt
ANSSI's 2030. A **jurisdiction** answers *whose national transposition will audit
me*. `hds` was the proof the two were tangled: French health-data hosting law,
filed next to the NSA's CNSA 2.0.

```jsonc
// sablier.json
{ "regime": "eu", "jurisdiction": "fr" }
```

A two-letter ISO code, and it is **declared, never inferred from `--lang`** — the
documents say so in as many words. A language is not a country: an English report
for a German entity, a Spanish one for the Mexican subsidiary of a Belgian group.
Reading the jurisdiction off the reader's language would be exactly the silent
assumption this tool refuses everywhere else.

What the Union-level layer gives is the same for all twenty-seven, and the audit
document now names it: **Directive (EU) 2022/2555**, of 14 December 2022,
OJ L 333/80, to be transposed *"by 17 October 2024"* under its article 41, whose
article 21(2)(h) lists among the risk-management measures *"policies and
procedures regarding the use of cryptography and, where appropriate,
encryption"*. That is the obligation this inventory serves, and it holds whatever
the state of each transposition — several are still unfinished.

**All twenty-seven are in the table**, each with the national cybersecurity
authority ENISA publishes for it and the date that name was taken. France also
carries its referential and its registration portal, read on ANSSI's own site; no
other row carries either, because no other row has been read there yet.

What the table deliberately does **not** carry is a transposition status. The
Commission's own country pages were a state of play from mid-2025, several member
states have moved since, and a status frozen into a release is a regulatory fact
that goes stale between two versions of this tool and still reads as current. So
the documents cite the Commission's living page — one URL for all twenty-seven,
which updates itself — instead of copying a verdict out of it.

Two more things every row prints. The date the authority's name was taken, for
the same reason `deadlines_checked_on` exists: a regulatory fact with no date on
it is one nobody can age. And a caveat, because several member states designate
sectoral authorities as well: this is the door to start at, not necessarily the
one that audits you.

A declared jurisdiction outside the Union — `ch`, `uk`, `us` — has no row, and
the document says so rather than reaching for the nearest plausible agency.

And this inventory is not a NIS 2 compliance report. It produces one of the
measures the directive asks for. Registration with the authority and incident
reporting are obligations on the entity, and the tool says nothing about either.

## The interview as one file

```bash
sablier worksheet /path/to/project --out=worksheet.html   # [--lang=fr|en|es]
# … the person fills it in, anywhere, and hands back a file
sablier declare /path/to/project --import=answers.json
```

A page that talks to nothing: the subjects and the questions baked in, no
server, no port, no request. It is opened from a memory stick or an attachment,
answered in a browser with the cable out, and what comes back is a block of
JSON the person can save or copy.

It exists for the rooms the served interview cannot enter — a closed network, a
client who will not run a command, a machine nobody may connect to — and it
removes the tunnel, the certificate and the question of whether the auditor's
laptop is sound for everybody else too.

What travels is the point: the file carries **no absolute path** from the
machine that wrote it, and what comes back carries durations and the names the
person gave, never the inventory that produced them. Both are checked on every
run. The report is then computed by the auditor, where it belongs.

The merge rules are not reimplemented in the browser. The page collects
answers; `--import` runs them through the same code a typed interview uses, so
a name given twice means the same thing — one domain, both paths, the longer
lifetime — wherever it was given.

### What the person reads, and its budget

Three sessions with the same company director ended in *"it is gibberish to me,
I do not understand the sentences, I am lost"*. The third time, the document had
grown to **986 words** of text he had to get through to answer two questions per
subject — with *fingerprint* five times, and *algorithm*, *deadline*, *regime*,
*declaration*, *plumbing* on the way. Almost all of it had been added in good
faith, one defensible paragraph at a time, each explaining what the tool could
not know or why a question was being asked.

Everything that was removed is still said — in the audit report, which is where
a caveat belongs: it is read by the person who has to weigh the figures, not by
the person supplying one of them. What is left is **235 words**, and a test
fails over 260. A budget rather than a review, because prose arrives one
justified paragraph at a time and nothing else would have caught it. A second
test fails if any trade word returns to the path.

Two questions also left it. The cryptography found at a place is now behind a
fold with the file names: true, and no use to somebody answering about data.
And **which regulatory regime applies is not asked at all** — nobody outside the
field picks between NIST IR 8547, CNSA 2.0 and an ANSSI position, and the
question printed five lines of acronyms, then deadlines of 2030 and 2035 under a
year the person had just given as 2029. It is the auditor's to set, in the
declaration, where it is reviewable; the import says so when it is left at the
default.

What survives is the only thing the person in the room is the authority on:
what the data is, in their words, and what it would cost if it got out.
