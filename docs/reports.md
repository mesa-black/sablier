# What the reports say, and who they are for

*← back to the [README](../README.md)*

## The report concludes

Findings are not a decision. The last section is an ordered action plan derived
from what was actually found — what to do first, and why it comes first.

It takes positions most inventories avoid. When data is already harvestable the
first action is not "migrate": it is deciding what happens to the data already
sent, because migration cannot reach it. When nothing is burning it says so
plainly, because replacing cryptography that holds costs time and improves
nothing. And when most findings sit in undeclared domains, finishing the
declaration comes before everything else — until then the verdicts above are
approximations delivered in a confident typeface.

A share button hands the summary to **Threema**, which opens a local
application with plain text. Nothing reaches a third-party server, which is the
only kind of sharing this tool can offer without contradicting its own footer.

Threema is the house channel for everything this tool hands over, and the reason
is in the arithmetic rather than in a preference: it is end-to-end encrypted, it
authenticates the person rather than a domain, and the key that matters is
checked by scanning a code in front of somebody. That is exactly the property an
audit needs when it sends a **fingerprint** — see further down: the report may go
by e-mail, the fingerprint must not go the same way.

`threema://` is a phone scheme. On a desktop that has never registered it the
browser refuses the link, so the summary it would have carried is printed in a
disclosure under the button, selectable in one click.

## The third factor, counted rather than estimated

The EU roadmap's quantum risk rests on three things: the weakness of the
cryptography, the impact of a break, and *"the estimated time and effort required
to migrate"*. This tool measured the first two and said nothing about the third —
which is the one a team actually plans against, and the one every vendor answers
with a number nobody can check.

So the report now counts what there is to change, per algorithm: call sites,
files, domains, how many entries are declared rather than observed at a call
site, and how many name the algorithm in a variable or a configuration instead of
at the call site. That last count is the roadmap's own definition of
crypto-agility — *"a modular way that enables replacing the cryptographic
components"* — observed instead of asserted, and it marks the cheapest kind of
call site to change.

Every figure is already in the inventory; none of them is an inference. Two
catalogue entries that share a label are told apart by purpose, because two rows
both reading "RSA" is how a reader stops believing a table. An algorithm that is
sound, or a digest used as a cache key, is not work and is not listed. With
nothing to change the block does not render at all.

**What it will not do is turn that into a duration.** Eight call sites in one file
behind one function are an afternoon; eight across six services with a protocol
between them are a quarter, and nothing in a repository distinguishes the two. A
tool that printed "three weeks" would be inventing the only number in the report
that cannot be checked — and would be believed, precisely because it is the number
somebody needed. The count is ours; the estimate is the reader's, and the block
says so where the figures are.

## Wrong findings

Two different things get called a false positive, and they do not go to the same
place. The report says so under every finding, with the exact text to use.

**The tool is right, but the finding is accepted here.** That is a project
decision, so it lives in the declaration next to the data lifetimes — a
versioned file, which means the review happens in code review, with no service
and no database:

```bash
sablier accept a3f1c2 --reason="SHA-1 mandated by the TOTP specification" --until=2027-04-01
```

Three rules are enforced rather than suggested, because a suppression file that
is easy to write is how these tools empty themselves out within six months:

- **an accepted finding does not disappear.** It moves to its own section,
  carrying the verdict it would have had, the stated reason and the date;
- **an acceptance expires.** `until` is required, and the finding comes back on
  its own the day it lapses — the same way the window closes by itself;
- **the reason is required and written for a human.** It is what the person
  approving the change actually reads.

An acceptance is keyed on the evidence rather than the line number, so it lapses
when the line it was about materially changes. That is wanted: the code moved,
the decision deserves a second look.

**The tool is wrong.** That is a rule to fix, and it belongs here. Every finding
carries a link that opens a pre-filled report — the link opens your browser on a
form you fill in yourself; the file still sends nothing.

## The date, not the bar

A bar against a vertical mark asks the reader to do the subtraction. The
subtraction has one answer and it is a date, so the report prints it under the
chart:

```
DATES DE BASCULE
  · backups — 10 ans — bascule franchie depuis 2026
  · authentication — 3 ans — bascule le 1er janvier 2033
```

Data encrypted in year Y stays sensitive until Y plus its lifetime, so the
crossing year is `expiry − lifetime + 1`: the first year whose output outlives
the algorithm protecting it. Before it the domain holds; from it, everything
emitted is already lost by the day the algorithm goes — and migrating later
does not reach back.

Two conditions, because a date about the wrong domain is worse than no date.
It is about **confidentiality**, since a signature is not harvested; and about
an algorithm **a quantum computer breaks**, since a domain protected by AES or
ML-KEM can hold data for a century without crossing anything. Colouring by
duration alone was a bug this project already fixed once, in the chart; this is
the same bug in words, and the regression test asserts the silence.

The action plan stops saying "replay this once a year" and names the
appointment: *Prochaine bascule : authentication, le 1er janvier 2033.*

```bash
sablier scan . --calendar=crossings.ics
```

`--calendar` writes the ones still ahead as iCalendar — one all-day event per
domain, folded at 75 octets as the specification requires, because a tool that
spends its report telling people to read the standard does not get to ignore
one. A date in a report is read once; a date in a calendar interrupts somebody
in 2033, which is the only version that works.

## Two reports, for two rooms

`--audit=FILE` writes a second document from the same analysis. Not a mode of
the first one: a different document, for a different reader.

The technical report is read next to an editor by someone who can act on it.
The audit report is read by a client, a committee, an insurer, a lawyer —
people who did not write the code and may have to weigh it in a dispute. It
borrows its shape from expert reports rather than from dashboards:

- **facts and opinion are separated, and numbered.** Section 5 observes, in a
  numbered table; section 7 concludes, citing the numbers it relies on. A
  reader can accept a fact and contest the opinion built on it, which is
  precisely what a cross-examination does;
- **the input that decides the outcome is printed in full.** Every verdict
  depends on lifetimes a human declared, so section 6 reproduces them and says
  plainly that the tool can neither verify them nor derive them from the code;
- **the limits are a numbered section**, at the same size as the rest;
- **the references are cited with the date they were last checked** — a
  deadline quoted from memory is worth nothing in front of someone paid to
  check it;
- **a glossary** of the seven terms the document needs, so the reader is not
  asked to already know what harvesting is;
- **nothing about the auditor is invented.** An absent name prints as a field
  to complete, and an absent statement prints as a statement still to write,
  date and sign. A report that fills in a plausible auditor is a forgery with
  good intentions.

The identity comes from two files, because two different things were being
asked of one block. **The engagement** changes every mission and is reviewed
with the project it concerns, so it lives in the versioned declaration:

```json
"audit": {
  "client": "Example SAS",
  "reference": "AUD-2026-014",
  "mandate": "Establish the exposure of confidential data to harvesting."
}
```

**The auditor** belongs to a person rather than to a project, and typing their
name into every client's repository is how it goes stale in one of them. It
sits once in `~/.config/sablier/identity.json` (or wherever `SABLIER_IDENTITY`
points), and fills in by itself on every engagement:

```json
{
  "auditor": "A. Lambert",
  "organisation": "Lambert & Co",
  "statement": "The findings in section 5 were produced by the tool named in section 1…"
}
```

The identity file fills what the declaration leaves empty and loses every
conflict: the versioned file is the one somebody reviewed. `examples/identity.json`
is the template.

There is no YAML here and there will not be: PHP ships no YAML parser, so
supporting it means either a dependency this project refuses or a parser
written by hand — and a hand-rolled YAML parser is a liability, not a feature.

```bash
sablier scan . --out=report.html --audit=audit.html --pdf=report.pdf --sign=sablier.key
```

With `--pdf`, the audit document gets its own PDF next to the technical one —
it is the one that gets printed, signed and filed. Both exist in French,
English and Spanish, and both carry the same digest: section 10 prints it, with
the command a third party runs to verify the signature, and the standing caveat
that the signature itself is Ed25519.

What the tool does not claim: none of this makes a document admissible
anywhere. The auditor signs it and defends it; Sablier produces the facts, the
method, the limits and the arithmetic, in a shape that survives being read by
someone looking for a hole in it.

## Typesetting the report as a PDF

`--pdf=FILE` writes a PDF as well, typeset here rather than printed by a
borrowed browser. A4, the three fonts every reader already carries, the ten
numbered sections, the declared lifetimes, and the timeline drawn in vector
operations — the one figure that carries the argument, so it travels rather
than being dropped.

This replaced a hunt for Chrome in fourteen locations and a pinned Chromium
container. The file is plainer: no colour beyond the bars, no typography to
speak of. It is also eighteen times smaller, it carries **a page number on
every page** — which the browser would never give us, since Chrome ignores the
CSS that would print one — and it cannot fail for want of something to borrow.
That last property is the one that mattered: on a closed site there is no
browser to find and no image to pull, and a report that cannot be printed
cannot be signed or filed.

It needs PHP's `dom` extension, which is enabled in every standard build and in
the container this project ships with. Without it, the tool says so and the
HTML still prints to PDF from any browser, since it ships a print stylesheet
that forces the light palette and keeps charts, findings and the probe block
off page breaks.
