# After a breach

*← back to the [README](../README.md)*

## When the hole was already used

An advisory says somebody found a way in. A breach says somebody went through
it, and the arithmetic of this whole tool then has to be read backwards.

```bash
sablier scan . --breached=2026-07-29
```

Everything else here reasons forward: an adversary captures today what they will
read when the algorithm falls. After a breach they are not waiting any more —
they hold it — and the only question left is how much of the confidentiality you
asked for the cryptography can still deliver. Data taken in year B has to stay
secret until B + lifetime; the algorithm protecting it stops being credible at
the regime's expiry; whatever lies between the two is the part that becomes
readable, and migrating afterwards does not reach it.

The date belongs on the domain, because a stolen table is not a statement about
the whole system:

```json
{ "name": "backups", "lifetime_years": 10, "breached": "2026-07-29" }
```

On the command line it applies to every domain at once, which is the worst case
and is meant to be read as one. Each breached domain then gets one line:

- **plaintext loses the whole duration.** Nothing has to fall for that data to
  be readable, because nothing was protecting it;
- **an algorithm quantum reaches loses the tail.** Ten years asked for, taken in
  2026, an algorithm credible until 2035: one year of what was taken becomes
  readable, and no migration reaches it;
- **an algorithm quantum does not reach loses nothing**, and the line says so
  rather than staying silent.

Three refusals keep this from becoming a breach-notification generator. It
**counts years, never people** — how many records left is a fact for the incident
team, how long they keep hurting is the question nobody else asks. It only speaks
about **domains somebody declared breached**. And it **says what it cannot
know**: the tool has no idea what actually left, whether it left encrypted, or
whether the keys left with it, and that sentence is printed next to the figure.

This is not a prevention claim either. The breaches that make the news are
stolen credentials and unpatched edges, and nothing in this tool would have
stopped one. What it can do is answer the question asked the week after, which is
how long the damage lasts.

### The document for the week after

The breach block above sits inside the technical report, which is read next to an
editor. The week after a breach, the question is asked in a different room — by a
DPO, a legal team, a committee — and the answer has to be short enough to be read
in one sitting:

```bash
sablier scan . --breached=2026-07-29 --incident=incident.html
```

Six sections, one page or two: what the document is and is not, what was declared
breached and by whom, how long each domain stays protected, what can still be
done, the method and its limits, the digest. It does not look like the audit
report — sans-serif, no table of contents — because two documents from the same
run that look alike is how somebody files the wrong one.
[`examples/incident.html`](examples/incident.html) is one, with its
[PDF](examples/incident.pdf).

Three things it refuses:

- **it is not a notification.** Article 33 asks for the categories and the
  approximate number of data subjects and records concerned. This document
  contains none of them, says so in section 1, and names who that obligation
  belongs to;
- **it refuses to be written without a date.** No breach declared, no document —
  a post-breach report produced by a tool that decided on its own that there was
  a breach is worse than no report;
- **it grades the remedies by what they reach.** Rotating keys, re-encrypting
  what is still held and notifying are all necessary and none of them touches the
  data that already left. One measure does — shortening the retention where the
  duration is a choice rather than a legal floor — and the document marks which
  is which rather than listing four measures that read as equivalent.
