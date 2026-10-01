# Changelog

A tool that demands dated decisions of its users owes them one of its own.
Each entry says what changed and, where it matters, why — the reasoning is in
the commit messages, and this page is the map.

## v0.3.0 — 2026-10-02

The release where somebody who does not write code can answer the question the
whole tool rests on.

### The interview

`sablier serve <path>` opens it in a browser: one subject per page, a button
that starts the clock, a counter the person can see, and a skip that is a real
answer. `sablier declare <path>` is the same questions in a terminal.

Two dry runs with somebody playing the non-technical part rebuilt the screen
and are worth recording, because each line of it answers a failure. A file path
told them nothing, so the heading became the part of the application in words.
"What would we be talking about" was answered with the incident — "a hack of my
server" — so it asks for a name now, with examples and a suggestion to correct.
The duration question was answered three times out of four by typing and four
out of four once it became buttons; retention stayed at one in four, so it is
optional and last. "I do not know" is a button, recorded separately from a
plain skip. And nothing had said what the audit was for, so the opening says
it, naming the project rather than "this application".

A subject made of signatures is asked a different question — how long the proof
must hold, not what a leak would cost — because a signature is published on
purpose, and a long answer writes `trust_anchor` into the declaration.

### What the session leaves behind

Every lifetime now carries **who declared it and when**. The audit prints both
beside the number, and one nobody has revisited for two years becomes a blind
spot: acceptances expire and regulatory dates carry a verification date, while
the one input that decides every verdict had neither.

The session record holds the time spent per subject, what was skipped and why,
and two questions about the interview itself — those go to us, not to the
report.

### The system, not only its data

`service_until` puts the last day the system writes data into the arithmetic:
backups kept ten years and written until 2032 are exposed to 2042, not 2036.
`regime` picks whose deadline applies — NIST IR 8547, ANSSI, CNSA 2.0 — and
with it the citation. Same code, same declared lifetimes, read as a commercial
service or an institutional one: no red at all, or one red.

### Elsewhere

- `sablier init` writes a declaration to correct rather than a form to fill;
- the probe gained LDAP, AMQP, Redis, MQTT, and **SSH**, which never becomes
  TLS and so reads the server's KEXINIT instead — where a post-quantum key
  exchange shows up that no file in a repository mentions;
- a signed report names the one it replaces, inside what is signed, with no
  flag to remember: a folder of reports is an audit trail;
- the audit report names the build that produced it, and every page runs a line
  identifying the document, the project, the engagement and the version — Chrome
  ignores the CSS that would carry a page number, which was tested rather than
  assumed;
- `sablier --version` answers directly;
- `--quiet` writes no report unless one is named: the flag means "the verdict is
  in the exit code", and a build that drops an unrequested page at the root of a
  repository every run is leaving state behind.

## v0.2.0 — 2026-10-01

The release where the report stopped being the only thing this tool produced.

### A second document

`--audit=FILE` writes an audit report in the three languages: ten numbered
sections, facts and opinion separated so a reader can accept one and contest
the other, the declared lifetimes reproduced in full because every verdict
depends on them, the limits as a numbered section rather than a footnote, a
glossary, and an integrity section with the digest and the command to verify
it. Nothing about the auditor is invented: an absent name prints as a field to
complete. The engagement lives in the versioned declaration, the auditor's own
identity in `~/.config/sablier/identity.json`, so a name is not retyped into
every client's repository.

### Dates instead of bars

A domain crosses at `expiry − lifetime + 1`, the first year whose output
outlives the algorithm protecting it. Both documents print the dates under the
chart, the action plan names the next appointment instead of advising an annual
replay, and `--calendar=FILE` writes the ones still ahead as iCalendar — folded
at 75 octets, as the specification requires.

### Living in a pipeline

`--baseline=FILE` compares a run against the JSON report of a previous one.
Three things stop a build: a new finding, a verdict that got worse — a lapsed
acceptance surfaces here — and a red finding nobody decided on. The reference
is explicitly **not** a suppression file: a red finding it already recorded
still blocks, every run, until somebody fixes it or accepts it with a reason
and an expiry date. `--quiet` now exits with the verdict instead of always
zero.

### Somebody else's inventory

`sablier judge cbom.json` reads a CBOM produced by another scanner — in a
language this project will never parse — and gives every component a domain, a
lifetime and a verdict. `--cbom=FILE` is the other direction, on both commands.
An algorithm we do not know is counted and named rather than dropped, the
detection is credited to the tool that did it, and the fingerprint is always
recomputed so an imported file cannot claim an existing acceptance.

### Published vulnerabilities

`sablier advisories <path>` collects the known vulnerabilities of the declared
libraries, in a pinned container, from lock files mounted read-only. It is the
only command that reaches the network, and it reaches it for a database rather
than with your inventory. A library with a published high or critical hole then
becomes BROKEN TODAY rather than plain inventory — a defect owing nothing to
quantum computing. Only libraries this tool already inventories are judged; the
others are counted in the blind spots.

Findings that are broken today also carry the defect behind them — SHA-1 its
collision CVE, MD5 its own, RC4, 3DES, TLS 1.0 and 1.1 theirs — linked to NIST,
GitHub or OSV. RSA and the elliptic curves carry none, deliberately: a CVE is a
dated fact somebody published, the post-quantum expiry is a regulatory horizon,
and filing the second under the first would turn a deadline into an accusation.

### What hides in the assets

Bytes after the end of an image, and a file whose magic bytes contradict its
extension — both reported as *to confirm*, never as a verdict. Key material in
a binary asset was already detected; what it gained is the sentence saying
where. No steganography, and the blind spots say so.

### Running anywhere, on containers we vouch for

`./sablier` uses the local PHP when it is 8.4 or newer and otherwise runs the
unchanged code in `php:8.4-cli-alpine`. The PDF export looks for a browser in
the places a Linux machine actually keeps one, and borrows a Chromium
container when there is none. `make cve` proves the four images we ask anybody
to run carry no known high or critical vulnerability, on **both**
architectures, every push and every Monday. The one exception is written down
with a statement and an expiry date in `.trivyignore.yaml`.

### Smaller, and worth saying

- static analysis at level max, in a container — no vendor directory, zero
  errors, enforced in CI;
- the type holes it found were real: a `-1` match offset silently produced
  wrong line numbers, a framework rule read a capture group that need not
  exist, and signature verification checked the key length but not the
  signature's;
- interfaces renamed to `DetectorInterface`, `ReporterInterface`,
  `TransportInterface`;
- the hourglass mark left the report header; the name carries it.

## v0.1.0 — 2026-09-30

First working prototype: static detection across PHP, shell, server and
framework configuration, key material and lock files; the live TLS probe, with
STARTTLS for SMTP, IMAP, POP3, MySQL and PostgreSQL; the risk model, the action
plan, acceptances that expire, and the self-contained HTML report in French,
English and Spanish, optionally signed.
