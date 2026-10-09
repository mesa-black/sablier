# Changelog

A tool that demands dated decisions of its users owes them one of its own.
Each entry says what changed and, where it matters, why — the reasoning is in
the commit messages, and this page is the map.

## v0.11.1 — 2026-10-09

### A seal older than the report now explains both of its halves

Found by a reader, not by a test. A regenerated report shows today's date in its
masthead while the seal below keeps the date the findings were first sealed — the
rule this tool exists to defend, since re-attesting would throw away the
antecedence a token buys. The sentence explaining that was attached to the
attested date alone, so the "signed on" line one row higher raised exactly the
same question and got no answer.

The signature and the attestations are kept together or redone together, both
hanging off the digest, so the explanation is now asked of the seal as a whole
and names both. It also moved out of the timestamp block: a kept signature with
no attestation raised the same question and the first version answered none of
it.

The sentence also says what re-signing on every run would cost, because that is
the natural wrong move: the same findings hash to the same value, so a new
signature carries no new information — and a new token replaces an older bound
with a later one, for nothing.

## v0.11.0 — 2026-10-09

The release that fills in the national frames, and says what a failure costs.

### Seven member states, read on their own authority's site

The twenty-seven each carried an authority and nothing else. Seven carry more
now, and every fact was read where that country publishes it.

France keeps ReCyF and MesServicesCyber. Germany: the NIS-2-Umsetzungsgesetz, in
force since 6 December 2025, registration through portal.bsi.bund.de within three
months of coming into scope. Belgium: CyberFundamentals, which the CCB recommends
to every NIS 2 entity for a reason worth printing — a validated implementation
grants a presumption of conformity — and Safeonweb@Work. Italy: Decreto
legislativo 138/2024, in force since 16 October 2024, registration on the ACN
platform through SPID, and an administrative penalty of up to 0.1 % of turnover
for registering late. The Netherlands: the Cyberbeveiligingswet, in force since
15 August 2026, registration in the register the NCSC keeps — while the RDI
supervises nine sectors, which makes it the sharpest illustration of the caveat
every frame prints, since you register at one door and are inspected from
another. Portugal: Decreto-Lei 125/2025, in force 3 April 2026 after the hundred
and twenty days it names, the Medidas Mínimas de Cibersegurança, and MyCiber.
Spain: the opposite kind of fact, since its transposition is still a bill and
INCIBE itself writes that the competent authorities and the single point of
contact have to wait for it.

The other twenty carry the authority alone. That means nobody has read their
site yet, not that there is nothing there.

### What the directive says a late or absent measure costs

Article 34 is widely quoted as "fines up to EUR 10 million", which reads as a cap
and is the reassuring half of a sentence saying the opposite. The text sets a
maximum of **at least** EUR 10 000 000 or at least 2 % of total worldwide annual
turnover for an essential entity, whichever is higher, and EUR 7 000 000 or 1,4 %
for an important one. It is a floor on the ceiling: a member state's law must
allow at least that much, and may allow more.

The audit document now carries both storeys and says which is which. The Union
sets what every national law must at least permit; a member state adds penalties
of its own for named failures, and Italy's 0.1 % sits on top of the article 34
regime rather than replacing it. Read in the directive's own text rather than in
a summary, which is how the "up to" reading survives everywhere.

## v0.10.0 — 2026-10-08

The release that says which country audits you, and stops guessing it.

### A jurisdiction is not a regime, and not a language

One field carried two questions. A **regime** answers *when does this
cryptography expire*, borrowed from whichever authority the declarer accepts —
which is why a German entity is free to adopt ANSSI's 2030. A **jurisdiction**
answers *whose national transposition will audit me*. `hds` was the proof the two
were tangled: French health-data hosting law, filed next to the NSA's CNSA 2.0.

`jurisdiction` is its own field now, an ISO 3166-1 alpha-2 code, **declared and
never inferred from `--lang`**, and the documents say so in as many words. A
language is not a country: an English report for a German entity, a Spanish one
for the Mexican subsidiary of a Belgian group. `hds` supplies `fr` because health
hosting law genuinely is French; `anssi` deliberately does not.

Sablier knows all twenty-seven member states, each with the national
cybersecurity authority ENISA publishes for it and the date that name was taken.
Four say more, each read where that country publishes it: France (ReCyF,
MesServicesCyber), Germany (the NIS-2-Umsetzungsgesetz, in force since
6 December 2025, and registration through portal.bsi.bund.de within three months
of coming into scope), Belgium (CyberFundamentals, where a validated
implementation grants a presumption of conformity, and Safeonweb@Work) and Spain
— the opposite kind of fact, since its transposition is still a bill and INCIBE
itself writes that the competent authorities and the single point of contact have
to wait for it. A country outside the Union gets no frame and the document says
so rather than reaching for the nearest plausible agency.

### The directive, named at last, and conditionally

The tool never once said "NIS 2". The audit document now cites it from the
primary source — **Directive (EU) 2022/2555**, 14 December 2022, OJ L 333/80, to
be transposed *"by 17 October 2024"* under article 41, whose article 21(2)(h)
lists *"policies and procedures regarding the use of cryptography and, where
appropriate, encryption"* among the risk-management measures.

Conditionally, because the first version of that sentence broke the rule this
release is about. English is read everywhere and most Spanish speakers are
outside the Union, so "one of the measures NIS 2 asks for", stated flat, assumes
a reader's jurisdiction from their language. In the Union it is the obligation
this inventory answers to; outside it the frame is whatever `regime` names, and
the READMEs point at the two non-EU frameworks the tool already carries.

**No transposition status is stored, and that is deliberate.** The Commission's
own country pages are a state of play from mid-2025 — Germany still reads
"reasoned opinion, 7 May 2025" there, ten months after its law entered into force
and with 20,141 entities registered. A status frozen into a release is a
regulatory fact that goes stale between versions and still reads as current. The
documents cite the Commission's living page instead, and two tests fail the build
if a verdict ever appears in a document or that pointer ever leaves one.

### The one image a reader actually runs was named by a tag

The Makefile pinned its three images by digest and `./sablier` — the thing the
README tells somebody with no PHP to run — named the bare `php:8.4-cli-alpine`,
with the checked digest sitting in the same directory. It is pinned now, and the
suite asserts both that the launcher names a digest and that it names the same
one as the Makefile; a single assertion would have passed on two different
digests.

### A README that stops

It had reached 1,484 lines and thirty sections, which is a manual with no table
of contents. It is 144 lines: what the tool does, three commands, why the
interview is the tool, what it is not, and a map. Twenty-eight sections moved
into ten pages under `docs/`, one per subject, each in the three languages, and
not one line of prose was retyped — the sections were sliced by position out of
the three files, whose order was identical. The heading-parity check now runs per
document, and every `docs/` and `examples/` link the READMEs make must resolve.

## v0.9.0 — 2026-10-08

The release about the one claim a signature cannot make.

### A date can now be attested by several authorities

`--timestamp` repeats, or takes a comma-separated list, and the same digest goes
to each authority named. One authority is one point of trust; an authority only
ever sees thirty-two bytes, so there is nothing to coordinate and none of them
needs to know it is not alone. The cost is one HTTP request each.

Each token is written to its own slot — `report.html.tsr`, `report.html.2.tsr`,
… in the order the authorities were named — and the slot belongs to the
authority across runs: one that was unreachable today leaves its slot empty
instead of shifting the others down and detaching their antecedence. A failure
is loud and does not stop the others being asked, which would be a strange thing
to give up in a mechanism whose purpose is surviving one operator having a bad
day. `verify` walks the slots rather than reading the first one: a reader handed
three attestations and a command that checks one would verify a third of what
they hold and conclude on the whole of it.

What it buys is worth stating precisely, and the report states it: each
authority sets an *independent* upper bound, so the date defensible without
trusting any single operator is the latest of them, and forging the earliest no
longer detaches the document from a date.

### The verification command now works off Debian

The report printed `-CAfile <the authority's root>`, and the command everybody
publishes for RFC 3161 hardcodes `/etc/ssl/certs/ca-certificates.crt`. Both are
wrong on machines people actually use, and both fail the same way a forged token
does — `Verification: FAILED` — so a reader on the wrong distribution learns that
our seal is broken rather than that their paths differ.

Two false assumptions, measured rather than assumed. The certificate store is a
Debian convention: that file does not exist on Fedora, Rocky or openSUSE. And the
token carries its full chain, but LibreSSL — the `openssl` Apple ships — does not
read it and answers `unable to get local issuer certificate`.

The report now prints a three-step recipe that locates the store with
`openssl version -d` and hands the chain over with `-untrusted`, checked as
printed on Debian 13, Ubuntu 24.04, Alpine 3.22, Fedora 42, Rocky 9,
openSUSE Leap 15.6, and macOS with both OpenSSL 3.6 and LibreSSL 3.3.

### The release job had never run once

Worth writing down, because the way it hid is more instructive than the bug. The
job that cuts a release on a tag carried `Sablier\\Version::NUMBER` in its YAML,
which reaches PHP with two backslashes and is a parse error — so the step meant
to check the version constant against the tag failed the build instead of
checking anything. It only runs on tags, and the v0.6.0, v0.7.0 and v0.8.0
releases were created by hand, by us, in the same sitting as the automation that
was supposed to replace that gesture. The releases existed, so nobody went
looking at why the job that was supposed to create them had not.

It also owed an archive it never attached. `docs/airgap.md` tells a closed site
that every release carries an archive built from the tag, that `make release`
rebuilds the same bytes, and that the digest is in the notes — and none of that
was true of any release. The job now builds it, attaches it, and appends its
digests — plural, for the reason the next section gives.

### And the reproducible archive was not reproducible

Found by doing what the documentation tells a reader to do, on a second machine.
`docs/airgap.md` said a release's archive could be rebuilt from its tag to the
same bytes, and published one digest for the `.tar.gz`. Rebuilding v0.9.0 gave
`fb3a8c5d…` against the `ecafa3e6…` the release announced.

The tar was identical on both sides — `3b733323…` under git 2.50.1 and git
2.47.3 alike — so `git archive` is reproducible and `gzip` is not: `-n` stops it
writing the current time into the header, and does nothing about two deflate
implementations disagreeing. Apple gzip 479 and GNU gzip 1.13 compress the same
tar to different bytes.

So the claim moved to where it holds. `make release` and the release notes now
carry two digests, and say which question each answers: the `.tar.gz` checks that
the file you were handed is the file we published, and the tar is the one that
reproduces from the tag on anybody's machine. The command in the notes stops at
`git archive` for that reason.

### And why the seal can be older than the report

A re-run that changes no finding keeps its token, so the masthead showed today
and the seal showed the first attestation, with nothing to say why — a document
appearing to contradict itself. The seal now carries the reason, because the rule
behind it is the point: antecedence is what a token buys, and replacing it
destroys it.

## v0.5.0 — 2026-10-03

The release where it stopped asking of others what it did not do itself.

### The managed services, as far as a file can tell

`.tf` files are now read. Every report said the cryptography of your database,
your object storage and your TLS termination appears in no file of the
repository — true of an application, and false the moment the infrastructure
sits beside it as code, which is most of the projects this tool is pointed at.

What it reads is what somebody decided: encryption switched off at rest or in
transit, a minimum TLS version below what is still negotiated, the server-side
encryption on a bucket and whose key it uses, the keys the infrastructure makes
for itself, an asymmetric KMS key. A managed database holding ten years of
accounting records with `storage_encrypted = false` is the same finding as a
backup script with no encryption.

It reads the intent and not the outcome, so the blind spot is reworded rather
than removed.

### The signature it tells everybody else to migrate to

A report carries two signatures now: Ed25519, verifiable anywhere PHP runs, and
**ML-DSA-65** in addition, through the openssl binary, from OpenSSL 3.5.

For three versions this tool told people to migrate before 2030 while signing
its own reports with Ed25519 alone, and its own report said so in the findings.
PHP cannot do it: libsodium has no post-quantum signature, and ext-openssl
reads an ML-DSA key but refuses to sign with it — `openssl_sign` takes a digest,
and ML-DSA is pure.

In addition rather than instead, which is hybridation and what ANSSI asks for;
borrowed rather than implemented, because a hand-written lattice signature here
would be indefensible; and stated when absent, with `verify` distinguishing
*did not match* from *could not be checked on this machine*.

### A key that signs once

`--sign=ephemeral` makes a pair for one report, signs with it, and destroys the
private halves before the command returns. Nothing to store, nothing to steal,
nothing to rotate, and a key that can never sign a second document.

What ties the document to a person is then a **fingerprint** — sixteen bytes
over both public keys, one line, carried by a channel that already proves who
is speaking. The report and that line must not travel the same way: whoever can
alter one in flight can alter the other. The audit prints the fingerprint in its
integrity section so a reader still has something to compare months later.

The post-quantum key is also vouched for by the declaration now, for the
long-lived case. It used to travel inside the signature it authenticated, which
proves nothing to the one reader a post-quantum signature exists for.

### Smaller

- the interview asks the questions that can change something **first**. Pointed
  at a real project it opened on five directories computing SHA-256 — sound at
  every declared lifetime, so no answer could have moved a verdict — and that
  was question one of four;
- `openssl_public_encrypt` was detected by nothing at all. RSA used directly is
  how most PHP code seals something for a recipient, and the fixture written to
  test the ordering found the hole;
- the README exists in three languages, English governing, with a test that
  fails when their sections diverge;
- the example declaration no longer maps a real production application, nor
  points its `probe` at somebody's live host;
- the test suite no longer opens two browser windows per run;
- a protocol's table of supported algorithms is inventory, not a use: an SSH
  client carries `hmac-sha1` because the specification obliges it to. Three of
  the six remaining false positives were this, and the measurement moves from
  25 % to **14 %** on the same 31 repositories.

## v0.4.0 — 2026-10-03

The release where the tool started applying its own standards to itself.

### The interview as one file

`sablier worksheet <path>` writes the whole interview into a single HTML page
that talks to nothing — no server, no port, no request, and no absolute path
from the machine that wrote it. It is opened from a memory stick in a room with
no network, answered in a browser, and hands back a block of JSON;
`sablier declare --import=` takes it from there.

It was built for a closed network, where the output of an audit is as sensitive
as the system it describes and a tunnel is not an option. It turns out to be
the simpler answer everywhere else: no certificate, no DNS, no question about
whether the auditor's laptop is sound.

The browser collects answers and nothing more. The merge — a name given twice
is one domain holding both paths and the longer lifetime — stays in PHP, so
there is one definition of it rather than two that drift.

### Nine reds out of ten were wrong

31 public PHP repositories, scanned with no declaration, every red finding
judged by hand. The first count was **82 false positives out of 89** — a tool
whose reds are wrong teaches people to stop reading reds, and nothing else in
this release would have mattered.

The causes were a handful of rules, not a thousand: `mcrypt_*` reported as DES
when the call never names a cipher, object hash codes and lock names read as
security controls because the heuristic looked at the line and not at the
function around it, HMAC-MD5 called broken when collisions do not reach the
construction, a call matched inside a comment, and test code presented as
production.

It stands at **6 out of 24 — 25 %**, with recall unchanged. The middle of that
story is in `docs/false-positives.md` and is the part worth reading: tuned on
one corpus the rate looked like 12 %, and on six repositories never used for
tuning it was 63 % again. The published number is the one measured after the
rules were made general.

### The browser is gone

`--pdf` no longer hunts for Chrome in fourteen locations and no longer falls
back to a pinned Chromium container. It typesets the file here: A4, the three
fonts every reader carries, the numbered sections, the tables, and the timeline
drawn in vector operations — the figure carries the argument, so it travels.

What that cost is colour and typography. What it bought is an export that
cannot fail for want of something to borrow, a file eighteen times smaller, a
page number on every page (which Chrome never gave us, since it ignores the CSS
that would print one), and **one container fewer to vouch for** — `make cve`
now proves three images instead of four, which is one less thing standing
behind the claim.

### A closed site, all the way to the printer

`--airgap` refuses instead of disabling: the probe and the advisory database
stop with a message naming the alternative, containers are refused because a
container is pulled, and a declared host is skipped into the blind spots rather
than dropped. `SABLIER_AIRGAP=1` sets it for a whole site.

The PDF then has nothing to borrow, so it is written here: A4, the three fonts
every reader carries, headings, tables, and a page number on every page — the
one thing Chrome would not do. A report that cannot be printed cannot be signed
or filed, and on those sites that is the difference between an audit and a
folder of HTML.

### Citing sources as they actually read

Five regulatory references, checked against the documents rather than against
memory. Three were wrong, and every one of them made this tool sound more
certain than its source — the failure mode that matters, since a report is read
in a room where somebody disagrees.

NIST IR 8547 is an **initial public draft** and is now cited as one; its dates
are right and are now quoted at the security level the table gives them. CNSA
2.0 has two dates, not one: 2030 for signing and networking, 2033 for browsers,
cloud and operating systems. Recommendation (EU) 2024/1101 asks for coordinated
national roadmaps within two years and does not contain the sentence we
attributed to it. ANSSI holds hybridation essential and requires it for French
security visas, which is not the same as requiring it of everybody.

`docs/scoping.md` had carried "re-verify: status of the document" since the
first week. Writing that line is easy; this is what it was for.

### What it says about itself

Scanned with its own tool, this repository turned up two things to fix. Its
declaration had no `declared_by`, no `declared_on` and no `service_until`, so
the report printed our own missing horizon in the blind spots — the feature
built for clients, pointed at us. And the exclusion list had eight entries, four
of which excluded files that produce no findings at all. Scanned with the list
removed entirely, this repository produces 47 findings instead of nine and not
one of them is red. The list is four entries now, and the README gives the
reason for each.

### Smaller

- the test suite no longer opens two browser windows per run: `serve` opens one
  for the person who typed it, and a pipe is not a person;
- the network surface is pinned by a test: sockets are allowed in four files,
  all behind the probe, and the build fails the day a detector grows one. Where
  the kernel allows it, a full scan also runs with the network stack removed;
- `--quiet` writes no report unless one is named;
- `--expose` mints a key for a session handed over through a tunnel, which a
  bind address cannot judge, and `--public=` prints the address to hand over;
- the ten detectors live in one place instead of three copies.

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
