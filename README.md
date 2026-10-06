# Sablier

What is encrypted in your project, and **how long it holds**.

*[Français](README.fr.md) · [Español](README.es.md) — this English version is the
one that governs; the others are translations, and the drift is checked in CI.*

*How it works, in three diagrams: [docs/how-it-works.md](docs/how-it-works.md)*

*On a closed network: [docs/airgap.md](docs/airgap.md)*

*Scoping study: [docs/scoping.md](docs/scoping.md)*

Sablier reads a project, inventories its cryptography, and crosses that inventory
with the one input no scanner can find on its own: **how long each kind of data
has to stay confidential.** Out of that crossing comes the only question that
matters about post-quantum today:

> Data encrypted today with RSA or an elliptic curve, and required to stay secret
> past the expiry of those algorithms, is **already lost**. Migration protects
> what comes after it, not that data.

This is the *harvest now, decrypt later* model: an adversary captures today what
they will decrypt later. For the data concerned, the compromise date is the day
it was encrypted, not the day of the attack.

The formula is **Mosca's inequality** (2015), simplified: the framework is
standard and named, and other tools implement it. [`docs/scoping.md`](docs/scoping.md)
lists them honestly and says what is left that is ours — mostly a set of refusals,
and a live probe that reads what a server actually negotiates rather than what a
file claims.

Status: **prototype**.

## Try it

```bash
make demo                                   # fixture project + report
sablier init /path/to/project               # a declaration to correct, not a form to fill
make scan DIR=/path/to/project LANG=en      # a real project
make scan DIR=/path/to/project PDF=1        # …and a PDF alongside it
make scan DIR=/path/to/project AUDIT=1      # …and the audit document
make probe HOST=example.org                 # what a server actually negotiates
make test                                   # does the risk model still discriminate?
```

**No PHP on this machine?** `./sablier` is the same tool through a container:
it uses the local interpreter when it is 8.4 or newer, and otherwise runs the
unchanged code inside `php:8.4-cli-alpine`. Nothing is installed, the report is
written by your own user, and paths are resolved against the directory you
stand in — which is the one mounted, so the launcher refuses a path outside it
rather than writing a report that disappears with the container.

```bash
cd /path/to/project && /path/to/sablier scan . --out=report.html
```

Reports are available in French, English and Spanish (`--lang=fr|en|es`).

**Without running anything:** [`examples/report.html`](examples/report.html) is
the technical report for the fixture project, and
[`examples/audit.html`](examples/audit.html) the audit document of the same
run. Both are regenerated at each release, and both are a single self-contained
file — open them from disk. [`examples/report.pdf`](examples/report.pdf) and
[`examples/audit.pdf`](examples/audit.pdf) are the same two documents as this
tool typesets them, thirteen and twenty-six kilobytes, which is what a PDF
weighs when no browser printed it. [`examples/worksheet.html`](examples/worksheet.html)
is the offline interview as it is handed over, [`examples/cbom.json`](examples/cbom.json)
the same inventory as CycloneDX, and [`examples/crossings.ics`](examples/crossings.ics)
the crossing dates as a calendar. [`CHANGELOG.md`](CHANGELOG.md) says what each
release changed.

The report is a self-contained HTML file: no remote font, no script, no request.
A tool that reads where the keys are must not open a socket to render its own
output.

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

## What it says about itself

This repository carries its own declaration and is scanned on every build, with
the result compared against `.sablier/baseline.json`. Nine findings: six
Ed25519 signatures, two SHA-256 digests it is right to leave alone, and one it
calls an identifier rather than a control — our own fingerprint function, which
is exactly what it is.

The declaration excludes four paths, and a reader is owed the reason for each:

| excluded | why |
|---|---|
| `src/Detector/*` | the detectors contain the patterns — the string `rsa` there is what finds RSA, not a use of it |
| `src/Probe.php` | the same, for the handshake it reads |
| `tests/fixtures/*` | cryptography planted on purpose, so the tests have something to find |
| `tests/run.sh` | the `openssl genrsa` the suite runs to make itself a key |

Scanned with that list removed, the repository produces 47 findings instead of
nine and **not one of them is red**: twelve pattern strings in the detectors,
twenty-three in the fixtures, and the rest already reported. The list hides
nothing; it was trimmed from eight entries to four when this was checked,
because four of them excluded files that had nothing in them.

The declaration also had to be brought up to the standard this tool asks of
everybody else. It carries `declared_by` and `declared_on` now, and a
`service_until`, because the report was printing our own missing horizon in its
blind spots — which is the tool working, and was not a comfortable way to find
out.

## How often it is wrong

Measured, not claimed: **31 public PHP repositories, 959 findings, 21 of them
red, 3 of those wrong — 14 %.** Before this measurement it was 92 %, and the
nine out of ten reds that were wrong were all the same handful of mistakes:
`mcrypt_*` reported as DES, object hash codes and lock names read as security
controls, HMAC-MD5 called broken, a call matched inside a comment.

[`docs/false-positives.md`](docs/false-positives.md) has the method, the fixes,
the judgement on every remaining red finding, and the repositories to reproduce
it — including the six that were never used for tuning, where the rate was 63 %
until the rules were made general rather than particular.

Three false positives are left and are documented rather than hidden. Recall did
not move: every real finding the first corpus contained is still reported.

## The managed services, as far as a file can tell

Every report carries the same admission: the cryptography of your database,
your object storage and your TLS termination appears in no file of the
repository. That is true of an application. It stops being true the moment the
infrastructure sits beside it as code.

`.tf` files are read for the decisions somebody wrote down — `storage_encrypted
= false`, a `minimum_protocol_version` below what is still negotiated, the
server-side encryption on a bucket and whose key it uses, the keys the
infrastructure creates for itself, an asymmetric KMS key. A managed database
holding ten years of accounting records with encryption switched off is the
same finding as a backup script with no encryption: the provider does not
change the arithmetic.

What this reads is the **intent**, not the outcome, so the blind spot is
reworded rather than removed: what the provider actually does with that
declaration — its own keys, its own algorithms, its TLS termination — is still
outside the report.

## Two sources, because a repository can be wrong

The probe covers HTTPS, SMTP, IMAP, POP3, PostgreSQL, MySQL, LDAP, and the
implicit-TLS ports of AMQP, Redis and MQTT — plus **SSH**, which never becomes
TLS and so gets its own reader: it takes the banner and the server's KEXINIT,
which is where `sntrup761x25519` shows up when somebody enabled a post-quantum
key exchange that no file in the repository mentions. It sends a banner, reads
one packet and hangs up: never a key, never a password, never far enough to be
an authentication attempt.

**Static analysis** reads what the code declares. **The probe** performs an
ordinary TLS handshake and reports what the server actually negotiates — they
disagree often enough that reporting only the first is misleading. A project with
no post-quantum cryptography anywhere in its code can already be protected by its
CDN; a project that configured everything correctly can be terminated by an
intermediary that undoes it.

```
$ make probe HOST=example.org

  negotiated protocol          TLSv1.3
  cipher suite                 TLS_AES_256_GCM_SHA384 (256 bits)
  negotiated group             X25519MLKEM768
  certificate signature        ecdsa-with-SHA256
  accepted versions            TLSv1.2, TLSv1.3
```

The probe only belongs against hosts you are responsible for.

## What a framework declares

Most of this tool reads code. The most useful cryptographic facts about a web
application are not in its code: nobody writes `RS256` in a controller. They write
it once in a firewall, and every login for the next five years uses it.

```
config/packages/security.yaml      password hashers · OIDC · token handlers
config/packages/lexik_jwt_*.yaml   the signature behind every API token
config/packages/doctrine.yaml      whether the database connection is encrypted
config/app.php · hashing.php       Laravel's cipher and password driver
config/jwt.php · database.php      tymon/jwt-auth, and sslmode
config/filesystems.php             server-side encryption asked of an object store
config/passport.php                the RSA keys signing Laravel's OAuth2 tokens
config/broadcasting.php            whether real-time traffic is over TLS
app/Config/Encryption.php          CodeIgniter's cipher and digest
config/web.php                     Yii's signed cookies
```

Laravel gets one more thing, and it is about effort rather than algorithms.
`Crypt::encryptString()`, `Hash::make()` and the bare `encrypt()` helper name no
algorithm — the cipher is in `config/app.php`, the driver in
`config/hashing.php` — so the configuration alone gives one finding per
application and says nothing about how much of it depends on that line. Those
call sites are recorded too, at **medium confidence** and never claiming to name
the cipher, because the day it has to change what matters is how many places have
to be opened. That is the third factor of the risk model, counted in places
rather than estimated in days. The bare helpers are read only in a file that
imports `Illuminate`: `encrypt()` is the most generic function name in the
language, and outside Laravel it belongs to somebody else.

Symfony needed a detector of its own, because it is the one framework here that
puts its security configuration in YAML — and until this existed, a tool that only
opened `.php` files walked past all of it.

**The value decides, not the key.** `algorithm:` appears in a dozen unrelated
places in a Symfony configuration, so a pattern matches only when the value is a
hasher or a JOSE algorithm this tool recognises. The cost of getting that wrong
was measured rather than imagined: a first version read `cookie_secure: auto` in a
real application and reported a password hasher that does not exist, because
`auto` is also the name of one. The fixture now contains that exact line, in a
file that declares no hashers, and a test fails if it is ever read as one.

**`HS256` and `RS256` are not the same kind of thing**, and a report that prints
the JOSE name and stops has told the reader nothing. The first is a shared secret
and survives a quantum computer; the second is an RSA signature and does not.

**OIDC is the case worth having built this for.** A firewall that delegates login
to an identity provider names the provider and never the signature: the algorithm
comes from the keys that provider publishes, so it is not in the repository and
cannot be. That is this tool's whole argument stated by somebody else's
configuration format — the entire authentication path rests on an algorithm nobody
here chose — so it is reported as undetermined and asks to be declared.

And it stays in its lane. `verify_peer: false` under `http_client` is a real
defect and is deliberately not reported: it is a problem of today's
authentication, not of when a cipher stops holding, and a tool that starts
reporting every security smell loses the right to be believed about 2035.

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

## How it is put together

Two extension points, because the scoping study names two axes that will
actually grow — and nothing else gets an interface.

```
DetectorInterface   one way of finding cryptography in one kind of file
  PhpDetector · ShellDetector · KeyMaterialDetector · AssetDetector
  EnvDetector · ServerConfigDetector · SshConfigDetector · TerraformDetector
  FrameworkConfigDetector · FrameworkYamlDetector · LaravelDetector
  SymfonyVaultDetector · DependencyDetector

ReporterInterface   one way of rendering an analysis
  HtmlReporter · AuditReporter · CbomReporter · JsonReporter
```

`Scanner` walks a tree and knows nothing about cryptography; the detector list is
composed in `bin/sablier` and passed in. Adding a language means writing a
detector and registering it, never editing the scanner. `Analysis` carries
everything a reporter needs, so adding a fact to the report does not change every
renderer's signature.

Everything else stays concrete. `Catalogue`, `Assessor`, `Declaration` and `Lang`
have one implementation each and no second one in sight: an interface with a
single implementation and no prospect of another is a cost with no buyer.

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

## Judging somebody else's inventory

Detectors are not where this tool can win. CycloneDX 1.6 is a published format,
several scanners emit it, and they have teams behind them. What nobody else does
is cross an inventory with **how long the data it protects has to stay secret**.
So the inventory can come from anywhere:

```bash
sablier judge cbom.json --declare=sablier.json --out=report.html
```

A CBOM produced by another scanner — in Java, Python, Go, a language this
project will never parse — comes out of that command with a domain, a lifetime
and a verdict attached to every component. The locations in the CBOM are matched
against the `paths` of your declaration exactly as a local scan would be:

```
  example-service — inventory imported from another-scanner 2.1.0, 3 locations, 5 findings

    COMPROMISED              1
    BROKEN TODAY             1
    WATCH                    2
    CLEAR                    1
```

Three things are refused on the way in, and they are what makes the import
usable rather than flattering:

- **the detection is not ours, and the report says so** — in the blind spots,
  with the name of the tool that produced it. We judge what we were handed;
  whether that scanner read the code correctly is its author's claim;
- **an algorithm this tool does not know is never guessed at.** It is counted and
  named in the report (`Components of the CBOM left unjudged … : 2 (Camellia,
  TLS)`), because an importer that silently drops what it did not understand
  manufactures exactly the false assurance this project exists to refuse;
- **the fingerprint is recomputed, never read from the file.** A CBOM that could
  assert the fingerprint of an existing acceptance would walk straight through
  the decision attached to it.

One distinction survives the trip that most inventories lose: CycloneDX records
the **primitive**, so RSA signing arrives as a signature and RSA encrypting as
key transport — and this tool treats the first as not harvestable and the second
as harvestable, which is the whole risk model.

The other direction is `--cbom=FILE`, on `scan` as well as on `judge`:

```bash
sablier scan . --cbom=cbom.json --out=report.html
```

The findings leave as CycloneDX 1.6 `cryptographic-asset` components, with the
verdict, the domain, the lifetime that produced it and the fingerprint carried
as `sablier:` properties. Two things are deliberately not written: a
`nistQuantumSecurityLevel` other than zero — zero is what a quantum computer
breaks, and claiming levels 1 to 5 for everything else would be inventing
figures — and an OID, which is never guessed. Support for cryptographic assets
is recent in the tools that consume CBOMs; if yours rejects something we emit,
that is a rule to fix and it belongs in this repository.

## What hides in the files nobody reads

A repository's images, fonts and archives are copied, reviewed by nobody and
shipped. They are also a convenient place to leave something. Three checks,
graded by what they actually prove:

- **key material inside a binary asset.** A PEM header in a `.png` is not an
  accident — and it was already being found, because the key detector reads
  every file rather than the ones with key-shaped names. What is new is the
  sentence that says where: *"Key block found at byte 73 of a .png file. A
  binary asset is not a place key material arrives in by accident."*;
- **bytes after the end of the image.** PNG ends at `IEND`, JPEG at `FFD9`, and
  a file that continues past it carries something else. Reported as **to
  confirm**, with the byte count, never as a verdict: a colour profile and an
  exfiltrated archive look the same from here, and only one of them is a
  problem;
- **an extension that lies about the content.** The magic bytes say what a file
  is. A `.png` that starts with `PK\x03\x04` is a zip, which is worth a look
  and nothing more.

This is deliberately **not** steganography detection, and the report says so in
its blind spots. A message hidden in the low bits of an image is a research
problem whose false positive rate would bury every real finding this tool
prints. A tool that cries wolf about holiday photos loses the right to be
believed about a backup key — which is why the regression test that matters
most here is the one asserting silence on an ordinary image.

## A hole somebody already found

The rest of this report argues about 2035. An advisory says somebody found a
way in before the report was printed, which outranks it by a decade.

```bash
sablier advisories .                       # collect, once, on purpose
sablier scan . --advisories=.sablier/advisories.json
```

The first command is the only one in this tool that reaches the network, and it
reaches it for a database rather than with your inventory: the scanner runs in a
pinned container, reads your lock files from a read-only mount, and writes a file
you can read and version. A scan never does any of that — no package name of
yours leaves the machine while one runs.

A declared library with a published high or critical vulnerability stops being
plain inventory and becomes **BROKEN TODAY**, in the same category as MD5 and
SHA-1: a defect that owes nothing to quantum computing and comes before any
migration. The advisory numbers are printed with it, linked to NIST, GitHub or
OSV depending on who issued them.

Three lines hold it in place:

- **only the libraries this tool already inventories are judged.** A project has
  dozens of vulnerable dependencies and a report that lists them all buries the
  cryptography it was asked about. The others are counted in the blind spots, so
  the reader knows they were seen and left alone;
- **high and critical raise a verdict; medium and low are attached, not
  promoted.** The same threshold `make cve` applies to our own containers;
- **without the file, the report says the question was not asked** rather than
  implying the answer was no. That sentence is in the blind spots of every scan
  run without one.

## Citing a defect, and not citing a deadline

A finding that is broken today carries the published defect it rests on —
SHA-1 its collision CVE, MD5 its own, RC4 and 3DES theirs, TLS 1.0 and 1.1 the
two attacks that retired them — printed next to the verdict, linked to the
NIST entry a reader can go and check without taking our word for anything.

RSA and the elliptic curves carry none, and that is the point. A CVE is a
dated fact somebody else published; the post-quantum expiry is a regulatory
horizon, cited as such in the audit report's normative references. Filing the
second under the first would turn a deadline into an accusation, and it is
the kind of slippage this tool exists to refuse.

The numbers travel with the inventory: `references` in the JSON output, and
`externalReferences` of type `advisories` in the CBOM, where every consumer
already knows how to read them.

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

## In a pipeline

A report nobody compares is a verdict nobody acts on, and this tool's whole
argument is that the window closes on its own: the same codebase, scanned next
year, can turn red without a line of code moving, and an acceptance lapses on a
date somebody chose months earlier. So the second run is the one that matters.

The reference is the JSON report of a previous run — no second format, and a
file meant to be versioned next to the declaration:

```bash
sablier scan . --json=.sablier/baseline.json --out=report.html   # once
git add .sablier/baseline.json                                   # reviewed like any other file
```

Then every run compares against it:

```bash
sablier scan . --baseline=.sablier/baseline.json --out=report.html
```

```
  reference: .sablier/baseline.json (12 findings)

    + 1 new finding(s)
        36d82f61  BROKEN TODAY         sha1  src/NewToken.php:3
    ↑ 1 verdict(s) got worse
        d45d9d61  WATCH → COMPROMISED  rsa   deploy/backup.sh:3
    ● 1 red finding(s) already known, with no decision
        d87d2d2b  BROKEN TODAY         sha1  src/Tokens.php:17
    − 2 finding(s) gone: time to refresh the reference

  ✗ this needs another look: 3 decision(s) due.
     Fix it, or decide: sablier accept <fingerprint> --reason="…" --until=YYYY-MM-DD
```

Three things stop the build, and they are the three that require a human: a
**new** finding, a verdict that **got worse** — an acceptance that lapsed shows
up here — and a **red finding nobody has decided on**. Findings that disappeared
are printed and stop nothing; they are the reason to refresh the reference.

| Exit | Meaning |
|---|---|
| `0` | nothing new, nothing red pending — go |
| `2` | a decision is due |
| `1` | usage error: missing path, unreadable reference |

**The reference is not a suppression file.** A red finding it already recorded
still stops the build, every run, until somebody fixes it or accepts it — with a
reason, an expiry date, and a reviewer, as described above. A baseline that
silences what it records is how these tools empty themselves out within six
months, and the dates in this one come back on their own.

Refreshing the reference is therefore a deliberate commit, read in review like
any other. A pipeline that regenerates it after each failure records nothing.

```yaml
name: cryptography

on: [push, pull_request]

jobs:
  sablier:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          extensions: sodium, openssl, json
          coverage: none

      - name: Get Sablier
        run: git clone --depth 1 --branch v0.5.0 https://github.com/mesa-black/sablier.git "$RUNNER_TEMP/sablier"

      - name: Inventory the cryptography
        run: |
          php "$RUNNER_TEMP/sablier/bin/sablier" scan . \
            --baseline=.sablier/baseline.json \
            --out=sablier-report.html \
            --no-probe

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sablier-report
          path: sablier-report.html
```

Pin a tag rather than a branch: this tool decides whether your build passes.
`--no-probe` is deliberate — a runner probes your servers from somebody else's
network, which measures their path rather than yours; run the probe from a host
that reaches your own services, on a schedule. And upload the report `if:
always()`, because the run you most want to read is the one that failed.

Without `--baseline`, the exit code is `2` only when a `COMPROMISED` finding is
present. That is enough to try the tool out, not enough to live in a pipeline.

`--quiet` writes **no report unless you name one**. Run by hand, `scan` leaves a
`report.html` next to you because that is what you came for; run with `--quiet`,
it answers in the exit code and writes only the files you asked for by path. A
tool that leaves an unrequested page at the root of somebody's repository on
every build is leaving state behind.

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

## On a network that has none

```bash
sablier scan /path/to/project --airgap --out=report.html --pdf=report.pdf
```

`--airgap` refuses rather than disables. `--no-probe` is a convenience — it
skips a step you could have run; on a closed site that is the wrong shape,
because a flag you can forget is a flag you will forget. So `sablier probe` and
`sablier advisories` stop with a message naming what to do instead, every
container is refused since a container is pulled, and a declared probe host is
skipped and **written into the blind spots** rather than silently dropped. A
site sets it once for everybody with `SABLIER_AIRGAP=1`.

The PDF then has no browser to borrow and no container to pull one from, so it
is typeset here instead: A4, the three fonts every reader already has, and a
page number on every page — which is the one thing the browser export cannot do,
because Chrome ignores the CSS that would carry one. Plainer than the printed
HTML, and it exists, which is the whole argument: a report that cannot be
printed cannot be signed or filed.

Nothing in this tool reaches the network unless you name a host. Sockets exist
in exactly four files — `Probe.php`, `SshProbe.php` and the two transports —
all of them behind `sablier probe` and the probe step of a scan, which
`--no-probe` removes. `sablier advisories` is the one command that goes out,
and it goes out for a vulnerability database rather than with your inventory.

That claim is pinned by a test rather than asserted: the list of files allowed
to open a socket is checked on every run, and the build fails the day a
detector grows one. Where the kernel allows it, the suite also runs a full scan
with the network stack removed (`unshare -rn`) and compares the result.

It matters because the output is the sensitive part. An inventory of where the
cryptography lives in a system is as sensitive as the system, so on a closed
network the question is not whether a tool promises to send nothing, but
whether it *can*. There is no telemetry, no update check, no dependency to
fetch: four lines of autoloader, PHP 8.4, and a repository somebody can read in
an afternoon before carrying it in.

## Signing a report, with the signature we tell you to use

```bash
sablier keygen                                   # two keys, Ed25519 and ML-DSA-65
sablier scan /path --sign=sablier.key --out=report.html
sablier verify report.html.sig --declare=sablier.json
```

For three versions this tool told people to migrate their signatures before
2030 and signed its own reports with Ed25519 alone — and said so, in its own
findings. The reason was not laziness: **PHP cannot do it.** libsodium exposes
no post-quantum signature, and ext-openssl reads an ML-DSA key but refuses to
sign with it, because its API takes a digest and ML-DSA is a pure scheme with
nothing to pre-hash. `openssl_sign` answers `invalid digest`.

The openssl **binary** can, from 3.5, and that is the one the probe already
borrows. So a report now carries two signatures: Ed25519, verifiable anywhere
PHP runs, and ML-DSA-65 in addition. Three rules keep that honest:

- **in addition, never instead** — replacing one with the other would make
  reports unverifiable for whoever has the older library, which is most people.
  It is also what ANSSI asks for and what this tool cites: hybridation;
- **borrowed, never implemented** — a hand-written lattice signature in a tool
  whose credit rests on not inventing cryptography would be the worst thing it
  could ship;
- **said out loud when absent** — on an older OpenSSL the report states that it
  carries one signature and why, and `verify` distinguishes *did not match*
  from *could not be checked here*. Collapsing those two would turn a missing
  library into a forgery accusation.

### A key that signs once

```bash
sablier scan /path --sign=ephemeral --out=report.html
#   Key made for this report, used once, destroyed. Fingerprint of both public keys:
#       7D52 D126 6B6B EA5D 58D4 1FE8 48D4 AFD9
sablier verify report.html.sig --fingerprint="7D52 D126 …"
```

`--sign=ephemeral` makes the pair for this report, signs, and destroys the
private halves before the command returns. Nothing to store, nothing to steal,
nothing to rotate — and a key that can never sign a second document, which is a
property a long-lived key does not have.

What ties the report to a person is then the **fingerprint**, not a file: one
line, carried by a channel that already proves who is speaking. An ML-DSA
public key is 2.7 kB and nobody pastes that into a message; sixteen bytes of
SHA-256 over both keys fit in a sentence, and the recipient checks the file
against them. SSH host keys have been authenticated this way for thirty years.

**The report and the fingerprint must not travel the same way.** Anyone who can
alter one in flight can alter the other, and the whole guarantee collapses.
Report by e-mail, fingerprint by Threema or out loud — not both by e-mail.

The audit report prints the fingerprint in its integrity section, so a reader
holding the document months later still has something to compare.

For a long-lived key instead, both halves are vouched for by the versioned
declaration, `signing_public_key` and `signing_public_key_pq`. A post-quantum key asserted only by the file it
signs would be worth nothing to the one reader this signature exists for: the
one who can already forge the Ed25519 half.

### What is actually signed

**A digest of the findings, not the file.** Two runs of the same inventory
differ byte for byte — a rendering date, a duration — while saying exactly the
same thing; two renderings in two languages give the same digest.

**Each report names the one before it.** A second run over the same output path
reads the signature it is about to replace and records that digest inside what
it signs, with no flag to remember — so a folder of reports is an audit trail
rather than a pile of files, and `sablier verify new.sig --previous=old.sig`
says whether the link holds. A report that claims a predecessor says so even
when the earlier file is not at hand: somebody holding one document learns that
another exists.

With an ephemeral key each link is signed by a different pair, so the chain is a
sequence of independently authenticated statements that reference each other
rather than one key vouching for all of them. The recipient needs every
fingerprint, and the audit report prints each one.

There is no blockchain here and there will not be one. A chain of your own is
one node, which is one person: no more trustworthy than the signature it would
replace. A public chain means the digest leaves the machine, which breaks the
promise in the report's own footer. When a date has to be opposable to someone
who does not trust you, a timestamping authority answers it in one request —
which is the next section.

### A date somebody else attests

Every signature above proves two things and not a third: **which key signed, and
which findings it signed.** The `signed_at` field is covered by the signature, so
it cannot be edited afterwards — and it is read off the clock of the machine that
signed, which is yours. Backdating a report costs nothing, and the chain does not
help: one key holds every link, so the whole chain can be rebuilt in order and
will verify perfectly. These seals answer *who* and *what*. Nothing in them
answers *when*.

```bash
sablier scan . --sign=sablier.key --timestamp=https://tsa.example.org/tsr
```

A timestamping authority is handed the digest, never the document, and returns a
signed token saying that this digest was presented to it at this instant. It has
no stake in your conclusions, which is the entire point.

**The digest is what gets attested** — not the signature, not the file. It is
printed in the report, so the attestation can be checked with no reference to
this tool at all:

```bash
openssl ts -verify -digest <the digest printed in the report> \
  -in report.html.tsr -CAfile <the authority's root>
```

That is also why the token is a file of its own, raw DER beside the `.sig`: it is
exactly what the stock `openssl ts` command reads. And it survives an ephemeral
key — the key is destroyed, the attested date is not.

**There is no default authority.** Who attests your dates is a decision, like the
regime and the lifetimes, and a default would make it for you in a jurisdiction
you did not pick. The flag takes a URL or does nothing.

`sablier verify` picks the token up on its own when it sits beside the signature,
and reports four states rather than two, because collapsing them lies:

| | meaning |
|---|---|
| attested, verified | the authority's signature holds, up to a root this machine trusts |
| attested, chain unverified | the imprint matches this report; no chain to a trusted root could be built — a self-signed authority or a missing intermediate, not a forgery. Pass `--timestamp-ca=<file>` |
| invalid | the token attests a different digest, or it was tampered with. This fails the command |
| not checkable here | no openssl, or no certificate store to check against |

The imprint is compared **before** any question of trust, and that ordering is
the point: `openssl ts -verify` stops at a chain it cannot build, so without that
comparison "I cannot establish the chain" and "this token is about another
document entirely" came back as the same answer.

**The limit, printed in the report rather than left to be discovered.** A
timestamping authority signs with RSA or ECDSA, which this tool's own catalogue
classes as quantum vulnerable. A token is evidence for a dispute in the next few
years, not for 2040; keeping a date past that means re-attesting it while the
scheme still holds. A tool that spends forty pages saying signatures expire does
not get to make an exception for the one it relies on.

### Signing the input, not only the output

A report is signed, verified, chained — and the durations every verdict in it
rests on were a string anybody could type into `declared_by`. The one artefact
here that commits people was the one artefact nobody signed.

```bash
sablier endorse sablier.json         # ephemeral key, destroyed before it returns
sablier verify sablier.json.sig --declare=sablier.json
```

What is signed is the **decisions, not the bytes**: the regime, the lifetimes,
the paths, the trust anchors, the notes and the authors, with domains and paths
sorted. Reformat the file, reorder its keys, rewrap a note — the endorsement
holds. Correct a lifetime, add a path, change the regime — it breaks, which is
what somebody who endorsed that file expects.

The audit report then prints one of three things in the very section that
reproduces the durations: endorsed on a date, with the key fingerprint; **not
signed**, with the command to fix it; or — the interesting one — a signature that
no longer matches, which says the file this report rests on is not the file
somebody put their name to.

The key is ephemeral by default, like the reports'. A declaration endorsed at the
end of an interview, in front of the person who declared it, is exactly the case
that key was invented for: nothing to store, nothing to rotate, and the
fingerprint travels by the channel that already proves who they are.

## The three containers, and what is claimed about them

A tool that reads where your keys are has no business telling you to run
images it has not looked at. Three are named in this repository —
`php:8.4-cli-alpine` for machines without PHP, `ghcr.io/phpstan/phpstan` for
the static analysis, and the scanner itself — and one command re-checks all
three:

```bash
make cve
```

It fails on any high or critical vulnerability, on **both architectures** — a
multi-arch tag is several images rebuilt at different times, and a claim that
only holds for the laptop it was made on is not a claim. It runs in CI on every
push **and every Monday**, because an image with no known vulnerability today
is not an image with no known vulnerability in March. It has already caught
one: a pcre2 advisory that landed in the PHPStan image between two runs, hours
before upstream rebuilt it.

Which is the case the gate has to survive without being switched off, and it
arrived the same day. `.trivyignore.yaml` carries that decision — a statement
somebody wrote and a date it stops being true, the same two things `sablier
accept` demands of anybody using this tool. One entry stands today:
**CVE-2026-103111**, pcre2 in the PHPStan image, fix published upstream and
the image not rebuilt yet; the only regular expressions reaching that
container are the ones in this repository. It expires on 2026-10-22, after
which the gate goes red again rather than quietly staying green — which is the
entire difference between a decision and a suppression file.

The claim is exactly that, and no larger: *no known high or critical
vulnerability, per Trivy's database at the time of the scan*. There is no
claim about unknown ones, and none about the low and medium findings, which
are visible in the same output.

The Alpine image is not a taste: at the time of writing Trivy reports **162
high or critical vulnerabilities in `php:8.4-cli`** — 46 of them with a fix
available — and **none** in `php:8.4-cli-alpine`. The pinned versions in the
`Makefile` are what `make cve`, the launcher and the CI all use, so the figure
above is one command away from being contradicted.

Static analysis runs at **level max** (`make phpstan`), in a container for the
same reason: this project ships no `vendor/` directory, and a QA tool is not a
reason to start one.

## What the tool refuses to do

- **Guess.** An algorithm coming from a variable is reported as undetermined,
  with its location. A wrong inventory is worse than an incomplete one, because
  nobody checks an inventory twice.
- **Predict.** The expiry date used is the regulatory deadline (2035 by default,
  configurable), not a prophecy about when a quantum computer arrives.
- **Shout.** Strong symmetric cryptography is reported as clear, a signature is
  not treated as a leak, an `md5()` used as a cache key is filed as off-topic,
  and a declared dependency is never a red alert — it is a use to confirm.
- **Fix by itself.** Rewriting cryptography without understanding the context is
  an incident generator.
- **Leave.** No account, no upload, no telemetry, no dependency.

## What it does not see

The report prints its own blind spots, at the same size as everything else: the
cryptography of managed services, live TLS negotiation for undeclared hosts, keys
held in an HSM, and data lifetimes nobody declared.

An inventory that does not say what it failed to look at is not an inventory.

## First results

First scan on a real project (Show me the REX, ~1,900 files): 17 findings, **no
red alert** — and three lessons that changed the tool immediately.

1. Backup encryption, the most sensitive operation in the project, **is not in
   the repository**: it lives in a script on the server. Static analysis alone
   will never see what matters most unless you declare it.
2. The first version reported a `md5()` in a test and a TOTP dependency — whose
   SHA-1 is mandated by the specification — as breaks. Two false positives out of
   fifteen findings is enough to lose the reader. Hence the separation between
   *inventory* and *use*, and test code filed as off-topic.
3. The probe found what no file could say: the site already negotiates
   **X25519MLKEM768**, a hybrid post-quantum key exchange. Nothing in the
   repository mentions it.
