<img src="assets/logo.svg" alt="" width="22" height="30" align="left" hspace="10">

# Sablier

What is encrypted in your project, and **how long it holds**.

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

The report is a self-contained HTML file: no remote font, no script, no request.
A tool that reads where the keys are must not open a socket to render its own
output.

`--pdf=FILE` writes a PDF as well, by borrowing a browser rather than shipping
one — the same rule as the TLS probe: use what is present, add nothing. It
looks for Chrome, Chromium, Brave or Edge: the macOS bundles by path, and on
Linux the usual PATH names (`google-chrome-stable`, `chromium`,
`brave-browser`, …), the snap shim, the two `/opt` paths the Debian and RPM
packages really install, and a Chromium that Playwright or Puppeteer already
downloaded.

**And if there is none**, it borrows one from a container
(`zenika/alpine-chrome`, pinned, scanned by `make cve` like the rest): the page
is mounted read-only, the destination directory writable, nothing else, and the
PDF belongs to whoever ran the command. The report says which browser produced
it, because one of the two did not exist on the machine five seconds earlier.

With neither a browser nor Docker, the tool says so and stops there — the HTML
report still prints to PDF from any browser, since it ships a print stylesheet
that forces the light palette and keeps charts, findings and the probe block
off page breaks.

## Two sources, because a repository can be wrong

**Static analysis** reads what the code declares. **The probe** performs an
ordinary TLS handshake and reports what the server actually negotiates — they
disagree often enough that reporting only the first is misleading. A project with
no post-quantum cryptography anywhere in its code can already be protected by its
CDN; a project that configured everything correctly can be terminated by an
intermediary that undoes it.

```
$ make probe HOST=showmetherex.com

  negotiated protocol          TLSv1.3
  cipher suite                 TLS_AES_256_GCM_SHA384 (256 bits)
  negotiated group             X25519MLKEM768
  certificate signature        ecdsa-with-SHA256
  accepted versions            TLSv1.2, TLSv1.3
```

The probe only belongs against hosts you are responsible for.

## Declaring confidentiality lifetimes

Without a declaration the tool applies a default lifetime and says so. With one,
it becomes useful. See [`examples/showmetherex.json`](examples/showmetherex.json).

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

One of those notes matters more than the rest: **a backup's lifetime is the
maximum of everything inside it.** It inherits the longest domain you declared,
whatever that is. That single line is where most red verdicts come from.

## How it is put together

Two extension points, because the scoping study names two axes that will
actually grow — and nothing else gets an interface.

```
DetectorInterface   one way of finding cryptography in one kind of file
  PhpDetector · ShellDetector · KeyMaterialDetector
  ServerConfigDetector · DependencyDetector

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

A share button hands the summary to Threema, which opens a local application
with plain text. Nothing reaches a third-party server, which is the only kind of
sharing this tool can offer without contradicting its own footer.

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

The identity comes from the declaration, where it is versioned with everything
else:

```json
"audit": {
  "client": "Example SAS",
  "auditor": "A. Lambert",
  "organisation": "Lambert & Co",
  "reference": "AUD-2026-014",
  "mandate": "Establish the exposure of confidential data to harvesting.",
  "statement": "The findings in section 5 were produced by the tool named in section 1…"
}
```

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
        run: git clone --depth 1 --branch v0.1.0 https://github.com/mesa-black/sablier.git "$RUNNER_TEMP/sablier"

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

## Signing a report

```bash
sablier keygen                                   # private key, mode 600
sablier scan /path --sign=sablier.key            # writes report.html.sig
sablier verify report.html.sig --declare=sablier.json
```

What is signed is **a digest of the findings, not the file**. Two runs of the
same inventory differ byte for byte — a rendering date, a duration — while
saying exactly the same thing; two renderings in two languages give the same
digest. The expected public key lives in the versioned declaration, because a
signature that verifies against whatever key came with it proves only that
somebody had a key.

And the uncomfortable part, printed in the report rather than buried in a
footnote: **the signature is Ed25519, which this very tool classifies as
quantum-vulnerable.** PHP offers no post-quantum signature at all — RSA and
ECDSA through ext-openssl, Ed25519 through ext-sodium, all three broken by the
same algorithm — so the choice was never "Ed25519 or nothing" but "Ed25519 or
equally exposed". That is defensible for a report
whose authenticity matters for months — a signature cannot be harvested, and
breaking the curve in 2035 does not forge a 2026 signature anyone still cares
about. It is not defensible for a report you must still prove genuine after the
expiry year. Sablier tells you which of the two you are in and lets you decide.

There is no blockchain here and there will not be one. A chain of your own is
one node, which is one person: no more trustworthy than the signature it would
replace. A public chain means the digest leaves the machine, which breaks the
promise in the report's own footer. When a date has to be opposable to someone
who does not trust you, a timestamping authority answers it in one request.

## The three containers, and what is claimed about them

A tool that reads where your keys are has no business telling you to run
images it has not looked at. Four are named in this repository —
`php:8.4-cli-alpine` for machines without PHP, `zenika/alpine-chrome` for
machines without a browser, `ghcr.io/phpstan/phpstan` for the static analysis,
and the scanner itself — and one command re-checks all four:

```bash
make cve
```

It fails on any high or critical vulnerability, and it runs in CI on every
push **and every Monday**, because an image with no known vulnerability today
is not an image with no known vulnerability in March.

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
