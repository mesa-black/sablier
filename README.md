<img src="assets/logo.svg" alt="" width="22" height="30" align="left" hspace="10">

# Sablier

What is encrypted in your project, and **how long it holds**.

*Scoping study: [docs/scoping.md](docs/scoping.md)*

Sablier reads a project, inventories its cryptography, and crosses that inventory
with something no tool knows: **how long each kind of data has to stay
confidential.** Out of that crossing comes the only question that matters about
post-quantum today:

> Data encrypted today with RSA or an elliptic curve, and required to stay secret
> past the expiry of those algorithms, is **already lost**. Migration protects
> what comes after it, not that data.

This is the *harvest now, decrypt later* model: an adversary captures today what
they will decrypt later. For the data concerned, the compromise date is the day
it was encrypted, not the day of the attack.

Status: **prototype**. The full scoping study — problem, prior art, admitted
limits, risk model — is in [`docs/scoping.md`](docs/scoping.md).

## Try it

```bash
make demo                                   # fixture project + report
make scan DIR=/path/to/project LANG=en      # a real project
make scan DIR=/path/to/project PDF=1        # …and a PDF alongside it
make probe HOST=example.org                 # what a server actually negotiates
make test                                   # does the risk model still discriminate?
```

Reports are available in French, English and Spanish (`--lang=fr|en|es`).

The report is a self-contained HTML file: no remote font, no script, no request.
A tool that reads where the keys are must not open a socket to render its own
output.

`--pdf=FILE` writes a PDF as well, by borrowing a Chrome or Chromium the machine
already has — the same rule as the TLS probe: use what is present, add nothing,
and say plainly when it is missing. With no browser installed, the HTML report
still prints to PDF from anywhere: it ships a print stylesheet that forces the
light palette and keeps charts, findings and the probe block off page breaks.

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

## How it is put together

Two extension points, because the scoping study names two axes that will
actually grow — and nothing else gets an interface.

```
Detector            one way of finding cryptography in one kind of file
  PhpDetector · ShellDetector · KeyMaterialDetector
  TlsConfigDetector · DependencyDetector

Reporter            one way of rendering an analysis
  HtmlReporter · JsonReporter
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
quantum-vulnerable.** It is what PHP ships. That is defensible for a report
whose authenticity matters for months — a signature cannot be harvested, and
breaking the curve in 2035 does not forge a 2026 signature anyone still cares
about. It is not defensible for a report you must still prove genuine after the
expiry year. Sablier tells you which of the two you are in and lets you decide.

There is no blockchain here and there will not be one. A chain of your own is
one node, which is one person: no more trustworthy than the signature it would
replace. A public chain means the digest leaves the machine, which breaks the
promise in the report's own footer. When a date has to be opposable to someone
who does not trust you, a timestamping authority answers it in one request.

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
