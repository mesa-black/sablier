# Sablier

What is encrypted in your project, and **how long it holds**.

*[Français](README.fr.md) · [Español](README.es.md) — this English version is the
one that governs; the others are translations, and the drift is checked in CI.*

## Start here

**What it does.** Sablier reads a project — its code, its dependencies, its
Dockerfiles, its Terraform, and, if you let it, the TLS a server actually
negotiates — lists every piece of cryptography it finds, and gives each one an
**expiry date**. Not "this is weak", but: *this algorithm protects data that has
to stay secret until 2041, and it stops being trustworthy in 2030.* What comes
out is one HTML page a human can read, signed, with a date a third party
attested.

**How to use it, in three commands.**

```bash
sablier init /path/to/project       # 1. a declaration, pre-filled from the code
sablier declare /path/to/project    # 2. the interview — the one input no scanner has
sablier scan /path/to/project       # 3. the report
```

Step 1 writes `sablier.json` by guessing from what it sees, so you start from
something to correct rather than a blank form. Step 3 works on its own if you
are in a hurry — `sablier scan .` and you have a report.

**Step 2 is the tool.** Everything else is reading files. A scanner can see that
you use AES-256; nothing in your repository says how long the data under it has
to stay confidential, and that single number decides whether a finding is urgent
or irrelevant. So Sablier asks, in business language, domain by domain — a
payroll record, a medical file, a session token — and it records who answered
and when. Fifteen minutes with the person who knows, once a year.

**Why it matters, in one paragraph.** An adversary who records your encrypted
traffic today decrypts it when the machine exists. For data that must stay secret
beyond the expiry of RSA and the elliptic curves, **the compromise date is the
day it was encrypted, not the day of the attack** — so migrating later protects
what comes after, and not that data. Which is why the question is never "is this
algorithm strong" but "does its expiry fall before or after the end of the
confidentiality it is carrying".

**What it is not.** Not a vulnerability scanner — it reads what you *chose*, not
what is broken today. Not a compliance report: it produces one artefact, a
cryptographic inventory. In the Union that artefact is one of the measures NIS 2
asks for; outside it, the same inventory answers to whichever framework you
adopt — the tool carries NIST IR 8547, the NSA's CNSA 2.0 and the EU roadmap, and
which one applies is a field in the declaration rather than a default. Either
way it says nothing about registering with an authority or reporting
incidents. And it has no
opinion it will not show you: every finding prints its evidence, its fingerprint,
and a pre-filled way to contest it.

**Then what.** Sign the report and have its date attested by somebody who is not
you (`--sign`, `--timestamp`), file the audit document (`--audit`), put the
switch-over dates in a calendar (`--calendar`), and re-run it once a year —
deadlines move, and a confidential lifetime of nine years is compliant this year
and not the next.

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
unchanged code inside `php:8.4-cli-alpine`, **pinned by digest** rather than by
that tag — a tag is a pointer somebody else moves, and the launcher would
otherwise run bytes nobody here has checked. The same digest is in the
`Makefile`, and the test suite refuses a commit where the two disagree.
`make images` prints what the tag resolves to today, for updating the pin on
purpose. Nothing is installed, the report is written by your own user, and paths
are resolved against the directory you stand in — which is the one mounted, so
the launcher refuses a path outside it rather than writing a report that
disappears with the container.

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

## Documentation

The README stops here on purpose. Everything below is one page per subject, in the three languages.

| | |
|---|---|
| [`docs/detection.md`](docs/detection.md) | What it detects, and how sure it is |
| [`docs/declaring.md`](docs/declaring.md) | Declaring confidentiality lifetimes |
| [`docs/reports.md`](docs/reports.md) | What the reports say, and who they are for |
| [`docs/judging.md`](docs/judging.md) | Judging somebody else's inventory |
| [`docs/advisories.md`](docs/advisories.md) | Published vulnerabilities |
| [`docs/breach.md`](docs/breach.md) | After a breach |
| [`docs/pipeline.md`](docs/pipeline.md) | In a pipeline |
| [`docs/signing.md`](docs/signing.md) | Signing a report, and dating it |
| [`docs/closed-network.md`](docs/closed-network.md) | On a closed network |
| [`docs/design.md`](docs/design.md) | How it is put together, and what it refuses |
| [`docs/how-it-works.md`](docs/how-it-works.md) | How it works, in three diagrams |
| [`docs/airgap.md`](docs/airgap.md) | The closed-network posture, in detail |
| [`docs/scoping.md`](docs/scoping.md) | Scoping study: the other tools, and what is left that is ours |
| [`docs/false-positives.md`](docs/false-positives.md) | False positives: how one is contested, and what happens next |
| [`docs/declaration-session.md`](docs/declaration-session.md) | Running the declaration interview with somebody |

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
