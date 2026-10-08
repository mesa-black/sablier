# In a pipeline

*← back to the [README](../README.md)*

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

## The three containers, and what is claimed about them

A tool that reads where your keys are has no business telling you to run
images it has not looked at. Three are named in this repository —
`php:8.4-cli-alpine` for machines without PHP, `ghcr.io/phpstan/phpstan` for
the static analysis, and the scanner itself — and one command re-checks all
three:

```bash
make cve
```

Each of the three is pinned **by digest**, not only by tag. A tag is a name and a
name can be re-pointed; `make cve` proves something about bytes, so it would be
worth nothing if the bytes could change under the name the proof was made about.
`make images` prints what those tags resolve to today, so moving a pin is a
decision somebody makes rather than something that happens to them.

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
