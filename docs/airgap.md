# Running on a closed network

Everything on this page is checkable with the commands given beside it. That is
the point: a security questionnaire answered with assurances is answered twice,
the second time by whoever did not believe the first.

## What this tool can send, in full

Five places in the source can open a socket or start a container. There is no
sixth — the list was produced by reading every call that could, not by
remembering:

| what | when | what leaves the machine |
|---|---|---|
| TLS probe | `probe`, and `scan` when the declaration names a host | a TLS handshake to the host **you declared**, nothing else |
| SSH probe | the same, for an `ssh://` host | an SSH version exchange, no authentication attempt |
| advisory collection | `advisories` | a container image pull, then a local filesystem scan |
| timestamp | `scan --timestamp=<url>` | **a SHA-256 digest**, to the authority you named |
| the interview server | `serve` | binds a local port; it listens, it does not call |

Nothing else. No telemetry, no update check, no error reporting, no package
manager: this project has no dependencies, which is why its `composer.json`
requires nothing and why CI asserts `test ! -d vendor` on every run.

The timestamp line deserves its own sentence. What is sent is the digest of the
findings — thirty-two bytes — and never the document, the file names, or anything
a digest could be reversed into. That is the design of RFC 3161 and the reason
the flag exists: an authority can attest a date without being told what it dates.

## The switch

```sh
export SABLIER_AIRGAP=1        # for a whole site, set once
sablier scan . --airgap        # or per run
```

It **refuses**, it does not skip. A flag that quietly does less is a flag whose
absence nobody notices; a command that stops with a message is one somebody
reads.

```
✗ Refused in air-gapped mode: "advisories" needs the network.
  Drop --airgap if this machine is allowed out, or run that step from one that is
  and carry the file back.
```

Refused under the switch: `probe`, `advisories`, `--timestamp`, and every
container — a container is a pull. Allowed: everything that only reads the files
in front of it, including an advisory file collected elsewhere and carried in.

Check it yourself, in four lines:

```sh
SABLIER_AIRGAP=1 sablier probe tls://example.org          # refuses
SABLIER_AIRGAP=1 sablier advisories .                      # refuses
SABLIER_AIRGAP=1 sablier scan . --sign=ephemeral \
  --timestamp=http://tsa.example.org                       # refuses
SABLIER_AIRGAP=1 sablier scan . --out=report.html          # works
```

The test suite checks all four on every commit, which is how `--timestamp` was
found missing from the list: it was written after the switch and nobody had
wired it in.

## What the report does when it is opened

A document produced here loads nothing. Measured on the three it can produce:

```
report.html    script src=0, link rel=0, img src=0, iframe=0, form=0, @import=0
audit.html     script src=0, link rel=0, img src=0, iframe=0, form=0, @import=0
incident.html  script src=0, link rel=0, img src=0, iframe=0, form=0, @import=0
```

The stylesheet is inside the file, the chart is inline SVG, the fonts are the
ones the reader already has. Opening one on a machine with no network produces
exactly what it produces anywhere else.

It does contain **hyperlinks** — six in the report, one in the audit document —
to the references it cites and to the issue tracker. A browser does not fetch
them to render the page; a reader who clicks one goes to the internet. That
distinction is the whole difference between a document that is self-contained and
one that merely looks it, so it is stated rather than rounded off.

Run the measurement yourself on any report:

```sh
grep -cE '<(script|link|iframe)[^>]+(src|href)=|@import' report.html   # expect 0
grep -coE '<a [^>]*href="https?://' report.html                        # the clickable ones
```

## Verifying a signed report with no network

Nothing in verification reaches out. The signature covers a digest of the
findings, the public key travels inside the `.sig`, and the key that is supposed
to have signed is named in the declaration — a file in your repository.

```sh
sablier verify report.html.sig --declare=sablier.json
```

On a closed site the usual shape is an ephemeral key: a pair made for one
document, used once, destroyed before the command returns. Then nothing on disk
proves who signed, and the fingerprint has to arrive by a channel that already
proves who is speaking — a phone call, a secure messenger, a sheet of paper
carried across the room:

```sh
sablier verify report.html.sig --fingerprint="B29F D9F9 B999 88DD 6A24 4C63 17D3 6354"
```

An attested date is the one guarantee a closed network cannot have, and the
report says so rather than leaving a gap for the reader to discover. If a date
has to be opposable, the digest — and only the digest — can be carried out to a
timestamping authority by hand, and the token carried back.

## What this does not claim

Classification applies to information, not to software. If this tool reads
classified source, **its report carries the classification of what it read**;
that is automatic and is not a property of the tool. No French certification —
CSPN, Critères Communs, qualification ANSSI — has been obtained or applied for,
and no page here implies otherwise.

What is offered instead is the thing those schemes eventually measure: no
dependency to audit, no network by default, a switch that refuses rather than
skips, source anybody can read in an afternoon, and every claim on this page
reduced to a command you can run before believing it.
