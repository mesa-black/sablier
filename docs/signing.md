# Signing a report, and dating it

*← back to the [README](../README.md)*

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
# 1. wherever your openssl keeps its certificate store
O=$(openssl version -d | sed 's/.*"\(.*\)"/\1/')
for f in "$O/cert.pem" "$O/certs/ca-certificates.crt" /etc/ssl/ca-bundle.pem; do
  [ -f "$f" ] && CA="$f" && break
done

# 2. the chain the token already carries, extracted so it can be handed over
openssl ts -reply -in report.html.tsr -token_out -out token.der
openssl pkcs7 -inform DER -in token.der -print_certs -out chain.pem

# 3. the verification
openssl ts -verify -digest <the digest printed in the report> \
  -in report.html.tsr -CAfile "$CA" -untrusted chain.pem
```

The report prints exactly that, and it is three steps rather than one line
because the one-liner everybody publishes is wrong on most machines. The
certificate store is not at the same path from one system to the next:
`-CAfile /etc/ssl/certs/ca-certificates.crt` fails on Fedora, Rocky and openSUSE,
where that file does not exist. And the token carries its full chain, but
LibreSSL — the `openssl` Apple ships — does not read it and answers `unable to
get local issuer certificate`; handing the chain over with `-untrusted` changes
nothing elsewhere and settles that case. Checked as printed on Debian, Ubuntu,
Alpine, Fedora, Rocky, openSUSE, and on macOS with both openssl builds.

That is also why the token is a file of its own, raw DER beside the `.sig`: it is
exactly what the stock `openssl ts` command reads. And it survives an ephemeral
key — the key is destroyed, the attested date is not.

**There is no default authority.** Who attests your dates is a decision, like the
regime and the lifetimes, and a default would make it for you in a jurisdiction
you did not pick. The flag takes a URL or does nothing.

**And it takes several.** One authority is one point of trust, so the flag
repeats — or takes a comma-separated list — and the same digest goes to each:

```bash
sablier scan . --sign=sablier.key \
  --timestamp=http://time.certum.pl,http://timestamp.digicert.com
```

An authority only ever sees thirty-two bytes, so there is nothing to coordinate
and none of them needs to know it is not alone. Each token is written to its own
slot — `report.html.tsr`, `report.html.2.tsr`, … in the order the authorities
were named — and `verify` walks the slots rather than reading the first one. The
slot belongs to the authority and is stable across runs: one that was unreachable
today leaves its slot empty instead of shifting the others down and detaching
their antecedence.

What that buys is precise. Each authority gives an *independent* upper bound, so
the date you can defend **without trusting any single operator** is the latest of
them, and the one you can defend **if you trust one** is the earliest. Forging the
earliest no longer gets you anything: the others still bound the document on
their own.

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
