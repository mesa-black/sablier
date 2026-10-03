# Sablier — scoping study

> A working name. The hourglass is the product's metaphor: the sand does not run
> out at the same speed for every piece of data, and the question is never "is it
> encrypted" but "until when".

Status: scoping, nothing sold. This document is meant to be contradicted by the
first scan of a real project.

---

## 1. The problem, and why it is present rather than future

The post-quantum transition is treated everywhere as a distant deadline. That is
a reasoning error, and it is the one place where this tool has something to say
that others do not.

The threat model that matters is called **harvest now, decrypt later**: an
adversary able to capture traffic or copy a backup does it today, and keeps it.
They will decrypt when a relevant quantum computer exists. For the data
concerned, the compromise date is not the date of the attack: **it is the day it
was encrypted.**

Hence the only formula that structures the product:

```
if  (today + the data's confidentiality lifetime)  >  the algorithm's expiry year
then the protection has already failed, and migrating does not repair it
```

**This formula has a name, and it is not ours.** It is Mosca's inequality,
published by Michele Mosca in 2015: `X + Y > Z`, where X is the data's
confidentiality lifetime, Y is the time the migration will take, and Z the years
until a cryptographically relevant quantum computer. It is the standard reference
CISOs and agencies use. What is written above is that inequality with Y dropped
and Z replaced by the regulatory deadline — a simplification, not an invention.

We wrote this document before checking, and claimed the angle was unoccupied. It
was not. Correcting it in place rather than quietly is the least this project can
do, given what it says about tools that hide what they did not look at.

### The dates### The dates

To be handled with care, and re-verified before any public communication: they
have moved several times and will move again.

Checked against the sources on 2026-10-03. Three of the five were imprecise,
which is the point of writing "re-verify" in a table and then actually doing it.

| Reference | What it says, checked | Was it right? |
|---|---|---|
| FIPS 203 / 204 / 205 | ML-KEM, ML-DSA, SLH-DSA standardised, August 2024 | yes |
| NIST IR 8547 **ipd** | Table 2: RSA and ECDSA at 112 bits deprecated after 2030; RSA, ECDSA, EdDSA disallowed after 2035 at every level | the dates, yes — but it is an **initial public draft** and we cited it as settled guidance |
| CNSA 2.0 (NSA) | software and firmware signing and networking equipment 2030; browsers, cloud and operating systems 2033 | no: we printed a single 2030, which is only the earliest category |
| Recommendation (EU) 2024/1101 | 11 April 2024, coordinated national roadmaps due within two years, hybrid schemes | no: "first critical uses before 2030" is not in it |
| ANSSI | hybridation essential wherever PQC is deployed and required for French security visas; after 2030, buying without PQC held unreasonable | nearly: "required during the transition" overstated a recommendation |

The lesson is worth more than the corrections: every one of these errors made
the tool sound *more* certain than its sources. A document read in a room where
somebody disagrees survives on the opposite habit.

**A design decision follows from that uncertainty**: the tool does not predict
the arrival of a quantum computer. It uses the **regulatory deadline** as the
default expiry date (2035, configurable) and says so in the report. Predicting a
cryptographic break date would be exactly the kind of invented figure we hold
against everyone else.

---

## 2. What already exists, honestly

Checked rather than remembered, in September 2026. The field is not empty and it
moved fast.

| Existing | What it does | Where it stops |
|---|---|---|
| **Mosca's inequality** (2015) | the framework itself: `X + Y > Z` | a formula, not a tool: somebody still has to find X |
| Mosca calculators (several vendors) | ask for three numbers, return an exposure | no inventory: they never look at a codebase |
| CycloneDX 1.6+ (CBOM) | a standardised **format** for cryptographic inventory | not a tool, and it judges nothing |
| IBM `cbomkit`, Mondoo `xgrep` | scan code, produce a CBOM | no data lifetime at all: algorithm-level findings |
| A .NET CBOM generator | two axes — quantum vulnerability and classical weakness | "data-sensitivity hints" are categorical, not a duration |
| **CryptoDrishti** | scans a codebase, per-asset confidentiality lifetime, computes Mosca, self-contained HTML report | a Python prototype of the same age and maturity as this one |
| ECDAT | discovery platform, also on Mosca's theorem | enterprise-shaped |
| `testssl.sh`, `sslyze` | what a server actually **negotiates** | network only: nothing of the code or the backups |

**So the angle is taken.** At least one project does precisely what this one does,
in another language, at the same stage. Pretending otherwise would make every
other claim in this document suspect.

What is left, and it is narrower than what we first wrote:

1. **The refusals.** Inventory is not usage, test code is not production, a digest
   used as a cache key is not a control, and a report that buries three real
   findings under forty false ones has failed. Every one of those rules came from
   a false positive this tool actually printed, and each is measurable.
2. **Signatures are not harvestable.** Mosca's inequality is about
   confidentiality. Applying `X + Y − Z` to a signature scores it as if traffic
   could be captured and opened later, which is wrong. A tool that does not make
   that distinction over-reports every signing key it finds. **To verify against
   the tools above rather than assume.**
3. **The live probe.** Static analysis reads intentions. On the first real project
   the probe found a hybrid post-quantum key exchange that no file in the
   repository mentioned — and the backup encryption, the most sensitive operation
   there, was in no file either.
4. **Nothing leaves the machine.** No service, no database, no account, no
   dependency. Some of the tools above ship a local web console and a scan
   history; that is a different posture, not a worse one, but it is a different
   promise.
5. **Refusing to model Z.** Others model the arrival of a quantum computer as a
   probability distribution. We use the regulatory deadline and say we do not
   predict. Theirs is more sophisticated; ours is more honest about what nobody
   knows. That is a defensible choice, not a superiority.

And one thing this document should have said from the first line: PhpMetrics did
not invent code metrics either.

## 3. What static analysis can see## 3. What static analysis can see, and what it never will

The most important section of this study. A security tool that lets you believe
it saw everything is worse than no tool: it manufactures false assurance.

### Reliable (high confidence)

- Calls to a cryptographic API with the algorithm **as a literal**:
  `openssl_sign(..., OPENSSL_ALGO_SHA256)`, `openssl_encrypt($d, 'aes-256-cbc', …)`,
  `hash('sha1', …)`, `password_hash(…, PASSWORD_BCRYPT)`, the whole `sodium_*` family.
- Key generation with literal parameters: type and size in
  `openssl_pkey_new(['private_key_type' => …, 'private_key_bits' => …])`.
- **Key material present in the repository**: PEM files, certificates, SSH keys —
  the type and size are readable from the header or the ASN.1.
- The **literal** signature algorithm of a JWT (`RS256`, `ES256`, `HS256`, `EdDSA`).
- TLS configuration declared in the repository: Caddyfile, nginx, Apache.
- Cryptographic dependencies declared in `composer.lock` / `package-lock.json`.
- Shell and pipeline files: `openssl enc`, `gpg --cipher-algo`, `ssh-keygen -t`,
  `age`. Added after the first real scan, which missed the one thing that
  mattered — see §8.

### Uncertain (medium confidence — flag it, never decide it)

- Algorithm or size coming from a variable, a constant, a `.env`. The tool must
  write "undetermined" and name the file, not infer.
- Cryptography called through an in-house abstraction layer.
- Library versions: the presence of `phpseclib` does not say which algorithm is
  actually used.

### Out of reach for static analysis

- **What is actually negotiated at runtime.** This is why the tool ships a live
  **TLS probe**: an ordinary handshake, the same one a browser performs. It is
  the only way to know what really protects the traffic, and it regularly
  contradicts the repository in both directions.
- **The cryptography of managed services**: at-rest encryption of a managed
  database, object-storage SSE, TLS terminated by a CDN. None of it is in the
  repository. Only a human declaration brings them in.
- **Keys held in an HSM or by a provider.**
- **The lifetime of the data.** Undecidable from code, and that is a good thing:
  it is declared, reviewed, versioned, and it is the only artefact in the project
  that commits people rather than tooling.
- Cryptography inside binaries, third-party containers, FFI.

> **Product rule**: the report prints its own blind spots, in plain sight, inside
> the document — not in a footnote. An inventory that does not say what it failed
> to look at is not an inventory.

---

## 4. The risk model

The only place the tool holds an opinion. Three distinctions that most
post-quantum discourse conflates.

### 4.1 Confidentiality ≠ authenticity

- **Confidentiality** (encryption, key exchange: RSA-OAEP, ECDH, TLS) — subject
  to harvesting. Urgency depends on the lifetime of the data. *Data encrypted
  today may already be lost.*
- **Authenticity** (signatures: ECDSA, RSA-PSS, JWT) — **not** subject to
  harvesting. A signature scheme broken in 2035 does not retroactively forge a
  2026 signature in most uses. The urgency is about **long-lived trust anchors**:
  code signing, certificate authorities, firmware, timestamping.

Conflating the two means either panicking for nothing or missing the real
subject.

### 4.2 Symmetric ≠ asymmetric

AES-256 and ChaCha20 are not the problem. Grover halves the margin, AES-128
becomes uncomfortable, AES-256 stays solid. The tool has to say so, so that teams
do not replace what is already fine.

### 4.3 Classically broken ≠ quantum-threatened

MD5 and SHA-1 are a problem **today**, with no quantum computer involved. They
belong in a separate category with higher urgency — otherwise a fix that was due
in 2017 gets postponed to 2030.

### 4.4 Scoring

```
exposure_end =  current year + confidentiality lifetime(domain)
expiry       =  the algorithm's expiry year (default 2035, configurable)

confidentiality:  exposure_end > expiry              → COMPROMISED
authenticity:     long-lived trust anchor            → MIGRATE
                  otherwise                          → WATCH
broken hash:      always                             → BROKEN TODAY (classical)
strong symmetric:                                    → CLEAR
undetermined:                                        → TO DECLARE
```

`COMPROMISED` does not mean "fix this quickly". It means: **the data already
emitted is lost, and migration only protects what comes after.** It is an
unpleasant sentence, and it is the one that moves an organisation.

---

## 5. The report, which is the product

One HTML file, no external resource, openable from an email attachment. Three
commitments:

1. **A verdict sentence at the top.** Not a score out of 100: a score is
   contemplated, a sentence is forwarded.
2. **The timeline before the table.** It is the only visual that makes the
   subject land with someone who is not a cryptographer. A bar turns red only
   when a harvestable algorithm protects that domain past the expiry line —
   colouring on duration alone made the chart contradict its own headline.
3. **The blind spots inside the document**, at the same size as the rest.

The report also explains, in two short paragraphs, what post-quantum cryptography
is and what the tool does — because the person who receives the file is usually
not the person who ran it.

Available in French, English and Spanish.

---

## 6. Scope of the first cut

**In**

- One language: PHP. Familiar ground, and where the PhpMetrics audience is.
- Static detection: OpenSSL/Sodium/hash calls, literal JWT algorithms,
  `composer.lock`, shell and pipeline files.
- Key material and certificates found in the tree.
- Declared TLS configuration (Caddy, nginx).
- **Live TLS probe** — pulled forward from "later" after the first real scan.
- A declaration file for data domains and their lifetimes.
- Self-contained HTML report plus JSON output, in three languages.
- **CBOM in and out** (CycloneDX 1.6). Out, so the inventory is consumable by
  tooling that already exists; in, so an inventory produced by a scanner for a
  language we do not parse can still be crossed with a declaration and judged
  here. The second direction is the one that matters: it says out loud that the
  detectors are not the product.
- **Zero dependencies.** On a tool that reads keys, each dependency is one more
  supply chain to defend. It is also a selling point.

**Out, explicitly**

- Other languages (JS, Go, Python) — after the thesis is validated.
- Automatic fixing. A tool that rewrites cryptography without understanding the
  context is an incident generator.
- SaaS, accounts, telemetry. Ever.

---

## 7. What can kill the project

1. **"We'll look at it in 2030."** The main risk, and it is commercial rather
   than technical. Only the "your 2026 data is already lost" framing answers it.
2. **Noise.** An `md5()` used as a cache key is not a vulnerability. If the first
   report on a real project drowns three real alerts in forty false ones, the
   tool is dead. **This is the prototype's stopping criterion.**
3. **The declaration nobody fills in.** Without lifetimes, the tool falls back to
   the level of its competitors. Hence sensible defaults per domain type, and a
   report that stays useful when the declaration is half-written.
4. **A vendor shipping the same angle.** The answer: speed, absence of friction,
   and the fact that every scan can be published as a field report.

---

## 8. What the first real scan taught us

Show me the REX, ~1,900 files. Seventeen findings, **no red alert** — and three
lessons that changed the tool the same evening.

1. **Backup encryption is not in the repository.** It lives in a script on the
   server. The most sensitive cryptographic operation in the project — the one
   protecting ten years of accounting records — is invisible to static analysis.
   This is the "out of reach" section demonstrated by example, and it is why the
   declaration file is the backbone rather than an accessory.
2. **Two false positives out of fifteen findings.** A `md5()` in a test, and a
   TOTP dependency whose SHA-1 is mandated by the specification, both announced
   as breaks. Exactly the stopping criterion above. Two rules followed: a
   declared dependency is never a red alert — presence is not usage — and test
   code does not fire.
3. **The probe found what no file could say.** The site already negotiates
   `X25519MLKEM768`, a hybrid post-quantum key exchange, courtesy of its CDN.
   Nothing in the repository mentions it. A report based on the code alone would
   have understated the project's actual posture — which is the mirror image of
   the failure mode everyone expects.

### A second corpus, and what it did not show

`pitch`, another PHP project on the same machine: 155 files read, one finding.
Eighteen source files — the two thousand others were Symfony's cache under
`var/`, correctly skipped. Nothing to learn about noise from a project that
small, which is itself worth recording: the noise criterion needs a codebase
with history, not a second young one.

### The probe bug a stranger's server would have hidden

Testing the "classical key exchange" path meant finding a server that still uses
one. Rather than point the tool at somebody else's host, a local TLS server
pinned to X25519 — and it immediately exposed a real defect: OpenSSL 3 labels the
field `Peer Temp Key`, while the parser only knew `Server Temp Key` and the
TLS 1.3 `Negotiated group` line. On any server without that last line, the probe
was silently dropping its most important field. Silently, because a missing group
is reported as "assumed classical" rather than as a parsing failure.

It is now a regression test: the suite starts a TLS server, probes it, and checks
the group comes back.

## 9. What happens next

1. Write the declaration for a real project, with someone whose job is the
   business rather than the code, and measure it. Never done yet, and it decides
   whether the thesis survives contact with a second team.

   **What to measure**, decided before the session so the result cannot be
   rationalised afterwards: the real time to fill it; how many domains the
   person answers with confidence against how many they stall on; and where they
   disagree with the starter file's defaults — the disagreements are the most
   instructive, because they say our defaults are wrong.

   **What would falsify the thesis**: the person cannot answer "how long must
   this stay secret" for most of their domains. Then the problem is not the tool
   and no further detector will compensate. The question would have to be asked
   differently — starting from legal retention, which people know, rather than
   from confidentiality lifetime, which they have never had to put into words.
2. Extend the probe beyond HTTPS: SMTP, IMAP, database connections.
3. A second language, once the thesis holds.

Any conclusion drawn before step 1 is an opinion.
