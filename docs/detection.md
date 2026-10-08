# What it detects, and how sure it is

*← back to the [README](../README.md)*

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
