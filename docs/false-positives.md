# What this tool gets wrong, counted

A tool that tells somebody their cryptography is broken owes them a number: how
often is it wrong? This page is that number, the method behind it, and the raw
judgement, so the figure can be argued with rather than believed.

Measured on **2026-10-03**, with Sablier 0.3.0 plus the fixes this measurement
produced.

## What was measured

**31 public PHP repositories**, shallow-cloned and scanned with
`sablier scan <repo> --airgap`. No declaration, so every lifetime is the
default — which is the worst case for the tool, and the state any first scan is
in.

The question asked of each finding is not "is the algorithm really there" — it
nearly always is — but **"is the report right to call this a problem"**. Only
the red findings are counted, the ones a reader is told to act on today. A tool
whose reds are wrong teaches people to stop reading reds.

A finding is a **false positive** when the code is not a security control (an
identifier, a cache key, a filename, a lock name, test code) or when the
algorithm named is not the algorithm in the code.

## The result

| | findings | red | false positives | rate |
|---|---|---|---|---|
| **before** (20 repositories) | 497 | 89 | 82 | **92 %** |
| **after** (the same 20) | 467 | 8 | 1 | 12 % |
| **after** (31 repositories, 11 never used for tuning) | 959 | 24 | 6 | **25 %** |

The first line is the honest starting point: **nine out of ten red findings
were wrong**. The third is where it stands now. The middle line is there to
show what tuning on one corpus buys and why it cannot be the published number —
measured on six repositories that had not been touched, the rate was 63 % again
before the rules were made general rather than particular.

Recall did not move: the seven real findings in the first corpus are all still
reported, and the larger set surfaced eleven more.

## What was wrong, and what fixed it

| cause | count | fix |
|---|---|---|
| `mcrypt_*` reported as DES | 28 | the cipher is only named when the code names it; otherwise the finding says the API is dead and the algorithm unknown |
| object hash codes, cache keys, filenames, lock and mutex names | ~40 | the identity heuristic reads the enclosing function name, not only the line |
| digests of `serialize()` / `json_encode()` | — | you cannot keep confidential something you serialised in order to hash it |
| HMAC-MD5 and HMAC-SHA-1 called broken | 6 | an HMAC is not its digest: collision attacks do not reach the construction |
| a call written inside a comment | 1 | a mention is not a use |
| test code presented as production | 3 | `*Test.php` counts as test code, not only `tests/` |

Two rescue words had to be narrowed after they rescued the wrong things:
`key` matched every `$key = md5(...)` cache lookup, and `token` matched a
profiling marker in a logger. Both now require a qualifier — `public_key`,
`access_token` — and the fixture in `tests/fixtures/digests` pins the
distinction so it cannot rot.

## What is still wrong, and why it is left

Six false positives remain in the 31 repositories, and they fall in two groups.

Three are **algorithm capability tables** in phpseclib: an SSH client lists
`hmac-sha1` because the protocol requires it. The right verdict is "confirm",
not "fix today", and the tool already has that rule for lock files — it does not
yet recognise a table of supported algorithms as the same kind of statement.

Three are identifiers whose line carries no hint at all: `md5($id)`,
`md5(time() . $buffer)`, `md5($_SERVER['REMOTE_ADDR'])`. Catching those needs
to know what the value is used for, which a regular expression cannot see.
Suppressing them by shape would also suppress real findings, and the trade is
not worth it: a reader can dismiss three findings far more cheaply than they can
recover from trusting a tool that hid one.

## The judgements

| repository | where | call | why |
|---|---|---|---|
| CodeIgniter | `system/core/Security.php:616` | real | CSRF token built on `md5(uniqid())` |
| CodeIgniter | `system/core/Security.php:1082` | real | the same, for the XSS hash |
| CodeIgniter | `system/helpers/string_helper.php:205` | real | `random_string()` returns `md5(uniqid())` |
| CodeIgniter | `system/helpers/string_helper.php:207` | real | the same with SHA-1 |
| CodeIgniter | `application/config/database.php:86` | real | `'encrypt' => FALSE` in a shipped config |
| CodeIgniter | `.../Session_files_driver.php:152` | **false** | a hash of the client address, in a session filename |
| Composer | `src/Composer/Util/TlsHelper.php:153` | real | SHA-1 certificate fingerprint |
| Laravel | `.../Notifications/VerifyEmail.php:88` | real | SHA-1 of an e-mail address in a verification URL |
| Laravel | `.../Auth/EmailVerificationRequest.php:22` | real | the same, compared with `hash_equals` |
| Flysystem | `src/PhpseclibV2/SftpConnectionProvider.php:167` | real | MD5 fingerprint of an SSH host key |
| mPDF | `src/Pdf/Protection.php:343` | real | MD5 in the PDF encryption key derivation |
| mPDF | `src/Pdf/Protection/UniqidGenerator.php:30` | **false** | an identifier |
| mPDF | `src/Writer/MetadataWriter.php:834` | **false** | a document identifier |
| phpseclib | `phpseclib/Net/SSH2.php:1524, 1909, 1911` | **false** ×3 | tables of algorithms the protocol requires it to support |
| phpseclib | `.../Traits/KeyDerivation.php:79` | real | SHA-1 integrity check value in a key wrap |
| phpseclib | `.../CMS/EncryptedData.php:695` | real | the same, on the writing side |
| phpseclib | `.../Keys/PKCS1.php:94` | real | MD5 key derivation |
| phpseclib | `.../Keys/PuTTY.php:84, 242, 303, 304, 335` | real ×5 | SHA-1 in the PuTTY key file MAC and KDF |

## Reproducing it

```bash
for r in <the list below>; do
  git clone --depth 1 "https://github.com/$r.git" "/tmp/fp/$(basename $r)"
  ./bin/sablier scan "/tmp/fp/$(basename $r)" --json="/tmp/fp/$(basename $r).json" --airgap
done
```

Tuning set: PHPMailer, guzzle, monolog, Slim, composer, uuid, php-jwt, jwt,
halite, php-encryption, flysystem, oauth2-server, otphp, httpful, phpdotenv,
PhpSpreadsheet, http-client, dbal, phpunit, CodeIgniter.

First validation: laravel/framework, cakephp, phpseclib, wp-cli, yii2,
sodium_compat. Second validation: intervention/image, php-amqplib, mpdf,
endroid/qr-code, symfony/console.

## The caveat that matters

This is PHP, and these are libraries. A library is not an application: it holds
more cryptography and less configuration than the projects this tool is aimed
at. The number should be re-measured on applications, and on the other blind
spot that no amount of tuning will close — the cryptography of managed services,
which appears in no file of any repository.
