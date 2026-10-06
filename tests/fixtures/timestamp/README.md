# Real timestamp tokens, kept so the tests need no network

Two tokens, each chosen for what it makes impossible to get wrong.

## `other-digest.tsr.base64`

An RFC 3161 token obtained from a public authority on 06/10/2026. It attests the digest of the string `sablier test fixture`, which
is **not** the digest of any report this suite produces — that is the point: the
test files it beside a signature it has nothing to do with, and the tool has to
say so rather than print a date that looks like a guarantee.

Stored as base64 and decoded by the test, so every file in this repository stays
readable in a diff. Decode it by hand with:

```sh
php -r 'echo base64_decode(file_get_contents("other-digest.tsr.base64"));' > t.tsr
openssl ts -reply -in t.tsr -text
```

The responder certificate inside it will expire. When it does, the chain check
answers `untrusted` instead of `valid` — which is why the test asserts on the
imprint mismatch, a hash comparison that needs no certificate at all and holds
for as long as SHA-256 does.

## `ecdsa-responder.tsr.base64`

A token from an authority whose **responder is ECDSA-384 and whose root is
RSA-4096**. The report prints the scheme the token's own signature rests on — the
whole argument being that this scheme expires too — so reading it off the wrong
certificate in the chain misnames it. Everywhere else the two are the same
algorithm and the mistake is invisible; here it is a different answer.

That is not hypothetical: picking "the first certificate printed" worked for
three authorities in a row, and the regex that replaced it with a real leaf
search had a dotall flag that collapsed the parse to one certificate. Both were
measured against this token.
