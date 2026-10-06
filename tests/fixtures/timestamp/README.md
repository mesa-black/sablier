# A real timestamp token, kept so the test needs no network

`other-digest.tsr.base64` is an RFC 3161 token obtained from a public authority
on 06/10/2026. It attests the digest of the string `sablier test fixture`, which
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
