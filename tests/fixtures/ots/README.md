# Real OpenTimestamps proofs, kept so the tests need no network

Three proofs from the official client's own examples, and the one block header
the complete one needs. Fetched on 17/11/2026 from
`https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/examples/`
(repository head `f3a9e92e4dcb89ed93396d71ec808b3290a438c4`), which is the
reference this tool's format code was checked against.

Stored as base64, like the RFC 3161 tokens next door, so every file in this
repository stays readable in a diff. Decode one by hand with:

```sh
base64 -d hello-world.txt.ots.base64 > hello-world.txt.ots
```

## `hello-world.txt.ots.base64`

The proof of the file `Hello World!\n` (SHA-256
`03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340`),
complete: its path ends in a Bitcoin attestation at block 358391, mined on
28/05/2015. SHA-256 of the decoded file:
`be61ecb940db2e4a6f89fbed59c8d4f7f74fa756cbc1fad1ad7aabcb2bf59c30`.

It is what proves the verification offline: the path is recomputed, its end is
compared with the merkle root of the header below, and the header's proof of
work is checked — all of it with no network, which is the case `--airgap` and
`--block-header` exist for.

## `block-358391.hex`

The 80-byte header of block 358391, in hex, as served on 17/11/2026 by both
`https://blockstream.info/api/block/<hash>/header` and
`https://mempool.space/api/block/<hash>/header` — identical bytes from the two.
Block hash `000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319`.

Nobody has to trust that it came from there: the test checks its double SHA-256
against the target in its own `nBits`, and that target against the floor in
`src/Ots/BlockHeader.php`. A header that was typed wrong fails one of the two.

## `two-calendars.txt.ots.base64`

A pending proof: two branches, one per calendar (alice and bob), each ending in
a pending attestation. Nothing in it can be checked against a block yet, and
the tool has to say so rather than say nothing. SHA-256 of the decoded file:
`1f0fe002dc50f6bc96bcab1fffa9d22f8fa71ac1f99b91bd5ece04d06d8b4d64`.

## `known-and-unknown-notary.txt.ots.base64`

A pending attestation beside one from a notary nobody knows (tag
`0102030405060708`). The unknown one has to survive a parse and a rewrite byte
for byte, since a future notary is exactly what this tool will not recognise.
SHA-256 of the decoded file:
`f49b05b941c4d2512b0f0569b57c2592d501ef6036f7965d667eae07b80721aa`.
