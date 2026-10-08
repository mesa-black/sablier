# Published vulnerabilities

*← back to the [README](../README.md)*

## A hole somebody already found

The rest of this report argues about 2035. An advisory says somebody found a
way in before the report was printed, which outranks it by a decade.

```bash
sablier advisories .                       # collect, once, on purpose
sablier scan . --advisories=.sablier/advisories.json
```

The first command is the only one in this tool that reaches the network, and it
reaches it for a database rather than with your inventory: the scanner runs in a
pinned container, reads your lock files from a read-only mount, and writes a file
you can read and version. A scan never does any of that — no package name of
yours leaves the machine while one runs.

A declared library with a published high or critical vulnerability stops being
plain inventory and becomes **BROKEN TODAY**, in the same category as MD5 and
SHA-1: a defect that owes nothing to quantum computing and comes before any
migration. The advisory numbers are printed with it, linked to NIST, GitHub or
OSV depending on who issued them.

Three lines hold it in place:

- **only the libraries this tool already inventories are judged.** A project has
  dozens of vulnerable dependencies and a report that lists them all buries the
  cryptography it was asked about. The others are counted in the blind spots, so
  the reader knows they were seen and left alone;
- **high and critical raise a verdict; medium and low are attached, not
  promoted.** The same threshold `make cve` applies to our own containers;
- **without the file, the report says the question was not asked** rather than
  implying the answer was no. That sentence is in the blind spots of every scan
  run without one.

## Citing a defect, and not citing a deadline

A finding that is broken today carries the published defect it rests on —
SHA-1 its collision CVE, MD5 its own, RC4 and 3DES theirs, TLS 1.0 and 1.1 the
two attacks that retired them — printed next to the verdict, linked to the
NIST entry a reader can go and check without taking our word for anything.

RSA and the elliptic curves carry none, and that is the point. A CVE is a
dated fact somebody else published; the post-quantum expiry is a regulatory
horizon, cited as such in the audit report's normative references. Filing the
second under the first would turn a deadline into an accusation, and it is
the kind of slippage this tool exists to refuse.

The numbers travel with the inventory: `references` in the JSON output, and
`externalReferences` of type `advisories` in the CBOM, where every consumer
already knows how to read them.
