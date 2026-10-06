# How Sablier works

One page, three diagrams. The long version is the [README](../README.md); this is
the shape of the thing.

## The pipeline

Two sources of fact, one input no scanner can find on its own, and one risk model
that turns the three into verdicts.

```mermaid
flowchart TB
    subgraph facts["What is true about the system"]
        code["Source code<br/>call sites, dependencies, configuration"]
        wire["Declared hosts<br/>what a TLS handshake actually returns"]
        other["Somebody else's CBOM<br/>CycloneDX 1.6, judged not detected"]
    end

    subgraph human["What only people know"]
        decl["sablier.json<br/>domains · confidentiality lifetimes<br/>regime · trust anchors · who declared it"]
    end

    inv["Inventory<br/>one finding per call site, with its evidence"]
    model["Risk model<br/>Mosca, read per domain"]
    verdicts["Verdicts<br/>compromised · urgent · migrate · declare<br/>watch · clear · noise · accepted"]

    code --> inv
    wire --> inv
    other --> inv
    inv --> model
    decl --> model
    model --> verdicts

    verdicts --> report["report.html<br/>for the team"]
    verdicts --> audit["audit.html<br/>numbered facts, method, limits"]
    verdicts --> cbom["cbom.json<br/>CycloneDX 1.6"]
    verdicts --> json["findings.json<br/>for a pipeline, with an exit code"]
    verdicts --> ics["calendar.ics<br/>the crossing dates"]
```

The first group is measured. The second is declared, and it is the half every
other tool leaves out: *how long does this data have to stay confidential?*
Without it an inventory is a list of algorithms, and a list of algorithms has no
deadline in it.

## The one question, decided

The arithmetic is Mosca's inequality, simplified to the only form that fits on a
line: **a secret written in year `E` and required to stay secret for `L` years is
readable if `E + L` lands past the year the algorithm stops holding.** The
crossing year — when a system starts producing data it cannot protect — is
`expiry − lifetime + 1`.

```mermaid
flowchart TB
    start(["A finding"]) --> known{"Algorithm<br/>recognised?"}
    known -->|no| declare["DECLARE<br/>we will not guess"]
    known -->|yes| noise{"Plausibly<br/>not cryptography?"}
    noise -->|"yes<br/>md5 as a cache key"| noisev["NOISE<br/>visible, not raised"]
    noise -->|no| broken{"Broken<br/>already?"}

    broken -->|"yes, at a call site"| urgent["URGENT<br/>a problem from 2004, not 2035"]
    broken -->|"yes, in a lock file"| watch1["WATCH<br/>presence is not usage"]
    broken -->|no| hybrid{"Quantum-vulnerable,<br/>but declared hybrid?"}

    hybrid -->|yes| clear1["CLEAR<br/>that is the transition, not a defect"]
    hybrid -->|no| quantum{"Quantum<br/>vulnerable?"}
    quantum -->|no| clear2["CLEAR<br/>symmetric is not the subject"]
    quantum -->|yes| purpose{"What is it for?"}

    purpose -->|"authenticity<br/>a signature cannot be harvested"| anchor{"Trust anchor?"}
    anchor -->|yes| migrate["MIGRATE<br/>it validates what comes after it"]
    anchor -->|no| watch2["WATCH<br/>migrate before the deprecation year"]

    purpose -->|confidentiality| maths["last emission + lifetime<br/>vs the regime's expiry"]
    maths -->|past it| compromised["COMPROMISED<br/>n years readable, migration does not reach it"]
    maths -->|inside it| watch3["WATCH<br/>the data expires before the algorithm"]
```

Two rules keep this honest. An **accepted** finding changes section, never
disappears: the original verdict stays attached, the reason is printed, and the
acceptance expires on a date the reader can see. And a declared dependency with a
published high-severity advisory becomes `URGENT` — the only place where
"presence is not usage" gives way, because an advisory says somebody already found
a way in while the rest of this document argues about 2035.

Under the `eu` regime the expiry is not one date for the project: it is read off
each domain. A confidentiality lifetime of ten years or more, or a trust anchor,
is high risk and due 2030; everything else is medium and due 2035.

## The four artefacts, and what each one proves

A report that cannot be checked is an opinion. Four files, each answering a
different question, and none of them answering a question that belongs to
another.

```mermaid
flowchart LR
    subgraph signed["Signed over the findings, not the file"]
        sig["report.html.sig<br/>Ed25519 + ML-DSA-65"]
        prev["previous digest<br/>the chain, with no flag to remember"]
    end

    tsr["report.html.tsr<br/>RFC 3161 token"]
    endorse["sablier.json.sig<br/>endorsement"]

    digest["Digest of the findings<br/>same inventory, same value,<br/>in any language"]

    digest --> sig
    sig --- prev
    digest --> tsr
    decisions["The decisions<br/>regime, lifetimes, anchors, authors"] --> endorse

    sig --> q1["who signed, and what"]
    tsr --> q2["when — attested by a third party<br/>with no stake in the conclusions"]
    endorse --> q3["who committed to the durations<br/>the verdicts rest on"]
```

- **The signature covers a digest of the findings, never the rendered page.** Two
  runs of one inventory differ byte for byte and say the same thing; two
  renderings in two languages give the same digest. Which also means a published
  page altered by hand still verifies — so the document prints that limit, and the
  way to close it is to replay the analysis on the same source and compare.
- **The chain is automatic.** A second run over the same output path records the
  digest it is replacing inside what it signs. A folder of reports is an audit
  trail; a missing link shows.
- **The date comes from somebody else.** `signed_at` is covered by the signature
  and still worthless as evidence: it is read off the clock that signed. An
  RFC 3161 token answers *when*, and `openssl ts -verify -digest <the digest
  printed in the report>` checks it with no reference to this tool.
- **The input is signed too.** Every verdict rests on durations that were a string
  somebody typed. The endorsement signs the decisions — not the bytes, so
  reformatting the file does not break it.

Each of those limits is printed in the document itself. That is the part of this
design that took the longest, and the only part that matters: a seal a reader
cannot use, or can over-read, is worse than no seal.
