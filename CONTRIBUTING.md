# Contributing

The project has a small number of rules, and they are the reason it is worth
using. Everything else is negotiable.

## The rules

**Never guess.** An algorithm that cannot be read from the source is reported as
undetermined, with its location, and the reader confirms it by hand. A wrong
inventory is worse than an incomplete one, because nobody checks an inventory
twice.

**Never shout.** Strong symmetric cryptography is clear. A signature is not a
leak. A digest used as a cache key is off-topic. A declared dependency is a use
to confirm, not a breach. If a change makes the tool louder, it needs to make it
more right by the same amount.

**Say what you did not look at.** Every detector can add to the report's blind
spots. A detector that knows it only read a declaration, and not the running
system, says so.

**Nothing leaves the machine.** No account, no telemetry, no dependency. The
report loads no external resource. The live probe performs a handshake, and the
PDF export borrows a browser the machine already has — both are visible, both
are optional, and both say plainly when they cannot run.

## Adding a detector

One detector reads one kind of file. Implement `Sablier\Detector\Detector` and
register it in `bin/sablier`; the scanner walks the tree and knows nothing about
cryptography.

If your detector recognises things by pattern, extend `PatternDetector` and
provide a rule table. Sentences belong in `translations/`, never in the detector:
the three languages are checked against each other, and a key missing from one
is a visible gap rather than a silent empty string.

## Adding a transport

A transport brings a connection to a TLS state. Implement
`Sablier\Transport\Transport`; the interesting part is the upgrade, because that
is where a session silently stays in cleartext.

Test it against a server you control. `tests/starttls-server.php` is twenty
lines and exists for that: pointing the tool at somebody's real mail host to
test your own code is neither necessary nor polite. That local server is also
how the first real probe bug was found.

## Running the tests

```bash
make test
```

They need `php` and `openssl` and nothing else. The suite asserts the risk model
still discriminates — harvesting from signatures, symmetric from asymmetric,
broken-today from the quantum deadline — and that every transport reaches TLS.
If a change moves one of those verdicts, that is the conversation to have in the
pull request.

## Commits

Written in English, in the imperative, saying what changed and why. The why is
the part that matters: this codebase is full of decisions that look arbitrary
until you know what they are avoiding.
