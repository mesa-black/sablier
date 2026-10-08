# How it is put together, and what it refuses

*← back to the [README](../README.md)*

## How it is put together

Two extension points, because the scoping study names two axes that will
actually grow — and nothing else gets an interface.

```
DetectorInterface   one way of finding cryptography in one kind of file
  PhpDetector · ShellDetector · KeyMaterialDetector · AssetDetector
  EnvDetector · ServerConfigDetector · SshConfigDetector · TerraformDetector
  FrameworkConfigDetector · FrameworkYamlDetector · LaravelDetector
  SymfonyVaultDetector · DependencyDetector

ReporterInterface   one way of rendering an analysis
  HtmlReporter · AuditReporter · CbomReporter · JsonReporter
```

`Scanner` walks a tree and knows nothing about cryptography; the detector list is
composed in `bin/sablier` and passed in. Adding a language means writing a
detector and registering it, never editing the scanner. `Analysis` carries
everything a reporter needs, so adding a fact to the report does not change every
renderer's signature.

Everything else stays concrete. `Catalogue`, `Assessor`, `Declaration` and `Lang`
have one implementation each and no second one in sight: an interface with a
single implementation and no prospect of another is a cost with no buyer.

## What the tool refuses to do

- **Guess.** An algorithm coming from a variable is reported as undetermined,
  with its location. A wrong inventory is worse than an incomplete one, because
  nobody checks an inventory twice.
- **Predict.** The expiry date used is the regulatory deadline (2035 by default,
  configurable), not a prophecy about when a quantum computer arrives.
- **Shout.** Strong symmetric cryptography is reported as clear, a signature is
  not treated as a leak, an `md5()` used as a cache key is filed as off-topic,
  and a declared dependency is never a red alert — it is a use to confirm.
- **Fix by itself.** Rewriting cryptography without understanding the context is
  an incident generator.
- **Leave.** No account, no upload, no telemetry, no dependency.

## What it does not see

The report prints its own blind spots, at the same size as everything else: the
cryptography of managed services, live TLS negotiation for undeclared hosts, keys
held in an HSM, and data lifetimes nobody declared.

An inventory that does not say what it failed to look at is not an inventory.
