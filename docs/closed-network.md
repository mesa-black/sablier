# On a closed network

*← back to the [README](../README.md)*

## On a network that has none

```bash
sablier scan /path/to/project --airgap --out=report.html --pdf=report.pdf
```

`--airgap` refuses rather than disables. `--no-probe` is a convenience — it
skips a step you could have run; on a closed site that is the wrong shape,
because a flag you can forget is a flag you will forget. So `sablier probe` and
`sablier advisories` stop with a message naming what to do instead, every
container is refused since a container is pulled, and a declared probe host is
skipped and **written into the blind spots** rather than silently dropped. A
site sets it once for everybody with `SABLIER_AIRGAP=1`.

The PDF then has no browser to borrow and no container to pull one from, so it
is typeset here instead: A4, the three fonts every reader already has, and a
page number on every page — which is the one thing the browser export cannot do,
because Chrome ignores the CSS that would carry one. Plainer than the printed
HTML, and it exists, which is the whole argument: a report that cannot be
printed cannot be signed or filed.

Nothing in this tool reaches the network unless you name a host. Sockets exist
in exactly four files — `Probe.php`, `SshProbe.php` and the two transports —
all of them behind `sablier probe` and the probe step of a scan, which
`--no-probe` removes. `sablier advisories` is the one command that goes out,
and it goes out for a vulnerability database rather than with your inventory.

That claim is pinned by a test rather than asserted: the list of files allowed
to open a socket is checked on every run, and the build fails the day a
detector grows one. Where the kernel allows it, the suite also runs a full scan
with the network stack removed (`unshare -rn`) and compares the result.

It matters because the output is the sensitive part. An inventory of where the
cryptography lives in a system is as sensitive as the system, so on a closed
network the question is not whether a tool promises to send nothing, but
whether it *can*. There is no telemetry, no update check, no dependency to
fetch: four lines of autoloader, PHP 8.4, and a repository somebody can read in
an afternoon before carrying it in.
