<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The container runtime, when there is one.
 *
 * Two features borrow a tool rather than ship it — the PDF when no browser is
 * installed, and the advisory database — and both need the same answer to the
 * same question. Asking it in one place also keeps the promise checkable:
 * every container this tool starts is started from here.
 */
final class Docker
{
    public static function binary(): ?string
    {
        // A container is pulled over the network, so on a closed site it is not
        // a fallback, it is a failure. Refusing here covers every borrowed tool
        // at once rather than at each call site.
        if (Airgap::on()) {
            return null;
        }

        $path = trim((string) @shell_exec('command -v docker 2>/dev/null'));

        return $path !== '' ? $path : null;
    }

    /** The uid the kernel sees, so a file written in a container belongs to a person. */
    public static function uid(): int
    {
        return \function_exists('posix_getuid') ? posix_getuid() : (int) getmyuid();
    }

    public static function gid(): int
    {
        return \function_exists('posix_getgid') ? posix_getgid() : (int) getmygid();
    }
}
