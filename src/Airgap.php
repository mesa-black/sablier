<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The switch that refuses, rather than disables.
 *
 * `--no-probe` is a convenience: it skips a step somebody could have run. On a
 * closed site that is the wrong shape — a flag you can forget is a flag you
 * will forget, and the mistake is not a slow build, it is a tool reaching for
 * a network that is not supposed to exist.
 *
 * So `--airgap` makes the reaching commands fail loudly instead of quietly
 * doing less: the probe, the advisory database, and every container, since a
 * container is pulled. What stays allowed is everything that only reads the
 * files in front of it, including an advisory file produced somewhere else and
 * carried in.
 *
 * It can also be set once for a whole session with `SABLIER_AIRGAP=1`, which is
 * how a site sets it for everybody rather than hoping each operator remembers.
 */
final class Airgap
{
    private static ?bool $on = null;

    public static function on(): bool
    {
        if (self::$on === null) {
            $env = trim((string) getenv('SABLIER_AIRGAP'));
            self::$on = $env !== '' && $env !== '0' && strtolower($env) !== 'false';
        }

        return self::$on;
    }

    public static function enable(): void
    {
        self::$on = true;
    }

    /** For the tests, which need both answers in one process. */
    public static function reset(): void
    {
        self::$on = null;
    }

    /**
     * Stop, saying which command was refused and what to do instead.
     *
     * The message names the alternative every time: an audit that cannot be
     * finished is worth less than one finished with a stated gap, and the blind
     * spots section of the report exists precisely to carry that gap.
     */
    public static function refuse(string $what): never
    {
        fwrite(\STDERR, '✗ '.Lang::t('airgap.refused', $what)."\n");
        fwrite(\STDERR, '  '.Lang::t('airgap.instead')."\n");
        exit(1);
    }
}
