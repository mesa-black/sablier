<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Which build produced a document.
 *
 * A report that prints the command it was produced by, the digest of its
 * findings and a signature over them, and then names the tool without a
 * version, is reproducible in theory only. This constant is bumped with the
 * tag, and it is printed wherever somebody might have to repeat the run three
 * years later.
 *
 * It said 0.5.0 for three releases, so every audit document produced in between
 * named a build that had not produced it — including one published on a public
 * website. A sentence in a docblock is not a mechanism: the test suite now
 * refuses a tagged commit whose constant disagrees with its tag, and the release
 * job refuses to publish one.
 */
final class Version
{
    public const string NUMBER = '0.11.0';

    public static function label(): string
    {
        return 'Sablier '.self::NUMBER;
    }
}
