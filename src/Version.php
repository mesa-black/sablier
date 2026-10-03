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
 */
final class Version
{
    public const string NUMBER = '0.4.0';

    public static function label(): string
    {
        return 'Sablier '.self::NUMBER;
    }
}
