<?php

declare(strict_types=1);

namespace Sablier\Ots;

/**
 * A proof that does not parse, or an operation that cannot be applied.
 *
 * One exception type for the whole format, caught at the edge and turned into
 * a sentence: a malformed proof is somebody's bad day, not a stack trace.
 */
final class FormatError extends \RuntimeException
{
}
