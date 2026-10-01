<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Reading values this tool did not produce.
 *
 * A declaration, a CBOM, a parsed certificate, a reference inventory: every
 * one of them arrives as decoded JSON or as a library's array, which is to say
 * as `mixed`. Casting that straight to a string works right up to the file
 * that puts an object where a string belonged, and then the tool reports a
 * finding about data it misread.
 *
 * So the coercions live here, in one place, and they share one rule: a value
 * of the wrong shape is replaced by the default, never guessed at and never
 * fatal. A malformed input file is somebody's bad day, not a stack trace.
 */
final class Value
{
    public static function string(mixed $value, string $default = ''): string
    {
        return \is_string($value) ? $value : (\is_int($value) || \is_float($value) ? (string) $value : $default);
    }

    public static function int(mixed $value, int $default = 0): int
    {
        if (\is_int($value)) {
            return $value;
        }

        return \is_string($value) && preg_match('/^-?\d+$/', $value) === 1 ? (int) $value : $default;
    }

    public static function bool(mixed $value, bool $default = false): bool
    {
        return \is_bool($value) ? $value : $default;
    }

    /** @return array<array-key, mixed> */
    public static function map(mixed $value): array
    {
        return \is_array($value) ? $value : [];
    }

    /**
     * Anything in the array that is not a string is dropped, not stringified.
     *
     * @return list<string>
     */
    public static function strings(mixed $value): array
    {
        $out = [];
        foreach (self::map($value) as $item) {
            if (\is_string($item)) {
                $out[] = $item;
            }
        }

        return $out;
    }
}
