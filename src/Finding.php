<?php

declare(strict_types=1);

namespace Sablier;

final class Finding
{
    public const string CONFIDENCE_HIGH = 'haute';
    public const string CONFIDENCE_MEDIUM = 'moyenne';

    public string $domain = 'non déclaré';
    public bool $domainDeclared = false;
    public int $lifetime = 0;
    public bool $trustAnchor = false;
    public string $verdict = '';
    public string $because = '';

    public function __construct(
        public readonly string $algorithm,
        public readonly string $purpose,
        public readonly string $file,
        public readonly int $line,
        public readonly string $evidence,
        public readonly string $confidence = self::CONFIDENCE_HIGH,
        /** Set when the call looks like a non-cryptographic use (cache key, ETag…). */
        public readonly bool $likelyNonCrypto = false,
        public readonly string $detail = '',
        /** A declared dependency, not an observed call: presence is not usage. */
        public readonly bool $inventory = false,
    ) {
    }
}
