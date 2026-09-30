<?php

declare(strict_types=1);

namespace Sablier;

final class Finding
{
    public const string CONFIDENCE_HIGH = 'haute';
    public const string CONFIDENCE_MEDIUM = 'moyenne';

    public string $domain = '';
    public bool $domainDeclared = false;
    public int $lifetime = 0;
    public bool $trustAnchor = false;
    public string $verdict = '';
    public string $because = '';

    /** Set when an acceptance applies: what the verdict would have been. */
    public string $originalVerdict = '';
    public string $acceptedReason = '';
    public string $acceptedUntil = '';
    public bool $acceptanceExpired = false;

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

    /**
     * A stable handle for this finding, so a decision about it can be written
     * down and found again on the next run.
     *
     * Deliberately not built on the line number, which moves on the first
     * commit. It is built on the evidence instead — which means an acceptance
     * lapses when the line it was about materially changes. That is the wanted
     * behaviour: the code changed, so the decision deserves a second look.
     */
    public function fingerprint(): string
    {
        $evidence = strtolower((string) preg_replace('/\s+/', ' ', trim($this->evidence)));

        return substr(hash('sha256', $this->algorithm.'|'.$this->purpose.'|'.$this->file.'|'.$evidence), 0, 8);
    }
}
