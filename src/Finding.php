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

    /** The domain pairs this algorithm with a post-quantum one, by declaration. */
    public bool $hybrid = false;

    /** The day this domain's data left, when somebody declared one. */
    public string $breachedOn = '';
    public string $verdict = '';
    public string $because = '';

    /**
     * Published advisories against the declared version of a library.
     *
     * @var list<string>
     */
    public array $advisories = [];

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
     * What a reader can go and check about this finding.
     *
     * An advisory against this very version outranks the defects the catalogue
     * knows about the algorithm in general: both are true, and the one that
     * describes the verdict is the specific one.
     *
     * @return list<string>
     */
    public function references(): array
    {
        return $this->advisories !== [] ? $this->advisories : Catalogue::references($this->algorithm);
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
