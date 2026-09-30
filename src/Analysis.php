<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Everything a reporter needs, and nothing a reporter should have to fetch.
 *
 * Renderers used to receive eight positional arguments; a value object means
 * adding a fact to the analysis no longer changes every renderer's signature.
 */
final readonly class Analysis
{
    /**
     * @param list<Finding>                                                          $findings
     * @param list<string>                                                           $blindSpots
     * @param list<array{target:string, facts:array<string,string>, notes:list<string>}> $probes
     */
    public function __construct(
        public array $findings,
        public Declaration $declaration,
        public string $target,
        public int $filesRead,
        public array $blindSpots,
        public int $currentYear,
        public float $duration = 0.0,
        public array $probes = [],
        public bool $projected = false,
        /** @var array{algorithm:string, digest:string, signed_at:string, public_key:string, signature:string}|null */
        public ?array $signature = null,
    ) {
    }
}
