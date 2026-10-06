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
        /** @var array{algorithm:string, digest:string, signed_at:string, public_key:string, signature:string, previous?:string, hybrid?:array{algorithm:string, public_key:string, signature:string}, ephemeral?:bool}|null */
        public ?array $signature = null,
        /**
         * What a third party attests about the date, when one was asked.
         *
         * @var array{time:string, authority:string, algorithm:string, serial:string, imprint:string, path:string}|null
         */
        public ?array $timestamp = null,
        /** The tool that produced the inventory, when it was not this one. */
        public string $importedFrom = '',
        /** The command that produced this analysis, so a third party can repeat it. */
        public string $commandLine = '',
        /**
         * What each detector opened and what it produced, so the report can say
         * what it looked for and did not find rather than only what it skipped.
         *
         * @var array<string, array{files:int, findings:int}>
         */
        public array $searched = [],
    ) {
    }
}
