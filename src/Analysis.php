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
         * What third parties attest about the date, when any were asked.
         *
         * A list rather than one token, in the order the authorities were named.
         * One authority is one point of trust; the same imprint presented to
         * several, in several jurisdictions, costs one HTTP request each and
         * turns forgery into collusion. The first is the primary — it is the one
         * whose file name every printed command uses, and the only one a reader
         * who corroborates nothing will look at.
         *
         * @var list<array{time:string, authority:string, algorithm:string, serial:string, imprint:string, path:string}>
         */
        public array $timestamps = [],
        /** The tool that produced the inventory, when it was not this one. */
        public string $importedFrom = '',
        /** The command that produced this analysis, so a third party can repeat it. */
        public string $commandLine = '',
        /**
         * Where this document was written, so the commands it prints can name
         * real files instead of angle brackets. Only the base name is ever
         * shown: the .sig and the .tsr sit beside the report wherever it travels,
         * and the path it had on the machine that made it is nobody's business.
         */
        public string $reportPath = '',
        /**
         * What each detector opened and what it produced, so the report can say
         * what it looked for and did not find rather than only what it skipped.
         *
         * @var array<string, array{files:int, findings:int}>
         */
        public array $searched = [],
    ) {
    }

    /**
     * The attestation every printed command refers to.
     *
     * @return array{time:string, authority:string, algorithm:string, serial:string, imprint:string, path:string}|null
     */
    public function timestamp(): ?array
    {
        return $this->timestamps[0] ?? null;
    }

    /**
     * The attestations that corroborate the first one, if any were asked for.
     *
     * @return list<array{time:string, authority:string, algorithm:string, serial:string, imprint:string, path:string}>
     */
    public function corroborations(): array
    {
        return \array_slice($this->timestamps, 1);
    }

    /**
     * Whether the seal on this document predates the run that rendered it.
     *
     * The signature and the attestations are kept together or redone together —
     * both hang off the digest — so one question answers for both halves, and a
     * document that explained only the token left the reader with the same
     * puzzle one line higher up.
     */
    public function sealPredatesRun(): bool
    {
        $signedAt = $this->signature['signed_at'] ?? '';
        if ($signedAt !== '') {
            $signed = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $signedAt);
            if ($signed !== false && $signed->setTimezone(new \DateTimeZone('UTC'))->format('d/m/Y') !== Rendered::day()) {
                return true;
            }
        }

        $token = $this->timestamp();

        return $token !== null && !str_starts_with(Timestamp::readable($token['time']), Rendered::day());
    }
}
