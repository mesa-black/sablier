<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Turns an inventory into an opinion — the only place the tool judges anything.
 *
 * Three distinctions carry the whole model, and most of the public discourse on
 * post-quantum mixes them up:
 *   · confidentiality is harvestable, authenticity is not;
 *   · symmetric cryptography is not the problem, and saying so prevents
 *     pointless migrations;
 *   · MD5 and SHA-1 are a problem from 2004 and 2017, not from 2035.
 */
final class Assessor
{
    public const string COMPROMISED = 'compromised';
    public const string MIGRATE = 'migrate';
    public const string URGENT = 'urgent';
    public const string WATCH = 'watch';
    public const string CLEAR = 'clear';
    public const string DECLARE = 'declare';
    public const string NOISE = 'noise';

    public function __construct(
        private readonly Declaration $declaration,
        private readonly int $currentYear,
    ) {
    }

    /**
     * @param list<Finding> $findings
     *
     * @return list<Finding>
     */
    public function assess(array $findings): array
    {
        foreach ($findings as $finding) {
            $domain = $this->declaration->resolve($finding->file);
            $finding->domain = $domain['name'];
            $finding->domainDeclared = $domain['declared'];
            $finding->lifetime = $domain['lifetime'];
            $finding->trustAnchor = $domain['trust_anchor'];

            [$finding->verdict, $finding->because] = $this->verdict($finding);
        }

        return $findings;
    }

    public static function label(string $verdict): string
    {
        return Lang::t("verdict.$verdict");
    }

    /** Order in which a human should read the verdicts. */
    public static function order(): array
    {
        return [self::COMPROMISED, self::URGENT, self::MIGRATE, self::DECLARE, self::WATCH, self::CLEAR, self::NOISE];
    }

    /** @return array{0:string, 1:string} */
    private function verdict(Finding $finding): array
    {
        if ($finding->algorithm === 'undetermined') {
            return [self::DECLARE, Lang::t('reason.undetermined')];
        }

        $algo = Catalogue::get($finding->algorithm);
        if ($algo === null) {
            return [self::DECLARE, Lang::t('reason.unknown_algorithm')];
        }

        if ($finding->likelyNonCrypto) {
            return [self::NOISE, Lang::t('reason.noise')];
        }

        if ($algo['broken']) {
            // Presence in a lock file is not a call site. A protocol may even
            // mandate the weak primitive — TOTP is specified on SHA-1 — so this
            // is something to confirm, never something to declare broken.
            if ($finding->inventory) {
                return [self::WATCH, Lang::t('reason.inventory_broken', $algo['label'])];
            }

            return [self::URGENT, Lang::t('reason.broken')];
        }

        if (!$algo['quantum']) {
            return [self::CLEAR, $algo['note'] !== '' ? $algo['note'] : Lang::t('reason.quantum_safe')];
        }

        if ($algo['purpose'] === Catalogue::PURPOSE_AUTHENTICITY) {
            if ($finding->trustAnchor) {
                return [self::MIGRATE, Lang::t('reason.trust_anchor', $this->declaration->expiryYear)];
            }

            return [self::WATCH, Lang::t('reason.signature', $this->declaration->deprecationYear)];
        }

        $exposureEnd = $this->currentYear + $finding->lifetime;
        if ($exposureEnd > $this->declaration->expiryYear) {
            $gap = $exposureEnd - $this->declaration->expiryYear;

            return [self::COMPROMISED, Lang::t(
                'reason.harvested',
                $exposureEnd,
                $gap,
                Lang::t($gap > 1 ? 'unit.years' : 'unit.year'),
                $algo['label'],
            ).($finding->domainDeclared ? '' : ' '.Lang::t('reason.undeclared_domain'))];
        }

        return [self::WATCH, Lang::t('reason.short_lived', $exposureEnd, $this->declaration->expiryYear)];
    }
}
