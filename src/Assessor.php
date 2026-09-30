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
    public const string COMPROMISED = 'COMPROMIS';
    public const string MIGRATE = 'À MIGRER';
    public const string URGENT = 'CASSÉ AUJOURD\'HUI';
    public const string WATCH = 'SURVEILLER';
    public const string CLEAR = 'CONFORME';
    public const string DECLARE = 'À DÉCLARER';
    public const string NOISE = 'PROBABLEMENT HORS SUJET';

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

    /** @return array{0:string, 1:string} */
    private function verdict(Finding $finding): array
    {
        if ($finding->algorithm === 'indéterminé') {
            return [self::DECLARE, "L'algorithme n'est pas lisible depuis le code. À confirmer à la main plutôt qu'à deviner."];
        }

        $algo = Catalogue::get($finding->algorithm);
        if ($algo === null) {
            return [self::DECLARE, 'Algorithme hors catalogue.'];
        }

        if ($finding->likelyNonCrypto) {
            return [self::NOISE, "Ressemble à un identifiant (clé de cache, empreinte) plutôt qu'à un contrôle de sécurité. À confirmer, pas à corriger."];
        }

        if ($algo['broken']) {
            // Presence in a lock file is not a call site. A protocol may even
            // mandate the weak primitive — TOTP is specified on SHA-1 — so this
            // is something to confirm, never something to declare broken.
            if ($finding->inventory) {
                return [self::WATCH, "Dépendance déclarée employant {$algo['label']}. Peut être imposé par la spécification du protocole, ou jamais appelé : à confirmer avant toute action."];
            }

            return [self::URGENT, "Cassé classiquement, indépendamment du quantique. L'échéance était hier."];
        }

        if (!$algo['quantum']) {
            return [self::CLEAR, $algo['note'] !== '' ? $algo['note'] : 'Résiste aux algorithmes quantiques connus.'];
        }

        if ($algo['purpose'] === Catalogue::PURPOSE_AUTHENTICITY) {
            if ($finding->trustAnchor) {
                return [self::MIGRATE, "Ancre de confiance à longue durée : une signature qui doit rester vérifiable après {$this->declaration->expiryYear} se prépare maintenant."];
            }

            return [self::WATCH, "Signature : pas de récolte possible. À migrer avant {$this->declaration->deprecationYear} pour la conformité, sans urgence de confidentialité."];
        }

        $exposureEnd = $this->currentYear + $finding->lifetime;
        if ($exposureEnd > $this->declaration->expiryYear) {
            $suffix = $finding->domainDeclared ? '' : ' (durée par défaut, ce domaine n\'est pas déclaré : le chiffre est à confirmer)';

            return [self::COMPROMISED, \sprintf(
                'Chiffré aujourd\'hui, à garder confidentiel jusqu\'en %d — soit %d %s après la péremption de %s. Une capture faite maintenant sera lisible.%s',
                $exposureEnd,
                $gap = $exposureEnd - $this->declaration->expiryYear,
                $gap > 1 ? 'ans' : 'an',
                $algo['label'],
                $suffix,
            )];
        }

        return [self::WATCH, \sprintf(
            'La donnée cesse d\'être sensible en %d, avant la péremption de %d. Migration à planifier pour le système, pas pour sauver cette donnée.',
            $exposureEnd,
            $this->declaration->expiryYear,
        )];
    }

    /** Order in which a human should read the verdicts. */
    public static function order(): array
    {
        return [self::COMPROMISED, self::URGENT, self::MIGRATE, self::DECLARE, self::WATCH, self::CLEAR, self::NOISE];
    }
}
