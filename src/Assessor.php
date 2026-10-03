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
    public const string ACCEPTED = 'accepted';

    public function __construct(
        private readonly Declaration $declaration,
        private readonly int $currentYear,
        /** Published vulnerabilities, when the operator has collected them. */
        private readonly ?Advisories $advisories = null,
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
            $finding->hybrid = $domain['hybrid'];

            [$finding->verdict, $finding->because] = $this->verdict($finding);
            $this->applyAdvisories($finding);
            $this->applyAcceptance($finding);
        }

        return $findings;
    }

    public static function label(string $verdict): string
    {
        return Lang::t("verdict.$verdict");
    }

    /**
     * Order in which a human should read the verdicts.
     *
     * @return list<string>
     */
    public static function order(): array
    {
        return [self::COMPROMISED, self::URGENT, self::MIGRATE, self::DECLARE, self::WATCH, self::ACCEPTED, self::CLEAR, self::NOISE];
    }

    /**
     * An accepted finding moves section; it does not disappear.
     *
     * The whole value of this feature is in what it refuses to do. A tool where
     * a finding vanishes in three seconds empties itself within six months —
     * every linter suppression file ever written says so. So the original
     * verdict stays attached, the reason is printed, and the acceptance expires
     * on a date the reader can see.
     */
    /**
     * A declared library with a published hole in the declared version.
     *
     * This is the one place where "presence is not usage" gives way, and the
     * reason is in the dates: the rest of this report argues about 2035, while
     * an advisory says somebody found a way in before the report was printed.
     * A high or critical one makes the finding urgent — the same category as
     * MD5 and SHA-1, which is to say a problem that owes nothing to quantum
     * computing. Medium and low are attached and shown, never promoted: a tool
     * that raises everything is a tool nobody reads twice.
     */
    private function applyAdvisories(Finding $finding): void
    {
        if ($this->advisories === null || !$finding->inventory || $finding->evidence === '') {
            return;
        }

        $all = $this->advisories->for($finding->evidence);
        if ($all === []) {
            return;
        }

        $finding->advisories = array_map(static fn (array $entry): string => $entry['id'], $all);

        $raising = $this->advisories->raising($finding->evidence);
        if ($raising === []) {
            return;
        }

        $fixed = '';
        foreach ($raising as $entry) {
            if ($entry['fixed'] !== '') {
                $fixed = $entry['fixed'];
                break;
            }
        }

        $finding->verdict = self::URGENT;
        $finding->because = Lang::t(
            $fixed !== '' ? 'reason.vulnerable_dependency.fixed' : 'reason.vulnerable_dependency',
            $finding->evidence,
            \count($raising),
            $fixed,
        );
    }

    private function applyAcceptance(Finding $finding): void
    {
        $acceptance = $this->declaration->acceptanceFor($finding->fingerprint());
        if ($acceptance === null || \in_array($finding->verdict, [self::CLEAR, self::NOISE], true)) {
            return;
        }

        $finding->acceptedReason = $acceptance['reason'];
        $finding->acceptedUntil = $acceptance['until'];

        if ($acceptance['expired']) {
            // The decision lapsed: the finding reopens with its real verdict and
            // says why it is back.
            $finding->acceptanceExpired = true;
            $finding->because = Lang::t('reason.acceptance_expired', $acceptance['until']).' '.$finding->because;

            return;
        }

        $finding->originalVerdict = $finding->verdict;
        $finding->verdict = self::ACCEPTED;
        $finding->because = Lang::t('reason.accepted', Assessor::label($finding->originalVerdict), $acceptance['until']);
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

        // A quantum-vulnerable algorithm kept beside a post-quantum one is the
        // transition the references ask for, not a thing to migrate. Telling
        // somebody to retire the classical half of a hybrid is telling them to
        // undo it — and this verdict is the one the tool pointed at its own
        // Ed25519 while signing every report with ML-DSA beside it.
        if ($algo['quantum'] && $finding->hybrid) {
            return [self::CLEAR, Lang::t('reason.hybrid')];
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

        // The last secret this system writes is written on its last day, and it
        // is harvestable for its full lifetime from there. Assuming the system
        // stops today is the optimistic reading, which is why an undeclared
        // horizon is printed as a blind spot rather than passed over.
        $lastEmission = max($this->currentYear, $this->declaration->serviceUntil);
        $exposureEnd = $lastEmission + $finding->lifetime;
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
