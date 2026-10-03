<?php

declare(strict_types=1);

namespace Sablier;

/**
 * What the analysis could not see, assembled once for every document.
 *
 * The product rule is that a report prints its own blind spots at the same
 * size as the rest. Two reports printing two different lists would make that
 * rule a decoration, so the list is built here and both read it.
 */
final class BlindSpots
{
    /** @return list<string> */
    public static function for(Analysis $analysis): array
    {
        // The managed-services line is true of an application repository and
        // false the moment the infrastructure is declared as code beside it.
        $iac = false;
        foreach ($analysis->findings as $finding) {
            if (str_ends_with($finding->file, '.tf')) {
                $iac = true;
                break;
            }
        }

        $lines = [
            Lang::t($iac ? 'blind.managed_services.iac' : 'blind.managed_services'),
            Lang::t('blind.runtime'),
            Lang::t('blind.hsm'),
            Lang::t('blind.lifetime', $analysis->declaration->defaultLifetime),
        ];

        $hybrid = 0;
        foreach ($analysis->declaration->domains as $domain) {
            if ($domain['hybrid']) {
                ++$hybrid;
            }
        }
        if ($hybrid > 0) {
            $lines[] = Lang::t('blind.hybrid', $hybrid);
        }

        $stale = Interview::stale($analysis->declaration->domains);
        if ($stale > 0) {
            $lines[] = Lang::t('blind.stale_declaration', $stale, Interview::STALE_AFTER_YEARS);
        }

        $lines[] = $analysis->declaration->serviceUntil > 0
            ? Lang::t('blind.service_until.declared', $analysis->declaration->serviceUntil)
            : Lang::t('blind.service_until');
        // A graded regime has no single retained date, and printing one as if
        // it did would hide the thing that makes it different.
        $lines[] = $analysis->declaration->graded()
            ? Lang::t(
                'blind.regime.graded',
                $analysis->declaration->deprecationYear,
                $analysis->declaration->expiryYear,
                Declaration::REGIMES[$analysis->declaration->regime]['source'] ?? '?',
            )
            : Lang::t(
                'blind.regime',
                $analysis->declaration->expiryYear,
                Declaration::REGIMES[$analysis->declaration->regime]['source'] ?? '?',
            );

        if ($analysis->declaration->rejectedAcceptances !== []) {
            $lines[] = Lang::t('accepted.rejected', \count($analysis->declaration->rejectedAcceptances));
        }

        $undetermined = 0;
        foreach ($analysis->findings as $finding) {
            if ($finding->verdict === Assessor::DECLARE) {
                ++$undetermined;
            }
        }
        if ($undetermined > 0) {
            $lines[] = Lang::t($undetermined > 1 ? 'blind.undetermined.plural' : 'blind.undetermined', $undetermined);
        }

        foreach ($analysis->blindSpots as $spot) {
            $lines[] = $spot;
        }

        return $lines;
    }
}
