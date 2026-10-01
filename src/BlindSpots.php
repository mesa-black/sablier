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
        $lines = [
            Lang::t('blind.managed_services'),
            Lang::t('blind.runtime'),
            Lang::t('blind.hsm'),
            Lang::t('blind.lifetime', $analysis->declaration->defaultLifetime),
        ];

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
