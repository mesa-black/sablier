<?php

declare(strict_types=1);

namespace Sablier;

/**
 * What to do, in order — the part every inventory tool skips.
 *
 * A list of findings asks the reader to do the arbitration themselves, which
 * means it gets postponed. This class takes a position: it names the first
 * action, says why it comes first, and admits when nothing is urgent.
 *
 * The ordering is by leverage rather than by severity alone. The one rule worth
 * stating: when most findings sit in undeclared domains, completing the
 * declaration comes before everything else, because until then the verdicts
 * above are guesses wearing a confident typeface.
 */
final class ActionPlan
{
    /** @return list<array{key:string, title:string, body:string}> */
    public static function for(Analysis $analysis): array
    {
        $counts = [];
        $undeclared = [];
        $domains = [];
        foreach ($analysis->findings as $finding) {
            $counts[$finding->verdict] = ($counts[$finding->verdict] ?? 0) + 1;
            // A probe finding has no path, so no glob can ever cover it:
            // counting it as an undeclared domain asked every project with a
            // declared host to go and declare something it cannot declare. Found
            // by scanning a repository whose only cryptography is its TLS — the
            // report said "nothing is urgent" and told the reader to complete a
            // declaration that was already complete.
            if (!$finding->domainDeclared && $finding->verdict !== Assessor::NOISE
                && !str_starts_with($finding->file, 'tls://')) {
                $undeclared[$finding->domain] = true;
            }
            if ($finding->verdict === Assessor::COMPROMISED) {
                $domains[$finding->domain] = true;
            }
        }

        $actionable = array_sum($counts) - ($counts[Assessor::NOISE] ?? 0);
        $declarationFirst = $actionable > 0 && \count($undeclared) > 0
            && (($counts[Assessor::DECLARE] ?? 0) + self::undeclaredFindings($analysis)) * 2 > $actionable;

        $actions = [];

        // "Nothing is urgent" is a finding, not a fallback. Emitting it only
        // when no other action exists meant a calm project was handed a to-do
        // list without ever being told it was calm.
        $urgentWork = ($counts[Assessor::COMPROMISED] ?? 0) > 0
            || ($counts[Assessor::URGENT] ?? 0) > 0
            || ($counts[Assessor::MIGRATE] ?? 0) > 0
            || self::hasClassicalKeyExchange($analysis);
        if (!$urgentWork) {
            $actions[] = self::action('nothing_urgent');
        }

        if (($counts[Assessor::COMPROMISED] ?? 0) > 0) {
            $actions[] = self::action('harvested', [
                implode(', ', array_keys($domains)),
                $analysis->declaration->expiryYear,
            ]);
        }

        if (($counts[Assessor::URGENT] ?? 0) > 0) {
            $actions[] = self::action(
                $counts[Assessor::URGENT] > 1 ? 'broken.plural' : 'broken',
                [$counts[Assessor::URGENT]],
                'broken',
            );
        }

        if (self::hasClassicalKeyExchange($analysis)) {
            $actions[] = self::action('hybrid_edge');
        }

        if ($undeclared !== [] || ($counts[Assessor::DECLARE] ?? 0) > 0) {
            $declaration = self::action(
                \count($undeclared) > 1 ? 'declare.plural' : 'declare',
                [\count($undeclared)],
                'declare',
            );
            if ($declarationFirst && $urgentWork) {
                array_unshift($actions, $declaration);
            } elseif ($declarationFirst) {
                array_splice($actions, 1, 0, [$declaration]); // right after "nothing urgent"
            } else {
                $actions[] = $declaration;
            }
        }

        if (($counts[Assessor::MIGRATE] ?? 0) > 0) {
            $actions[] = self::action('trust_anchors', [$analysis->declaration->deprecationYear]);
        }

        // Always last, and always present: the window closes on its own — and
        // now it says when. "Replay this once a year" is advice; "the next
        // crossing is 1 January 2029" is an appointment.
        $next = Crossings::next($analysis);
        $actions[] = self::action('calendar', [$analysis->declaration->expiryYear]);
        if ($next !== null) {
            $last = \count($actions) - 1;
            $actions[$last]['body'] .= ' '.Lang::t('crossing.next', $next['domain'], $next['year']);
        }

        return $actions;
    }

    /**
     * @param list<int|string> $args
     * @param string|null      $titleKey when the body has a plural variant but the title does not
     *
     * @return array{key: string, title: string, body: string}
     */
    private static function action(string $key, array $args = [], ?string $titleKey = null): array
    {
        return [
            'key' => $titleKey ?? $key,
            'title' => Lang::t('action.'.($titleKey ?? $key).'.title'),
            'body' => Lang::t("action.$key.body", ...$args),
        ];
    }

    /** Findings a declaration could have covered, which excludes the probe's. */
    private static function undeclaredFindings(Analysis $analysis): int
    {
        $count = 0;
        foreach ($analysis->findings as $finding) {
            if (!$finding->domainDeclared && $finding->verdict !== Assessor::NOISE
                && !str_starts_with($finding->file, 'tls://')) {
                ++$count;
            }
        }

        return $count;
    }

    /**
     * A probe that came back with a classical key exchange is the cheapest win
     * available: enabling a hybrid group is usually one switch at the edge, and
     * it protects every session at once.
     */
    private static function hasClassicalKeyExchange(Analysis $analysis): bool
    {
        foreach ($analysis->findings as $finding) {
            if (str_starts_with($finding->file, 'tls://')
                && $finding->algorithm === 'ecdh'
                && $finding->purpose === Catalogue::PURPOSE_CONFIDENTIALITY) {
                return true;
            }
        }

        return false;
    }
}
