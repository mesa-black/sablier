<?php

declare(strict_types=1);

namespace Sablier;

/**
 * What a breach costs, counted in years rather than in records.
 *
 * Everything else in this tool reasons forward: an adversary captures today
 * what they will read when the algorithm falls. A breach turns that around.
 * They are not waiting any more — they hold it — and the only question left is
 * how much of the confidentiality you asked for the cryptography can still
 * deliver.
 *
 * The arithmetic is the same inequality read from the other end. Data taken in
 * year B must stay secret until B + lifetime. The algorithm protecting it stops
 * being credible at the regime's expiry. Whatever lies between the two is the
 * part that becomes readable, and migrating afterwards does not reach it.
 *
 * Three refusals keep this from becoming a breach-notification generator:
 *
 * - **it counts years, never people.** How many records left is a fact for the
 *   incident team; how long they keep hurting is the question this tool was
 *   built to answer, and the one nobody else asks;
 * - **it only speaks about domains somebody declared breached.** A single
 *   stolen table is not a statement about the whole system, so the date sits on
 *   the domain, and a global one is a deliberate worst case;
 * - **it says what it cannot know.** The tool has no idea what actually left,
 *   whether it left encrypted, or whether the keys left with it. It reasons on
 *   what was declared, and the report prints that sentence next to the figure.
 */
final class Breach
{
    /**
     * One line per breached domain: what was asked, and what is still owed.
     *
     * @return list<array{domain:string, taken:string, lifetime:int, until:int, readable:int, plaintext:bool, harvestable:bool}>
     */
    public static function lines(Analysis $analysis): array
    {
        $expiry = $analysis->declaration->expiryYear;

        /** @var array<string, array{taken:string, lifetime:int, plaintext:bool, harvestable:bool}> $domains */
        $domains = [];
        foreach ($analysis->findings as $finding) {
            if ($finding->breachedOn === '' || $finding->verdict === Assessor::NOISE) {
                continue;
            }

            $algo = Catalogue::get($finding->algorithm);
            $current = $domains[$finding->domain] ?? [
                'taken' => $finding->breachedOn,
                'lifetime' => $finding->lifetime,
                'plaintext' => false,
                'harvestable' => false,
            ];

            $current['lifetime'] = max($current['lifetime'], $finding->lifetime);
            // Plaintext is the worst case and says so: nothing has to fall for
            // this data to be readable, because nothing was protecting it.
            $current['plaintext'] = $current['plaintext'] || $finding->algorithm === 'plaintext';
            $current['harvestable'] = $current['harvestable']
                || ($algo !== null && $algo['quantum'] && $algo['purpose'] === Catalogue::PURPOSE_CONFIDENTIALITY);
            $domains[$finding->domain] = $current;
        }

        $lines = [];
        foreach ($domains as $name => $domain) {
            $takenYear = (int) substr($domain['taken'], 0, 4);
            $until = $takenYear + $domain['lifetime'];
            $lines[] = [
                'domain' => $name,
                'taken' => $domain['taken'],
                'lifetime' => $domain['lifetime'],
                'until' => $until,
                // Plaintext loses the whole duration; an algorithm that holds
                // loses none, and the interesting case is in between.
                'readable' => $domain['plaintext']
                    ? $domain['lifetime']
                    : ($domain['harvestable'] ? max(0, $until - $expiry) : 0),
                'plaintext' => $domain['plaintext'],
                'harvestable' => $domain['harvestable'],
            ];
        }

        usort($lines, static fn (array $a, array $b): int => $b['readable'] <=> $a['readable'] ?: strcmp($a['domain'], $b['domain']));

        return $lines;
    }

    /** The block both documents print, or nothing when no breach was declared. */
    public static function render(Analysis $analysis): string
    {
        $lines = self::lines($analysis);
        if ($lines === []) {
            return '';
        }

        $rows = '';
        foreach ($lines as $line) {
            $rows .= \sprintf(
                '<li%s>%s</li>',
                $line['readable'] > 0 ? ' class="past"' : '',
                htmlspecialchars(match (true) {
                    $line['plaintext'] => Lang::t('breach.plaintext', $line['domain'], $line['lifetime'], $line['until']),
                    $line['readable'] > 0 => Lang::t(
                        $line['readable'] > 1 ? 'breach.readable' : 'breach.readable.one',
                        $line['domain'], $line['lifetime'], $line['until'], $analysis->declaration->expiryYear, $line['readable'],
                    ),
                    $line['harvestable'] => Lang::t('breach.held', $line['domain'], $line['until']),
                    default => Lang::t('breach.sound', $line['domain']),
                }),
            );
        }

        // Written the way every other date in these documents is written.
        $date = \DateTimeImmutable::createFromFormat('Y-m-d', substr($lines[0]['taken'], 0, 10));
        $taken = $date === false ? $lines[0]['taken'] : $date->format('d/m/Y');

        return '<section class="breach"><h2>'.htmlspecialchars(Lang::t('breach.title', $taken)).'</h2>'
            .'<p class="lead">'.htmlspecialchars(Lang::t('breach.lead')).'</p>'
            .'<ul>'.$rows.'</ul>'
            .'<p class="legend">'.htmlspecialchars(Lang::t('breach.limit')).'</p></section>';
    }
}
