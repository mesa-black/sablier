<?php

declare(strict_types=1);

namespace Sablier;

/**
 * How much there is to change, counted in places rather than in weeks.
 *
 * The EU roadmap's quantum risk rests on three factors: the weakness of the
 * cryptography, the impact of a break, and "the estimated time and effort
 * required to migrate to PQC". This tool measured the first two and said nothing
 * about the third, which is the one a team actually plans against — and the one
 * every vendor answers with a number nobody can check.
 *
 * So this counts, and refuses to estimate. For each algorithm that will have to
 * go: how many call sites, in how many files, how many of them are a declared
 * dependency rather than code of yours, and how many name the algorithm
 * somewhere other than the call site. Every one of those is already in the
 * inventory; none of them is an inference.
 *
 * What it will not do is turn that into a duration. Eight call sites in one file
 * behind one wrapper is an afternoon; eight across six services with a protocol
 * between them is a quarter, and nothing in a repository distinguishes the two.
 * A tool that printed "three weeks" would be inventing the only number in the
 * report that cannot be checked, and would be believed precisely because it is
 * the number somebody needed. The count is ours; the duration is the reader's.
 */
final class Effort
{
    /** Verdicts that mean something has to change. */
    private const array ACTIONABLE = [
        Assessor::COMPROMISED,
        Assessor::URGENT,
        Assessor::MIGRATE,
        Assessor::WATCH,
    ];

    /**
     * One line per algorithm to retire, heaviest first.
     *
     * @return list<array{algorithm:string, label:string, sites:int, files:int, declared:int, indirect:int, domains:int}>
     */
    public static function lines(Analysis $analysis): array
    {
        /** @var array<string, array{files:array<string, true>, domains:array<string, true>, sites:int, declared:int, indirect:int}> $byAlgorithm */
        $byAlgorithm = [];
        foreach ($analysis->findings as $finding) {
            if (!\in_array($finding->verdict, self::ACTIONABLE, true)) {
                continue;
            }

            $current = $byAlgorithm[$finding->algorithm] ?? [
                'files' => [], 'domains' => [], 'sites' => 0, 'declared' => 0, 'indirect' => 0,
            ];
            ++$current['sites'];
            $current['files'][$finding->file] = true;
            $current['domains'][$finding->domain] = true;
            // Declared and not observed: a dependency's capability table, a
            // protocol named in a configuration. What changes there is a
            // version or a setting rather than a line of code — and it has to
            // be confirmed first, since presence is not usage. Counted apart
            // because adding it to call sites would overstate the work.
            $current['declared'] += $finding->inventory ? 1 : 0;
            // The algorithm is named in a variable or a configuration rather
            // than at the call site. That is the roadmap's crypto-agility —
            // "a modular way that enables replacing the cryptographic
            // components" — observed instead of asserted, and it is the cheap
            // kind of call site to change. Counted only among the observed
            // ones: a declared entry is already counted above, and counting it
            // twice would read as two different pieces of work.
            $current['indirect'] += !$finding->inventory && $finding->confidence === Finding::CONFIDENCE_MEDIUM ? 1 : 0;
            $byAlgorithm[$finding->algorithm] = $current;
        }

        // Two catalogue keys can share a label — RSA encrypts and RSA signs —
        // and two rows reading "RSA" in one table is how a reader stops
        // believing the table. The purpose is what separates them, and it is
        // also the thing that decides whether the work is urgent.
        $labels = [];
        foreach (array_keys($byAlgorithm) as $algorithm) {
            $labels[Catalogue::label($algorithm)] = ($labels[Catalogue::label($algorithm)] ?? 0) + 1;
        }

        $lines = [];
        foreach ($byAlgorithm as $algorithm => $counts) {
            $label = Catalogue::label($algorithm);
            $entry = Catalogue::get($algorithm);
            if (($labels[$label] ?? 0) > 1 && $entry !== null) {
                $label .= ' · '.Lang::t('effort.purpose.'.$entry['purpose']);
            }
            $lines[] = [
                'algorithm' => $algorithm,
                'label' => $label,
                'sites' => $counts['sites'],
                'files' => \count($counts['files']),
                'declared' => $counts['declared'],
                'indirect' => $counts['indirect'],
                'domains' => \count($counts['domains']),
            ];
        }

        usort($lines, static fn (array $a, array $b): int => [$b['sites'], $b['files']] <=> [$a['sites'], $a['files']]
            ?: strcmp($a['label'], $b['label']));

        return $lines;
    }

    /** The block the technical report prints, or nothing when there is no work. */
    public static function render(Analysis $analysis): string
    {
        $lines = self::lines($analysis);
        if ($lines === []) {
            return '';
        }

        $rows = '';
        $sites = 0;
        $files = [];
        foreach ($lines as $line) {
            $sites += $line['sites'];
            $notes = [];
            if ($line['declared'] > 0) {
                $notes[] = Lang::t('effort.declared', $line['declared']);
            }
            if ($line['indirect'] > 0) {
                $notes[] = Lang::t('effort.indirect', $line['indirect']);
            }
            $rows .= '<tr><td>'.htmlspecialchars($line['label']).'</td>'
                .'<td class="n">'.$line['sites'].'</td>'
                .'<td class="n">'.$line['files'].'</td>'
                .'<td class="n">'.$line['domains'].'</td>'
                .'<td>'.htmlspecialchars(implode(' · ', $notes)).'</td></tr>';
        }
        foreach ($analysis->findings as $finding) {
            if (\in_array($finding->verdict, self::ACTIONABLE, true)) {
                $files[$finding->file] = true;
            }
        }

        return '<section class="effort"><h2>'.htmlspecialchars(Lang::t('effort.title')).'</h2>'
            .'<p class="lead">'.htmlspecialchars(Lang::t('effort.lead', $sites, \count($files))).'</p>'
            .'<table><thead><tr>'
            .'<th>'.htmlspecialchars(Lang::t('effort.col.algorithm')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('effort.col.sites')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('effort.col.files')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('effort.col.domains')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('effort.col.notes')).'</th>'
            .'</tr></thead><tbody>'.$rows.'</tbody></table>'
            .'<p class="legend">'.htmlspecialchars(Lang::t('effort.limit')).'</p></section>';
    }
}
