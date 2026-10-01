<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\Analysis;
use Sablier\Assessor;
use Sablier\Crossings;
use Sablier\Lang;

/**
 * The one picture in the whole product.
 *
 * It is the only visual that makes the subject land with someone who is not a
 * cryptographer: each bar is a duration somebody declared, the vertical line is
 * a regulatory date, and the question is simply which of the two is longer. A
 * bar turns red only when a harvestable algorithm protects that domain past the
 * line — colouring on duration alone made the chart contradict the verdict
 * printed above it.
 */
final class Timeline
{
    /**
     * The same chart, read as dates.
     *
     * A bar against a mark asks the reader to do the subtraction. The
     * subtraction has one answer and it is a date, so the report prints it:
     * nobody acts on a bar, and everybody acts on "1 January 2029".
     */
    private static function crossings(Analysis $analysis): string
    {
        $crossings = Crossings::for($analysis);
        if ($crossings === []) {
            return '';
        }

        $items = '';
        foreach ($crossings as $crossing) {
            $key = match (true) {
                $crossing['outlives'] => 'crossing.row.outlives',
                $crossing['past'] => 'crossing.row.past',
                default => 'crossing.row',
            };
            $items .= '<li'.($crossing['past'] ? ' class="past"' : '').'>'.htmlspecialchars(Lang::t(
                $key,
                $crossing['domain'],
                $crossing['lifetime'],
                $crossing['year'],
            )).'</li>';
        }

        return '<div class="crossings"><h3>'.htmlspecialchars(Lang::t('crossing.title')).'</h3><ul>'.$items.'</ul>'
            .'<p class="legend">'.htmlspecialchars(Lang::t('crossing.intro', $analysis->declaration->expiryYear)).'</p></div>';
    }

    /**
     * One bar per declared domain: how long its data must stay secret, against
     * the date its protection expires.
     *
     * Shared by both documents. The technical report and the audit report show
     * the same chart because it is the same claim — and a figure that differs
     * between two reports of one analysis is a figure nobody can cite.
     */
    public static function render(Analysis $analysis): string
    {
        $start = $analysis->currentYear;
        $end = max($analysis->declaration->expiryYear + 5, $start + 20);
        $span = $end - $start;

        // A long lifetime is not by itself an exposure: it only becomes one when
        // a harvestable algorithm protects that domain. Colouring the bar on the
        // duration alone made the chart contradict the verdict above it.
        $domains = [];
        $exposed = [];
        foreach ($analysis->findings as $finding) {
            if ($finding->verdict === Assessor::NOISE) {
                continue;
            }
            $key = $finding->domain;
            $domains[$key] = max($domains[$key] ?? 0, $finding->lifetime);
            $exposed[$key] = ($exposed[$key] ?? false) || $finding->verdict === Assessor::COMPROMISED;
        }
        if ($domains === []) {
            return '';
        }
        arsort($domains);

        $expiryLeft = round((($analysis->declaration->expiryYear - $start) / $span) * 100, 2);
        $deprLeft = round((($analysis->declaration->deprecationYear - $start) / $span) * 100, 2);

        $bars = '';
        foreach (\array_slice($domains, 0, 8, true) as $name => $lifetime) {
            $width = min(100, round(($lifetime / $span) * 100, 2));
            $bars .= \sprintf(
                '<div class="row"><div class="lbl">%s</div><div class="track"><div class="bar %s" style="width:%s%%"></div></div><div class="yrs">%d %s</div></div>',
                htmlspecialchars((string) $name),
                ($exposed[$name] ?? false) ? 'over' : '',
                $width,
                $lifetime,
                Lang::t($lifetime > 1 ? 'unit.years' : 'unit.year'),
            );
        }

        $title = htmlspecialchars(Lang::t('timeline.title'));
        $legend = htmlspecialchars(Lang::t('timeline.legend'));
        $dates = self::crossings($analysis);
        $deprecationLabel = htmlspecialchars(Lang::t('timeline.deprecation'));
        $expiryLabel = htmlspecialchars(Lang::t('timeline.expiry'));

        return <<<HTML
            <section class="timeline">
              <h2>$title</h2>
              <div class="chart">
                <div class="mark" style="left:{$deprLeft}%"><span>{$analysis->declaration->deprecationYear}<br>$deprecationLabel</span></div>
                <div class="mark expiry" style="left:{$expiryLeft}%"><span>{$analysis->declaration->expiryYear}<br>$expiryLabel</span></div>
                $bars
              </div>
              <p class="legend">$legend</p>
              $dates
            </section>
            HTML;
    }
}
