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
     * What the two marks on the axis mean.
     *
     * Under a flat regime they are a deprecation and an expiry. Under a graded
     * one they are the end dates of two risk levels, and labelling them
     * "deprecation" would misname somebody else's framework on a chart that
     * cites it.
     */
    private static function markLabel(Analysis $analysis, string $mark): string
    {
        return $analysis->declaration->graded()
            ? Lang::t("timeline.graded.$mark")
            : Lang::t("timeline.$mark");
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

        // The same figure, as data, for a reader that cannot run CSS. The PDF
        // typesetter draws from this rather than measuring inline styles back
        // out of the markup: one computation, two renderings.
        $chart = json_encode([
            'title' => Lang::t('timeline.title'),
            'start' => $start,
            'end' => $end,
            'marks' => [
                ['year' => $analysis->declaration->deprecationYear, 'label' => self::markLabel($analysis, 'deprecation')],
                ['year' => $analysis->declaration->expiryYear, 'label' => self::markLabel($analysis, 'expiry')],
            ],
            'bars' => array_map(
                static fn (string $name, int $lifetime): array => [
                    'name' => $name,
                    'years' => $lifetime,
                    'exposed' => $exposed[$name] ?? false,
                ],
                array_keys(\array_slice($domains, 0, 8, true)),
                array_values(\array_slice($domains, 0, 8, true)),
            ),
        ], \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES);
        // A <template>, not a <script>: inert by specification, and the report
        // can go on saying it carries no script at all — which is a claim worth
        // keeping literally true in a tool that reads where the keys are.
        $chart = '<template id="chart">'.str_replace('<', '&lt;', (string) $chart).'</template>';

        $title = htmlspecialchars(Lang::t('timeline.title'));
        $legend = htmlspecialchars(Lang::t('timeline.legend'));
        $dates = self::crossings($analysis);
        $deprecationLabel = htmlspecialchars(self::markLabel($analysis, 'deprecation'));
        $expiryLabel = htmlspecialchars(self::markLabel($analysis, 'expiry'));

        return <<<HTML
            <section class="timeline">
              <h2>$title</h2>
              $chart
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
