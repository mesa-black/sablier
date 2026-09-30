<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\Analysis;
use Sablier\Assessor;
use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;

/**
 * The report is the product.
 *
 * One self-contained HTML file: no external font, no script, no image, no call
 * to anything. A tool that reads where the keys are must not open a socket to
 * render its own output — and it makes the file safe to send as an attachment.
 */
final class HtmlReporter implements Reporter
{
    public function render(Analysis $analysis): string
    {
        $this->analysis = $analysis;

        return $this->html();
    }

    private Analysis $analysis;

    private function html(): string
    {
        $byVerdict = [];
        foreach (Assessor::order() as $verdict) {
            $byVerdict[$verdict] = [];
        }
        foreach ($this->analysis->findings as $finding) {
            $byVerdict[$finding->verdict][] = $finding;
        }

        $compromised = \count($byVerdict[Assessor::COMPROMISED]);
        $urgent = \count($byVerdict[Assessor::URGENT]);
        $actionable = \count($this->analysis->findings) - \count($byVerdict[Assessor::NOISE]);

        $headline = $compromised > 0
            ? Lang::t($compromised > 1 ? 'headline.compromised.plural' : 'headline.compromised', $compromised)
            : ($urgent > 0
                ? Lang::t($urgent > 1 ? 'headline.urgent.plural' : 'headline.urgent', $urgent)
                : Lang::t('headline.clear'));

        $rows = '';
        foreach ($byVerdict as $verdict => $group) {
            if ($group === []) {
                continue;
            }
            $rows .= $this->section($verdict, $group);
        }

        $elapsed = $this->analysis->duration < 1
            ? number_format($this->analysis->duration * 1000, 0, ',', ' ').' ms'
            : number_format($this->analysis->duration, 1, ',', ' ').' s';
        $logo = self::logo();
        $projection = $this->analysis->projected
            ? '<p class="projection">'.htmlspecialchars(Lang::t('report.projection', $this->analysis->currentYear)).'</p>'
            : '';
        $probeBlock = $this->probeBlock();
        $timeline = $this->timeline();
        $blind = $this->blind($byVerdict[Assessor::DECLARE] ?? []);
        $css = $this->css();
        $target = htmlspecialchars($this->analysis->target);
        $date = (new \DateTimeImmutable())->format('d/m/Y');
        $project = htmlspecialchars($this->analysis->declaration->project !== '' ? $this->analysis->declaration->project : basename($this->analysis->target));

        $lang = Lang::locale();
        $about = Lang::t('about.tool');
        $pq = Lang::t('about.postquantum');
        $declaration = $this->analysis->declaration;
        $checked = \DateTimeImmutable::createFromFormat('Y-m-d', $declaration->deadlinesCheckedOn);
        $subtitle = Lang::t('report.subtitle', $actionable, $declaration->expiryYear)
            .' '.Lang::t('report.deadline_checked', $checked === false ? $declaration->deadlinesCheckedOn : $checked->format('d/m/Y'))
            .($declaration->deadlinesAreStale() ? ' <strong class="stale">'.htmlspecialchars(Lang::t('report.deadline_stale', $declaration->monthsSinceCheck())).'</strong>' : '');
        $footer = Lang::t('report.footer');
        $filesLabel = Lang::t('report.files_read', $this->analysis->filesRead);
        $elapsedLabel = Lang::t('report.elapsed', $elapsed);

        return <<<HTML
            <!DOCTYPE html>
            <html lang="$lang"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sablier — $project</title>
            <style>$css</style></head>
            <body>
            <header>
              <div class="brand">$logo<span>SABLIER</span></div>
              <div class="meta">$project · $date · $filesLabel · $elapsedLabel</div>
            </header>

            <div class="about">$pq</div>
            <div class="about">$about</div>

            $projection
            <p class="headline">$headline</p>
            <p class="sub">$subtitle</p>

            $timeline
            $probeBlock
            $rows
            $blind

            <footer>$footer</footer>
            </body></html>
            HTML;
    }

    /**
     * The mark. Inline, geometric, drawn in currentColor so it holds in both
     * themes and on paper — an external image would be the one request this
     * report promises never to make.
     *
     * The top funnel is half drained and the bottom one has a pile: which is the
     * product's whole argument, that what matters is how much time is left for
     * this particular data, not whether it is encrypted.
     */
    private static function logo(): string
    {
        return <<<'SVG'
            <svg class="logo" viewBox="0 0 22 30" width="20" height="27" aria-hidden="true" focusable="false">
              <g fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round">
                <path d="M1.6 1.2h18.8M1.6 28.8h18.8"/>
                <path d="M3.4 3.4h15.2L11 14.6z"/>
                <path d="M11 15.4l7.6 11.2H3.4z"/>
              </g>
              <path fill="currentColor" d="M6 6h10l-2.8 4.2H8.8z"/>
              <path fill="currentColor" d="M11 20.4l3.4 6.2H7.6z"/>
              <path fill="currentColor" d="M10.3 16.4h1.4v2.6h-1.4z"/>
            </svg>
            SVG;
    }

    private function timeline(): string
    {
        // One bar per declared domain: how long its data must stay secret,
        // against the date its protection expires.
        $start = $this->analysis->currentYear;
        $end = max($this->analysis->declaration->expiryYear + 5, $start + 20);
        $span = $end - $start;

        // A long lifetime is not by itself an exposure: it only becomes one when
        // a harvestable algorithm protects that domain. Colouring the bar on the
        // duration alone made the chart contradict the verdict above it.
        $domains = [];
        $exposed = [];
        foreach ($this->analysis->findings as $finding) {
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

        $expiryLeft = round((($this->analysis->declaration->expiryYear - $start) / $span) * 100, 2);
        $deprLeft = round((($this->analysis->declaration->deprecationYear - $start) / $span) * 100, 2);

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
        $deprecationLabel = htmlspecialchars(Lang::t('timeline.deprecation'));
        $expiryLabel = htmlspecialchars(Lang::t('timeline.expiry'));

        return <<<HTML
            <section class="timeline">
              <h2>$title</h2>
              <div class="chart">
                <div class="mark" style="left:{$deprLeft}%"><span>{$this->analysis->declaration->deprecationYear}<br>$deprecationLabel</span></div>
                <div class="mark expiry" style="left:{$expiryLeft}%"><span>{$this->analysis->declaration->expiryYear}<br>$expiryLabel</span></div>
                $bars
              </div>
              <p class="legend">$legend</p>
            </section>
            HTML;
    }

    /** @param list<Finding> $group */
    private function section(string $verdict, array $group): string
    {
        // What is fine gets counted, not enumerated. The first scan of a real
        // project produced twenty-two identical SHA-256 rows above four findings
        // that mattered — a report that buries its own signal is a failed report.
        if (\in_array($verdict, [Assessor::CLEAR, Assessor::NOISE], true)) {
            return $this->summarised($verdict, $verdict, $group);
        }

        $items = '';
        foreach ($group as $finding) {
            $algo = Catalogue::get($finding->algorithm);
            $detail = $finding->detail !== '' ? '<span class="detail">'.htmlspecialchars($finding->detail).'</span>' : '';
            $fix = ($algo['replacement'] ?? '') !== ''
                ? '<div class="fix"><span>'.htmlspecialchars(Lang::t('label.replacement')).'</span> '.htmlspecialchars($algo['replacement']).'</div>'
                : '';
            $confidence = $finding->confidence === Finding::CONFIDENCE_MEDIUM
                ? '<span class="conf">'.htmlspecialchars(Lang::t('label.medium_confidence')).'</span>'
                : '';

            $items .= \sprintf(
                '<article><h3>%s <span class="dom">%s</span> %s</h3>
                 <div class="loc">%s</div>
                 <pre>%s</pre>
                 <p>%s %s</p>%s</article>',
                htmlspecialchars(Catalogue::label($finding->algorithm)),
                htmlspecialchars($finding->domain),
                $confidence,
                htmlspecialchars($finding->file.($finding->line > 0 ? ':'.$finding->line : '')),
                htmlspecialchars(mb_strimwidth($finding->evidence, 0, 160, '…')),
                htmlspecialchars($finding->because),
                $detail,
                $fix,
            );
        }

        return \sprintf(
            '<section class="verdict %s"><h2>%s <span class="count">%d</span></h2>%s</section>',
            $verdict, htmlspecialchars(Assessor::label($verdict)), \count($group), $items,
        );
    }

    private function probeBlock(): string
    {
        if ($this->analysis->probes === []) {
            return '';
        }

        $blocks = '';
        foreach ($this->analysis->probes as $probe) {
            $rows = '';
            foreach ($probe['facts'] as $key => $value) {
                $rows .= '<div><dt>'.htmlspecialchars((string) $key).'</dt><dd>'.htmlspecialchars($value).'</dd></div>';
            }
            $notes = '';
            foreach ($probe['notes'] as $note) {
                $notes .= '<li>'.htmlspecialchars($note).'</li>';
            }

            $blocks .= \sprintf(
                '<div class="probe"><h3>%s</h3><dl>%s</dl>%s</div>',
                htmlspecialchars($probe['target']),
                $rows,
                $notes !== '' ? '<ul class="probe-notes">'.$notes.'</ul>' : '',
            );
        }

        return '<section class="probes"><h2>'.htmlspecialchars(Lang::t('probe.title')).'</h2>'.$blocks
            .'<p class="legend">'.htmlspecialchars(Lang::t('probe.legend')).'</p></section>';
    }

    /**
     * @param list<Finding> $group
     */
    private function summarised(string $verdict, string $slug, array $group): string
    {
        $byAlgorithm = [];
        foreach ($group as $finding) {
            $byAlgorithm[$finding->algorithm][] = $finding;
        }
        uasort($byAlgorithm, static fn (array $a, array $b): int => \count($b) <=> \count($a));

        $rows = '';
        foreach ($byAlgorithm as $algorithm => $items) {
            $files = array_unique(array_map(static fn (Finding $f): string => $f->file.':'.$f->line, $items));
            sort($files);
            $note = $items[0]->because;
            $rows .= \sprintf(
                '<details><summary><strong>%s</strong> · %d %s <span class="dom">%s</span></summary><ul class="files">%s</ul></details>',
                htmlspecialchars(Catalogue::label((string) $algorithm)),
                \count($items),
                Lang::t(\count($items) > 1 ? 'unit.uses' : 'unit.use'),
                htmlspecialchars($note),
                implode('', array_map(static fn (string $f): string => '<li>'.htmlspecialchars($f).'</li>', \array_slice($files, 0, 40))),
            );
        }

        return \sprintf(
            '<section class="verdict %s summary"><h2>%s <span class="count">%d</span></h2>%s</section>',
            $slug, htmlspecialchars(Assessor::label($verdict)), \count($group), $rows,
        );
    }

    /** @param list<Finding> $undetermined */
    private function blind(array $undetermined): string
    {
        $lines = [
            Lang::t('blind.managed_services'),
            Lang::t('blind.runtime'),
            Lang::t('blind.hsm'),
            Lang::t('blind.lifetime', $this->analysis->declaration->defaultLifetime),
        ];
        if ($undetermined !== []) {
            $lines[] = Lang::t(\count($undetermined) > 1 ? 'blind.undetermined.plural' : 'blind.undetermined', \count($undetermined));
        }
        foreach ($this->analysis->blindSpots as $spot) {
            $lines[] = $spot;
        }

        $items = implode('', array_map(static fn (string $l): string => '<li>'.htmlspecialchars($l).'</li>', $lines));

        return '<section class="blind"><h2>'.htmlspecialchars(Lang::t('blind.title')).'</h2><ul>'.$items.'</ul>
            <p>'.htmlspecialchars(Lang::t('blind.motto')).'</p></section>';
    }

    private function css(): string
    {
        return <<<'CSS'
            :root{--ink:#16181d;--muted:#5d6470;--paper:#fbfaf8;--line:#e5e2dc;--bad:#a3281f;--warn:#9a5b10;--ok:#1d6b4f;--cool:#2a4c7d;--sand:#c8a44a}
            @media (prefers-color-scheme:dark){:root{--ink:#e8e6e1;--muted:#9aa0aa;--paper:#14161a;--line:#2b2f36;
                --bad:#e0685c;--warn:#d69a4a;--ok:#5fbb92;--cool:#7aa2d8}}
            *{box-sizing:border-box}
            body{margin:0;padding:2.5rem 1.25rem 4rem;background:var(--paper);color:var(--ink);
                 font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
                 max-width:52rem;margin-inline:auto}
            header{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap;
                   border-bottom:2px solid var(--ink);padding-bottom:.6rem;margin-bottom:2rem}
            .brand{font-weight:700;letter-spacing:.22em;font-size:.95rem;
                   display:flex;align-items:center;gap:.6rem}
            .logo{flex:none;display:block}
            .meta{color:var(--muted);font-size:.82rem}
            .headline{font-size:1.5rem;line-height:1.32;font-weight:500;margin:0 0 .8rem;text-wrap:balance}
            .sub{color:var(--muted);margin:0 0 2.4rem;font-size:.92rem}
            h2{font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);
               margin:2.6rem 0 1rem;font-weight:600}
            .count{background:var(--ink);color:var(--paper);border-radius:2px;padding:.05em .45em;font-size:.9em;letter-spacing:0}
            .timeline .chart{position:relative;border-left:1px solid var(--line);padding:1.8rem 0 .4rem}
            .mark{position:absolute;top:0;bottom:0;border-left:1px dashed var(--muted);padding-left:.4rem}
            .mark.expiry{border-left:2px solid var(--bad)}
            .mark span{font-size:.68rem;color:var(--muted);line-height:1.2;display:block}
            .mark.expiry span{color:var(--bad)}
            .row{display:grid;grid-template-columns:9rem 1fr 4rem;gap:.6rem;align-items:center;margin:.35rem 0}
            .lbl{font-size:.8rem;color:var(--muted);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
            .track{background:#00000008;height:14px;border-radius:2px;position:relative}
            .bar{height:100%;background:var(--cool);border-radius:2px}
            .bar.over{background:var(--bad)}
            .yrs{font-size:.72rem;color:var(--muted);font-variant-numeric:tabular-nums}
            .legend{font-size:.8rem;color:var(--muted);margin:.8rem 0 0}
            article{border-top:1px solid var(--line);padding:1rem 0}
            article h3{margin:0 0 .3rem;font-size:1rem;font-weight:600;display:flex;gap:.55rem;align-items:baseline;flex-wrap:wrap}
            .dom{font-weight:400;color:var(--muted);font-size:.82rem}
            .conf{font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;color:var(--warn);border:1px solid currentColor;border-radius:2px;padding:.05em .35em}
            .loc{font-family:ui-monospace,Menlo,monospace;font-size:.76rem;color:var(--muted)}
            pre{font-family:ui-monospace,Menlo,monospace;font-size:.76rem;background:#00000006;border:1px solid var(--line);
                border-radius:2px;padding:.5rem .6rem;overflow-x:auto;margin:.5rem 0}
            article p{margin:.4rem 0 0}
            .detail{color:var(--muted)}
            .fix{margin-top:.5rem;font-size:.85rem}
            .fix span{font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--ok);margin-right:.4rem}
            .verdict.compromised h2 .count,.verdict.urgent h2 .count{background:var(--bad)}
            .verdict.migrate h2 .count{background:var(--warn)}
            .blind{border:1px solid var(--line);border-radius:3px;padding:1.1rem 1.3rem;margin-top:3rem;background:#00000004}
            .blind h2{margin-top:0}
            .blind ul{margin:0;padding-left:1.1rem}
            .blind li{margin-bottom:.4rem}
            .blind p{color:var(--muted);font-size:.85rem;margin:.9rem 0 0}
            .about{border-left:2px solid var(--sand);padding:.1rem 0 .1rem 1rem;margin:0 0 2rem;
                   color:var(--muted);font-size:.88rem;line-height:1.55;
                   text-align:justify;hyphens:auto;-webkit-hyphens:auto}
            @media (max-width:34rem){.about{text-align:left;hyphens:manual}}
            .about strong{color:var(--ink)}
            .stale{color:var(--warn)}
            .projection{border:1px solid var(--warn);color:var(--warn);border-radius:3px;
                        padding:.6rem .85rem;margin:0 0 1.4rem;font-size:.86rem}
            .probe{border-top:1px solid var(--line);padding:.9rem 0}
            .probe h3{margin:0 0 .5rem;font-family:ui-monospace,Menlo,monospace;font-size:.85rem;font-weight:600}
            .probe dl{margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:.35rem 1.2rem}
            .probe dt{font-size:.68rem;letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
            .probe dd{margin:0 0 .3rem;font-size:.88rem;font-variant-numeric:tabular-nums}
            .probe-notes{margin:.7rem 0 0;padding-left:1.1rem;font-size:.82rem;color:var(--warn)}
            .summary details{border-top:1px solid var(--line);padding:.6rem 0}
            .summary summary{cursor:pointer;font-size:.92rem}
            .summary .dom{margin-left:.4rem}
            .files{margin:.6rem 0 0;padding-left:1.1rem;font-family:ui-monospace,Menlo,monospace;font-size:.74rem;color:var(--muted)}
            footer{margin-top:3rem;border-top:1px solid var(--line);padding-top:1rem;color:var(--muted);font-size:.8rem}

            /* Print, and therefore PDF. The palette is forced back to light: a
               report printed on a dark ground wastes ink and is unreadable on
               paper, and the viewer's theme must not follow the file to the
               printer. */
            @page{margin:18mm 15mm}
            @media print{
                :root{--ink:#16181d;--muted:#55595f;--paper:#fff;--line:#d9d6d0;
                      --bad:#8f241c;--warn:#8a5210;--ok:#1a5f46;--cool:#2a4c7d;--sand:#bb9a45}
                body{max-width:none;margin:0;padding:0;font-size:10.5pt;background:#fff}
                header{border-bottom-width:1.5pt}
                .headline{font-size:1.25rem}
                section,article,details,.probe{break-inside:avoid}
                h2{break-after:avoid}
                .timeline,.probes,.blind{break-inside:avoid}
                .blind{background:none}
                /* At 10.5pt the label column is too narrow and the names run
                   into the bars: give them room, not a smaller size. */
                .row{grid-template-columns:11.5rem 1fr 3.4rem;gap:.5rem}
                .lbl{font-size:.74rem}
                .summary details{display:block}
                .summary details>summary{list-style:none}
                .files{display:none}
                pre{white-space:pre-wrap;word-break:break-word}
                footer{break-before:avoid}
            }
            CSS;
    }
}
