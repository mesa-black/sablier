<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The report is the product.
 *
 * One self-contained HTML file: no external font, no script, no image, no call
 * to anything. A tool that reads where the keys are must not open a socket to
 * render its own output — and it makes the file safe to send as an attachment.
 */
final class Report
{
    /** @param list<Finding> $findings */
    public function __construct(
        private readonly array $findings,
        private readonly Declaration $declaration,
        private readonly string $target,
        private readonly int $filesRead,
        /** @var list<string> */
        private readonly array $blindSpots,
        private readonly int $currentYear,
    ) {
    }

    public function html(): string
    {
        $byVerdict = [];
        foreach (Assessor::order() as $verdict) {
            $byVerdict[$verdict] = [];
        }
        foreach ($this->findings as $finding) {
            $byVerdict[$finding->verdict][] = $finding;
        }

        $compromised = \count($byVerdict[Assessor::COMPROMISED]);
        $urgent = \count($byVerdict[Assessor::URGENT]);
        $actionable = \count($this->findings) - \count($byVerdict[Assessor::NOISE]);

        $headline = $compromised > 0
            ? \sprintf(
                '%d usage%s cryptographique%s protège%s des données dont la confidentialité doit durer au-delà de la péremption de l\'algorithme qui les protège.',
                $compromised, $compromised > 1 ? 's' : '', $compromised > 1 ? 's' : '', $compromised > 1 ? 'nt' : '',
            )
            : ($urgent > 0
                ? \sprintf('Aucune donnée à longue durée n\'est exposée à la récolte, mais %d usage%s repose%s sur un algorithme déjà cassé aujourd\'hui.', $urgent, $urgent > 1 ? 's' : '', $urgent > 1 ? 'nt' : '')
                : 'Aucune donnée dont la durée de confidentialité dépasse la péremption des algorithmes qui la protègent.');

        $rows = '';
        foreach ($byVerdict as $verdict => $group) {
            if ($group === []) {
                continue;
            }
            $rows .= $this->section($verdict, $group);
        }

        $timeline = $this->timeline();
        $blind = $this->blind($byVerdict[Assessor::DECLARE] ?? []);
        $css = $this->css();
        $target = htmlspecialchars($this->target);
        $date = (new \DateTimeImmutable())->format('d/m/Y');
        $project = htmlspecialchars($this->declaration->project !== '' ? $this->declaration->project : basename($this->target));

        return <<<HTML
            <!DOCTYPE html>
            <html lang="fr"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sablier — $project</title>
            <style>$css</style></head>
            <body>
            <header>
              <div class="brand">SABLIER</div>
              <div class="meta">$project · $date · $this->filesRead fichiers lus</div>
            </header>

            <p class="headline">$headline</p>
            <p class="sub">$actionable constats retenus sur l'ensemble analysé. Date de péremption retenue : <strong>{$this->declaration->expiryYear}</strong> — c'est l'échéance réglementaire, pas une prédiction de rupture cryptographique.</p>

            $timeline
            $rows
            $blind

            <footer>
              Sablier n'envoie rien, n'enregistre rien et ne dépend de rien. Ce fichier ne
              charge aucune ressource externe : il peut être lu hors ligne et transmis tel quel.
            </footer>
            </body></html>
            HTML;
    }

    private function timeline(): string
    {
        // One bar per declared domain: how long its data must stay secret,
        // against the date its protection expires.
        $start = $this->currentYear;
        $end = max($this->declaration->expiryYear + 5, $start + 20);
        $span = $end - $start;

        // A long lifetime is not by itself an exposure: it only becomes one when
        // a harvestable algorithm protects that domain. Colouring the bar on the
        // duration alone made the chart contradict the verdict above it.
        $domains = [];
        $exposed = [];
        foreach ($this->findings as $finding) {
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

        $expiryLeft = round((($this->declaration->expiryYear - $start) / $span) * 100, 2);
        $deprLeft = round((($this->declaration->deprecationYear - $start) / $span) * 100, 2);

        $bars = '';
        foreach (\array_slice($domains, 0, 8, true) as $name => $lifetime) {
            $width = min(100, round(($lifetime / $span) * 100, 2));
            $over = $exposed[$name] ?? false;
            $bars .= \sprintf(
                '<div class="row"><div class="lbl">%s</div><div class="track"><div class="bar %s" style="width:%s%%"></div></div><div class="yrs">%d %s</div></div>',
                htmlspecialchars($name), $over ? 'over' : '', $width, $lifetime, $lifetime > 1 ? 'ans' : 'an',
            );
        }

        return <<<HTML
            <section class="timeline">
              <h2>Durée de confidentialité des données, face à la péremption des algorithmes</h2>
              <div class="chart">
                <div class="mark" style="left:{$deprLeft}%"><span>{$this->declaration->deprecationYear}<br>dépréciation</span></div>
                <div class="mark expiry" style="left:{$expiryLeft}%"><span>{$this->declaration->expiryYear}<br>péremption</span></div>
                $bars
              </div>
              <p class="legend">Chaque barre est la durée pendant laquelle la donnée doit rester confidentielle. Elle passe en rouge quand un algorithme récoltable la protège au-delà du trait de péremption — dépasser le trait sans être rouge signifie que la donnée dure longtemps, mais qu'elle est protégée par de la cryptographie qui tiendra.</p>
            </section>
            HTML;
    }

    /** @param list<Finding> $group */
    private function section(string $verdict, array $group): string
    {
        $slug = strtolower(preg_replace('/[^a-z]+/i', '-', $verdict) ?? '');

        // What is fine gets counted, not enumerated. The first scan of a real
        // project produced twenty-two identical SHA-256 rows above four findings
        // that mattered — a report that buries its own signal is a failed report.
        if (\in_array($verdict, [Assessor::CLEAR, Assessor::NOISE], true)) {
            return $this->summarised($verdict, $slug, $group);
        }

        $items = '';
        foreach ($group as $finding) {
            $detail = $finding->detail !== '' ? '<span class="detail">'.htmlspecialchars($finding->detail).'</span>' : '';
            $algo = Catalogue::get($finding->algorithm);
            $fix = ($algo['replacement'] ?? '') !== ''
                ? '<div class="fix"><span>Remplacement</span> '.htmlspecialchars($algo['replacement']).'</div>'
                : '';
            $conf = $finding->confidence === Finding::CONFIDENCE_MEDIUM ? '<span class="conf">confiance moyenne</span>' : '';

            $items .= \sprintf(
                '<article><h3>%s <span class="dom">%s</span> %s</h3>
                 <div class="loc">%s:%d</div>
                 <pre>%s</pre>
                 <p>%s %s</p>%s</article>',
                htmlspecialchars(Catalogue::label($finding->algorithm)),
                htmlspecialchars($finding->domain),
                $conf,
                htmlspecialchars($finding->file),
                $finding->line,
                htmlspecialchars(mb_strimwidth($finding->evidence, 0, 160, '…')),
                htmlspecialchars($finding->because),
                $detail,
                $fix,
            );
        }

        return \sprintf(
            '<section class="verdict %s"><h2>%s <span class="count">%d</span></h2>%s</section>',
            $slug, htmlspecialchars($verdict), \count($group), $items,
        );
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
                '<details><summary><strong>%s</strong> · %d usage%s <span class="dom">%s</span></summary><ul class="files">%s</ul></details>',
                htmlspecialchars(Catalogue::label((string) $algorithm)),
                \count($items),
                \count($items) > 1 ? 's' : '',
                htmlspecialchars($note),
                implode('', array_map(static fn (string $f): string => '<li>'.htmlspecialchars($f).'</li>', \array_slice($files, 0, 40))),
            );
        }

        return \sprintf(
            '<section class="verdict %s summary"><h2>%s <span class="count">%d</span></h2>%s</section>',
            $slug, htmlspecialchars($verdict), \count($group), $rows,
        );
    }

    /** @param list<Finding> $undetermined */
    private function blind(array $undetermined): string
    {
        $lines = [
            "la cryptographie de vos services gérés — base de données, stockage objet, terminaison TLS chez un intermédiaire — n'apparaît dans aucun fichier de ce dépôt",
            "ce qui est réellement négocié à l'exécution : seule une sonde active face au vrai serveur peut le dire",
            'les clés détenues dans un HSM ou chez un fournisseur',
            "la durée de vie réelle des données : elle vient de votre déclaration, pas du code — un domaine non déclaré est calculé avec une durée par défaut de {$this->declaration->defaultLifetime} ans",
        ];
        if ($undetermined !== []) {
            $lines[] = \sprintf('%d usage%s où l\'algorithme vient d\'une variable : listés ci-dessus, à confirmer à la main', \count($undetermined), \count($undetermined) > 1 ? 's' : '');
        }
        foreach ($this->blindSpots as $spot) {
            $lines[] = $spot;
        }

        $items = implode('', array_map(static fn (string $l): string => '<li>'.htmlspecialchars($l).'</li>', $lines));

        return '<section class="blind"><h2>Ce que ce rapport n\'a pas regardé</h2><ul>'.$items.'</ul>
            <p>Un inventaire qui ne dit pas ce qu\'il n\'a pas vu n\'est pas un inventaire.</p></section>';
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
            .brand{font-weight:700;letter-spacing:.22em;font-size:.95rem}
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
            .verdict.compromis h2 .count,.verdict.cass-aujourd-hui h2 .count{background:var(--bad)}
            .verdict.-migrer h2 .count{background:var(--warn)}
            .blind{border:1px solid var(--line);border-radius:3px;padding:1.1rem 1.3rem;margin-top:3rem;background:#00000004}
            .blind h2{margin-top:0}
            .blind ul{margin:0;padding-left:1.1rem}
            .blind li{margin-bottom:.4rem}
            .blind p{color:var(--muted);font-size:.85rem;margin:.9rem 0 0}
            .summary details{border-top:1px solid var(--line);padding:.6rem 0}
            .summary summary{cursor:pointer;font-size:.92rem}
            .summary .dom{margin-left:.4rem}
            .files{margin:.6rem 0 0;padding-left:1.1rem;font-family:ui-monospace,Menlo,monospace;font-size:.74rem;color:var(--muted)}
            footer{margin-top:3rem;border-top:1px solid var(--line);padding-top:1rem;color:var(--muted);font-size:.8rem}
            CSS;
    }
}
