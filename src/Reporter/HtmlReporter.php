<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\ActionPlan;
use Sablier\Analysis;
use Sablier\Assessor;
use Sablier\BlindSpots;
use Sablier\Breach;
use Sablier\Catalogue;
use Sablier\Effort;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\Signature;

/**
 * The report is the product.
 *
 * One self-contained HTML file: no external font, no script, no image, no call
 * to anything. A tool that reads where the keys are must not open a socket to
 * render its own output — and it makes the file safe to send as an attachment.
 */
final class HtmlReporter implements ReporterInterface
{
    /** Where a rule defect goes. The tool's own repository, not the reader's. */
    private const string ISSUES_URL = 'https://github.com/mesa-black/sablier/issues/new';

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
        $actionable = \count($this->analysis->findings)
            - \count($byVerdict[Assessor::NOISE])
            - \count($byVerdict[Assessor::ACCEPTED]);

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
        $projection = $this->analysis->projected
            ? '<p class="projection">'.htmlspecialchars(Lang::t('report.projection', $this->analysis->currentYear)).'</p>'
            : '';
        // An imported inventory must never be mistaken for one this tool read
        // itself: two reports that look the same and were produced differently
        // is how a reader ends up trusting the wrong one. Same prominence as
        // the projection banner, for the same reason.
        $imported = $this->analysis->importedFrom !== ''
            ? '<p class="imported">'.htmlspecialchars(Lang::t('report.imported_banner', $this->analysis->importedFrom)).'</p>'
            : '';
        $seal = $this->seal();
        $plan = $this->actionPlan($headline, $actionable);
        $fpLegend = $this->analysis->findings === [] ? '' : $this->falsePositiveLegend();
        $probeBlock = $this->probeBlock();
        $timeline = Breach::render($this->analysis).Timeline::render($this->analysis);
        // Deliberately in this document only. The audit report's sections are
        // numbered and get cited by number; adding one would renumber a
        // document somebody has already quoted. This is also the half of the
        // analysis a team plans with rather than argues over.
        $effort = Effort::render($this->analysis);
        $blind = $this->blind();
        $css = $this->css();
        $target = htmlspecialchars($this->analysis->target);
        $date = (new \DateTimeImmutable())->format('d/m/Y');
        $project = htmlspecialchars($this->analysis->declaration->project !== '' ? $this->analysis->declaration->project : basename($this->analysis->target));

        $titleTag = $this->analysis->importedFrom !== '' ? ' · '.Lang::t('report.imported_tag') : '';
        $lang = Lang::locale();
        $about = Lang::t('about.tool');
        $pq = Lang::t('about.postquantum');
        $declaration = $this->analysis->declaration;
        $checked = \DateTimeImmutable::createFromFormat('Y-m-d', $declaration->deadlinesCheckedOn);
        $subtitle = Lang::t('report.subtitle', $actionable, $declaration->expiryYear)
            .' '.Lang::t('report.deadline_checked', $checked === false ? $declaration->deadlinesCheckedOn : $checked->format('d/m/Y'))
            .($declaration->deadlinesAreStale() ? ' <strong class="stale">'.htmlspecialchars(Lang::t('report.deadline_stale', $declaration->monthsSinceCheck())).'</strong>' : '');
        $footer = Lang::t('report.footer');
        $filesLabel = $this->analysis->importedFrom !== ''
            ? Lang::t('report.imported_from', $this->analysis->importedFrom, $this->analysis->filesRead)
            : Lang::t('report.files_read', $this->analysis->filesRead);
        $elapsedLabel = Lang::t('report.elapsed', $elapsed);

        return <<<HTML
            <!DOCTYPE html>
            <html lang="$lang"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sablier — $project$titleTag</title>
            <style>$css</style></head>
            <body>
            <header>
              <div class="brand">SABLIER</div>
              <div class="meta">$project · $date · $filesLabel · $elapsedLabel</div>
            </header>

            <div class="about">$pq</div>
            <div class="about">$about</div>

            $imported
            $projection
            <p class="headline">$headline</p>
            <p class="sub">$subtitle</p>

            $timeline
            $probeBlock
            $rows
            $blind
            $effort
            $plan
            $fpLegend

            $seal
            <footer>$footer</footer>
            </body></html>
            HTML;
    }

    /**
     * The conclusion. Data is not a decision, and a report that stops at
     * findings hands the arbitration back to a reader who will postpone it.
     */
    private function actionPlan(string $headline, int $actionable): string
    {
        $actions = ActionPlan::for($this->analysis);

        $items = '';
        $number = 0;
        foreach ($actions as $action) {
            ++$number;
            $items .= \sprintf(
                '<li><h3>%s</h3><p>%s</p></li>',
                htmlspecialchars($action['title']),
                htmlspecialchars($action['body']),
            );
        }

        $project = $this->analysis->declaration->project !== ''
            ? $this->analysis->declaration->project
            : basename($this->analysis->target);

        // The share link carries plain text and opens a local application. No
        // third party sees it, which is the only kind of sharing this tool can
        // offer without contradicting its own footer.
        $summary = Lang::t(
            'share.text',
            $project,
            (new \DateTimeImmutable())->format('d/m/Y'),
            strip_tags($headline),
            $actionable,
            $this->analysis->declaration->expiryYear,
            $actions[0]['title'],
        );
        // The scheme is the phone's. A desktop that has never registered it
        // answers with a browser error nobody can act on, so the text it would
        // have carried is printed right there, to be copied by hand.
        $href = 'threema://compose?text='.rawurlencode($summary);

        $title = htmlspecialchars(Lang::t('plan.title'));
        $intro = htmlspecialchars(Lang::t('plan.intro'));
        $share = htmlspecialchars(Lang::t('share.threema'));
        $note = htmlspecialchars(Lang::t('share.note'));
        $reveal = htmlspecialchars(Lang::t('share.reveal'));
        $text = htmlspecialchars($summary);

        return <<<HTML
            <section class="plan">
              <h2>$title</h2>
              <p class="legend">$intro</p>
              <ol>$items</ol>
              <p class="share"><a href="$href">$share</a></p>
              <p class="share-note">$note</p>
              <details class="share-text"><summary>$reveal</summary><pre>$text</pre></details>
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
            if ($verdict === Assessor::ACCEPTED) {
                $items .= \sprintf(
                    '<article class="accepted"><h3>%s <span class="dom">%s</span></h3>
                     <div class="loc">%s · %s</div>
                     <p>%s</p>
                     <div class="fix"><span>%s</span> %s &nbsp;·&nbsp; <span>%s</span> %s</div></article>',
                    htmlspecialchars(Catalogue::label($finding->algorithm)),
                    htmlspecialchars($finding->domain),
                    htmlspecialchars($finding->file.($finding->line > 0 ? ':'.$finding->line : '')),
                    htmlspecialchars(Lang::t('label.fingerprint').' '.$finding->fingerprint()),
                    htmlspecialchars($finding->because),
                    htmlspecialchars(Lang::t('accepted.reason')),
                    htmlspecialchars($finding->acceptedReason),
                    htmlspecialchars(Lang::t('accepted.until')),
                    htmlspecialchars($finding->acceptedUntil),
                );
                continue;
            }

            $algo = Catalogue::get($finding->algorithm);
            $detail = $finding->detail !== '' ? '<span class="detail">'.htmlspecialchars($finding->detail).'</span>' : '';
            $fix = ($algo['replacement'] ?? '') !== ''
                ? '<div class="fix"><span>'.htmlspecialchars(Lang::t('label.replacement')).'</span> '.htmlspecialchars($algo['replacement']).'</div>'
                : '';
            // A published defect is checkable by whoever reads this; the
            // post-quantum deadline is not one, and is cited as a deadline.
            $references = self::references($finding);
            $confidence = $finding->confidence === Finding::CONFIDENCE_MEDIUM
                ? '<span class="conf">'.htmlspecialchars(Lang::t('label.medium_confidence')).'</span>'
                : '';

            $items .= \sprintf(
                '<article><h3>%s <span class="dom">%s</span> %s</h3>
                 <div class="loc">%s</div>
                 <pre>%s</pre>
                 <p>%s %s</p>%s%s</article>',
                htmlspecialchars(Catalogue::label($finding->algorithm)),
                htmlspecialchars($finding->domain),
                $confidence,
                htmlspecialchars($finding->file.($finding->line > 0 ? ':'.$finding->line : '')),
                htmlspecialchars(mb_strimwidth($finding->evidence, 0, 160, '…')),
                htmlspecialchars($finding->because),
                $detail,
                $references,
                $fix.$this->falsePositive($finding),
            );
        }

        return \sprintf(
            '<section class="verdict %s"><h2>%s <span class="count">%d</span></h2>%s</section>',
            $verdict, htmlspecialchars(Assessor::label($verdict)), \count($group), $items,
        );
    }

    /** The CVE numbers behind a verdict, linked where a reader can check them. */
    private static function references(Finding $finding): string
    {
        $references = $finding->references();
        if ($references === []) {
            return '';
        }

        $links = array_map(
            static fn (string $reference): string => \sprintf(
                '<a href="%s">%s</a>',
                htmlspecialchars(Catalogue::referenceUrl($reference)),
                htmlspecialchars($reference),
            ),
            $references,
        );

        return '<div class="fix"><span>'.htmlspecialchars(Lang::t('label.references')).'</span> '.implode(' · ', $links).'</div>';
    }

    /**
     * Per finding: the two commands, and nothing else.
     *
     * The explanation lives in the legend, once. Printing it under all
     * twenty findings taught the reader nothing by the third one and buried
     * the only part that differs — the fingerprint, and the two lines that
     * carry it.
     *
     * Nothing here sends anything: the acceptance is a block of text to paste
     * into a versioned file, and the report link opens the reader's browser on
     * a form they fill in themselves. The footer's promise survives.
     */
    private function falsePositive(Finding $finding): string
    {
        $fingerprint = $finding->fingerprint();
        $snippet = "\"accepted\": {\n  \"$fingerprint\": {\n    \"reason\": \"…\",\n    \"until\": \"".
            (new \DateTimeImmutable('+6 months'))->format('Y-m-d')."\"\n  }\n}";
        $cli = 'sablier accept '.$fingerprint.' --reason="…" --until='.(new \DateTimeImmutable('+6 months'))->format('Y-m-d');

        $body = \sprintf(
            "Empreinte : %s\nAlgorithme : %s\nVerdict : %s\nFichier : %s:%d\nPreuve : %s\n\nPourquoi ce constat est faux :\n",
            $fingerprint,
            $finding->algorithm,
            Assessor::label($finding->verdict),
            $finding->file,
            $finding->line,
            $finding->evidence,
        );
        $href = self::ISSUES_URL.'?title='.rawurlencode('Faux positif : '.$finding->algorithm.' dans '.basename($finding->file))
            .'&body='.rawurlencode($body).'&labels='.rawurlencode('false-positive');

        return \sprintf(
            '<details class="fp"><summary>%s %s <code>%s</code></summary>
               <p class="fp-lead">%s <code>%s</code></p>
               <pre>%s</pre>
               <p class="fp-lead">%s <a href="%s">%s</a></p>
             </details>',
            htmlspecialchars(Lang::t('falsepositive.title')),
            htmlspecialchars(Lang::t('label.fingerprint')),
            htmlspecialchars($fingerprint),
            htmlspecialchars(Lang::t('falsepositive.accept_lead')),
            htmlspecialchars($cli),
            htmlspecialchars($snippet),
            htmlspecialchars(Lang::t('falsepositive.report_lead')),
            htmlspecialchars($href),
            htmlspecialchars(Lang::t('falsepositive.link')),
        );
    }

    /**
     * What a false positive is, said once.
     *
     * Two things wear the name and they are not settled the same way, so the
     * distinction is stated where a reader can find it — next to the seal,
     * with the fingerprint explained — rather than repeated under every
     * finding until it reads as boilerplate and nobody reads it at all.
     */
    private function falsePositiveLegend(): string
    {
        $placeholder = '<'.Lang::t('label.fingerprint').'>';
        $until = (new \DateTimeImmutable('+6 months'))->format('Y-m-d');
        $snippet = "\"accepted\": {\n  \"$placeholder\": {\n    \"reason\": \"…\",\n    \"until\": \"$until\"\n  }\n}";
        $cli = 'sablier accept '.$placeholder.' --reason="…" --until='.$until;

        return \sprintf(
            '<section class="fp-legend"><h2>%s</h2>
               <p>%s</p>
               <p><strong>1.</strong> %s</p>
               <pre>%s</pre>
               <p class="fp-cli">%s <code>%s</code></p>
               <p><strong>2.</strong> %s <a href="%s">%s</a></p>
               <p class="fp-note">%s</p>
             </section>',
            htmlspecialchars(Lang::t('falsepositive.title')),
            htmlspecialchars(Lang::t('falsepositive.intro')),
            htmlspecialchars(Lang::t('falsepositive.accept')),
            htmlspecialchars($snippet),
            htmlspecialchars(Lang::t('falsepositive.cli')),
            htmlspecialchars($cli),
            htmlspecialchars(Lang::t('falsepositive.report')),
            htmlspecialchars(self::ISSUES_URL),
            'github.com/mesa-black/sablier',
            htmlspecialchars(Lang::t('falsepositive.fingerprint')),
        );
    }

    /**
     * The report's own fingerprint, and the signature over it when there is one.
     *
     * The caveat is printed, not hidden: this tool classifies Ed25519 as
     * quantum-vulnerable, and it signs with Ed25519, because that is what PHP
     * ships. Saying so is the whole point — a signature cannot be harvested, so
     * it holds as long as the curve holds, and the only question that matters
     * is whether this report must still be provable after the expiry year.
     */
    private function seal(): string
    {
        $digest = Signature::digest($this->analysis);
        $rows = '<div><dt>'.htmlspecialchars(Lang::t('seal.digest')).'</dt><dd><code>'.htmlspecialchars($digest).'</code></dd></div>';

        $caveat = '';
        if ($this->analysis->signature !== null) {
            $block = $this->analysis->signature;
            $hybrid = $block['hybrid'] ?? null;
            $signedAt = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $block['signed_at']);
            // Both algorithms, because this block is where a reader decides
            // whether the signature outlives the curve. Naming only the
            // classical half of a hybrid is the report contradicting itself.
            $algorithms = $block['algorithm'].(\is_array($hybrid) ? ' + '.$hybrid['algorithm'] : '');
            $rows .= '<div><dt>'.htmlspecialchars(Lang::t('seal.signed')).'</dt><dd>'
                .htmlspecialchars($algorithms.' · '.($signedAt === false ? $block['signed_at'] : $signedAt->format('d/m/Y H:i'))).'</dd></div>'
                .'<div><dt>'.htmlspecialchars(Lang::t('seal.key')).'</dt><dd><code>'
                .htmlspecialchars(substr($block['public_key'], 0, 16).'…').'</code></dd></div>';

            // A key that signed once and was destroyed ties the document to
            // nobody on its own: the fingerprint is what the reader was given
            // by another road, so it is printed rather than assumed to be at
            // hand.
            if (($block['ephemeral'] ?? false) === true) {
                $rows .= '<div><dt>'.htmlspecialchars(Lang::t('seal.fingerprint')).'</dt><dd><code>'
                    .htmlspecialchars(Signature::fingerprint(
                        $block['public_key'],
                        \is_array($hybrid) ? $hybrid['public_key'] : '',
                    )).'</code></dd></div>';
            }

            $caveat = '<p class="seal-caveat">'.htmlspecialchars(\is_array($hybrid)
                ? Lang::t('seal.hybrid', $hybrid['algorithm'])
                : Lang::t('seal.caveat', $this->analysis->declaration->expiryYear)).'</p>';

            // How to check it, and what checking it establishes. The audit
            // document carried both and this one carried neither, which was
            // tolerable while reports travelled by hand and stopped being so
            // the first time one was published on a website: a reader who
            // arrives at a signed page with no command and no claim has a seal
            // they can admire and cannot use.
            $caveat .= '<p class="legend">'.htmlspecialchars(Lang::t('seal.verify')).' <code>'
                .htmlspecialchars(Lang::t('seal.verify.command')).'</code></p>';

            // And what it proves, which depends on where the expected key
            // lives. A key declared in a versioned file is checkable by its
            // own history; an ephemeral one rests entirely on the channel that
            // carried its fingerprint. Saying neither invites the reader to
            // believe the strongest of the two.
            $caveat .= '<p class="legend">'.htmlspecialchars(($block['ephemeral'] ?? false) === true
                ? Lang::t('seal.proves.ephemeral')
                : ($this->analysis->declaration->signingPublicKey !== ''
                    ? Lang::t('seal.proves.declared')
                    : Lang::t('seal.proves.unvouched'))).'</p>';
        }

        return '<section class="seal"><h2>'.htmlspecialchars(Lang::t('seal.title')).'</h2>'
            .'<dl class="probe-facts">'.$rows.'</dl>'
            .'<p class="legend">'.htmlspecialchars(Lang::t('seal.legend')).'</p>'
            .$caveat.'</section>';
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

    private function blind(): string
    {
        $items = implode('', array_map(
            static fn (string $l): string => '<li>'.htmlspecialchars($l).'</li>',
            BlindSpots::for($this->analysis),
        ));

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
            .crossings{margin-top:1.4rem;border-top:1px solid var(--line);padding-top:.9rem}
            .crossings h3{margin:0 0 .5rem;font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
            .crossings ul{margin:0;padding-left:1.1rem;font-size:.88rem}
            .crossings li{margin:.2rem 0}
            .crossings li.past{color:var(--bad)}
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
            .imported{border:1px solid var(--cool);color:var(--cool);border-radius:3px;
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
            .seal{margin-top:2.6rem;border-top:1px solid var(--line);padding-top:1.1rem}
            .seal dl,.probe dl{margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:.35rem 1.2rem}
            .seal dt{font-size:.68rem;letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
            .seal dd{margin:0 0 .3rem;font-size:.84rem;word-break:break-all}
            .seal code{font-family:var(--mono,ui-monospace,Menlo,monospace);font-size:.82em}
            .seal-caveat{border-left:2px solid var(--warn);padding-left:.9rem;color:var(--warn);
                         font-size:.84rem;margin:.9rem 0 0;text-align:justify;hyphens:auto}
            .fp{margin-top:.8rem;font-size:.84rem}
            .fp summary{cursor:pointer;color:var(--muted)}
            .fp summary code{font-size:.92em}
            .fp p{margin:.7rem 0 .2rem}
            .fp-lead{color:var(--muted)}
            .fp-cli{color:var(--muted)}
            .fp-legend{border:1px solid var(--line);border-radius:3px;padding:1.1rem 1.3rem;margin-top:2.6rem;font-size:.86rem}
            .fp-legend h2{margin-top:0}
            .fp-legend p{margin:.8rem 0 .2rem}
            .fp-legend pre{margin:.5rem 0}
            .fp-note{color:var(--muted)}
            .verdict.accepted .count{background:var(--muted)}
            article.accepted h3{opacity:.85}
            .plan{margin-top:3rem;border-top:2px solid var(--ink);padding-top:1.2rem}
            .plan ol{margin:1.4rem 0 0;padding-left:0;list-style:none;counter-reset:step}
            .plan li{counter-increment:step;position:relative;padding:0 0 1.5rem 2.6rem;border-top:1px solid var(--line);padding-top:1.1rem}
            .plan li::before{content:counter(step);position:absolute;left:0;top:1rem;
                             font-variant-numeric:tabular-nums;font-size:.95rem;font-weight:700;color:var(--sand)}
            .plan h3{margin:0 0 .35rem;font-size:1.02rem;font-weight:600}
            .plan p{margin:0;text-align:justify;hyphens:auto;-webkit-hyphens:auto}
            .share{margin:1.4rem 0 .3rem!important}
            .share a{display:inline-block;border:1px solid var(--accent-line,var(--ink));border-radius:3px;
                     padding:.45rem .9rem;text-decoration:none;color:var(--ink);font-size:.88rem}
            .share a:hover{background:var(--ink);color:var(--paper)}
            .share-note{color:var(--muted);font-size:.78rem;margin:0!important}
            @media (max-width:34rem){.plan p{text-align:left;hyphens:manual}}
            .share-text{margin:.5rem 0 0}
            .share-text summary{color:var(--muted);font-size:.78rem;cursor:pointer}
            .share-text pre{white-space:pre-wrap;font-size:.8rem;background:#00000008;
                            border-radius:3px;padding:.7rem .9rem;margin:.5rem 0 0;
                            user-select:all;-webkit-user-select:all}
            @media print{.share,.share-note,.share-text{display:none}}
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
                /* Paper has no disclosure triangle, so a closed <details>
                   prints as a dead question. Unfold them — the browser that
                   makes the PDF is also told to open them, because this
                   pseudo-element is recent and the export must not depend on
                   which Chrome the machine happens to have. The acceptance
                   block is dropped per finding: the legend carries one, and
                   the command line below it carries the fingerprint. */
                details::details-content{content-visibility:visible;block-size:auto}
                .fp,.fp-legend{break-inside:avoid}
                .fp summary{list-style:none}
                .fp pre{display:none}
                pre{white-space:pre-wrap;word-break:break-word}
                footer{break-before:avoid}
            }
            CSS;
    }
}
