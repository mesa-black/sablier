<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\ActionPlan;
use Sablier\Absences;
use Sablier\Analysis;
use Sablier\Assessor;
use Sablier\BlindSpots;
use Sablier\Breach;
use Sablier\Catalogue;
use Sablier\Effort;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\Rendered;
use Sablier\Signature;
use Sablier\Sky;
use Sablier\OpenTimestamps;
use Sablier\Timestamp;
use Sablier\Version;

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

    /**
     * The anchor of the share button, the same in every language: a link
     * quoted from the French report must still land in the English one.
     */
    public const string SHARE_ID = 'partager';

    /** What a SHA-256 digest weighs, the only part of the findings that ever leaves. */
    private const int DIGEST_BYTES = 32;

    /**
     * What `openssl ts -query -sha256 -cert` produces around those 32 bytes:
     * the algorithm, a random nonce and the request for the certificate.
     * Measured at 69 to 70 bytes (the nonce is a DER integer, so its length
     * moves by one); the footer says "about 70" rather than a range.
     */
    private const int TIMESTAMP_QUERY_BYTES = 70;

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
        $date = Rendered::at();
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
        $footer = $this->footer(str_contains($plan, 'id="'.self::SHARE_ID.'"'));
        $filesLabel = $this->analysis->importedFrom !== ''
            ? Lang::t('report.imported_from', $this->analysis->importedFrom, $this->analysis->filesRead)
            : Lang::t('report.files_read', $this->analysis->filesRead);
        $elapsedLabel = Lang::t('report.elapsed', $elapsed);
        // Beside the name, where software puts its version and where a reader
        // looks for it. It was in the footer, in front of a paragraph that also
        // begins with the word "Sablier" — present, and invisible.
        $build = htmlspecialchars(Version::NUMBER);

        return <<<HTML
            <!DOCTYPE html>
            <html lang="$lang"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sablier — $project$titleTag</title>
            <style>$css</style></head>
            <body>
            <header>
              <div class="brand">SABLIER <span class="build">$build</span></div>
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
     * What this report cost in traffic, said for this report.
     *
     * The footer used to promise that Sablier sends nothing. It stopped being
     * true the day the probe, the timestamps and the anchoring arrived, and a
     * promise a reader can catch out once is a promise they stop believing
     * everywhere. So it now lists what actually left the machine for the run
     * that wrote it — and when nothing did, it says that, which is the strong
     * claim, made only when it holds.
     *
     * "Forwarded as is" points at the two ways the report offers to forward
     * it: the share button above, and the PDF when one was written beside it.
     */
    private function footer(bool $shareSection): string
    {
        $out = [];

        // The probe: a handshake per declared host, the one a browser or an
        // SSH client would make. Hosts, not the declaration: what was dialled.
        $hosts = [];
        $ssh = false;
        foreach ($this->analysis->probes as $probe) {
            $host = explode(' · ', $probe['target'])[0];
            $ssh = $ssh || str_starts_with($host, 'ssh://') || preg_match('/:22$/', $host) === 1;
            $hosts[$host] = true;
        }
        if ($hosts !== []) {
            $out[] = Lang::t(
                'report.footer.out.'.($ssh ? 'probe_ssh' : 'probe').(\count($hosts) > 1 ? '.plural' : ''),
                self::names(array_keys($hosts)),
            );
        }

        // The timestamps: the findings digest, inside an RFC 3161 query.
        $authorities = [];
        foreach ($this->analysis->timestamps as $token) {
            $name = rtrim(trim($token['authority']), '.');
            if ($name !== '') {
                $authorities[$name] = true;
            }
        }
        if ($this->analysis->timestamps !== []) {
            $out[] = Lang::t(
                \count($this->analysis->timestamps) > 1 ? 'report.footer.out.timestamp.plural' : 'report.footer.out.timestamp',
                self::DIGEST_BYTES,
                self::TIMESTAMP_QUERY_BYTES,
                $authorities === [] ? '' : ' ('.self::names(array_keys($authorities)).')',
            );
        }

        // The anchoring: a hash of the digest and a nonce to the calendars,
        // then, once a block is claimed, its height to read the public header.
        $anchor = $this->analysis->anchor;
        if ($anchor !== null) {
            $out[] = Lang::t(
                // "That digest" only reads when the sentence before named it.
                $this->analysis->timestamps !== [] ? 'report.footer.out.anchor' : 'report.footer.out.anchor.alone',
                self::DIGEST_BYTES,
                $anchor['calendars'] === [] ? '' : ' ('.self::names($anchor['calendars']).')',
            );
            if ($anchor['height'] > 0) {
                $out[] = Lang::t('report.footer.out.block', Lang::number($anchor['height']));
            }
        }

        $sent = $out === []
            ? Lang::t('report.footer.out.none')
            : Lang::t('report.footer.out', implode(Lang::t('report.footer.out.separator'), $out));

        // Where "as is" goes. The PDF link is hidden in print: the PDF is
        // typeset from this very page, and a printed sheet pointing at itself
        // is noise.
        $threema = $shareSection
            ? '<a href="#'.self::SHARE_ID.'">'.htmlspecialchars(Lang::t('report.footer.threema')).'</a>'
            : '';
        $pdf = '';
        if ($this->analysis->pdfLink !== '') {
            $link = '<a href="'.htmlspecialchars($this->analysis->pdfLink).'">'.htmlspecialchars(Lang::t('report.footer.pdf')).'</a>';
            $pdf = '<span class="footer-pdf">'.Lang::t($threema !== '' ? 'report.footer.or' : 'report.footer.via', $link).'</span>';
        }
        $via = $threema !== '' ? Lang::t('report.footer.via', $threema) : '';

        return htmlspecialchars(Lang::t('report.footer').' '.$sent)
            .' '.htmlspecialchars(Lang::t('report.footer.file')).$via.$pdf.'.';
    }

    /**
     * A short list of names: all of them up to four, then the first three
     * and how many more, so a footer stays a footer on a fleet of hosts.
     *
     * @param list<string> $names
     */
    private static function names(array $names): string
    {
        if (\count($names) > 4) {
            return implode(', ', \array_slice($names, 0, 3)).' '.Lang::t('report.footer.more', \count($names) - 3);
        }

        return implode(', ', $names);
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
            Version::label(),
            $project,
            Rendered::at(),
            strip_tags($headline),
            $actionable,
            $this->analysis->declaration->expiryYear,
            rtrim($actions[0]['title'], '.').'.',
        );

        // The part that was missing, and the reason this button exists at all.
        //
        // This tool's whole model for a signed report is that the file travels
        // one way and the fingerprint of the keys travels by a channel that
        // already proves who is speaking — which is exactly what Threema is
        // here. The message carried neither the fingerprint nor the digest, so
        // the one channel built to establish them established nothing, and a
        // recipient had no more than a sentence anybody could have typed.
        //
        // Appended rather than folded into the sentence above: an unsigned
        // report must not grow a block of hashes that prove nothing.
        if ($this->analysis->signature !== null) {
            $hybrid = $this->analysis->signature['hybrid'] ?? null;
            $summary .= "\n\n".Lang::t(
                'share.text.sealed',
                Signature::digest($this->analysis),
                Signature::fingerprint(
                    $this->analysis->signature['public_key'],
                    \is_array($hybrid) ? $hybrid['public_key'] : '',
                ),
                basename($this->analysis->reportPath !== '' ? $this->analysis->reportPath : 'report.html').'.sig',
            );
            // And the name of their sky, which the page draws under its seal
            // and `sablier verify` computes on the reader's side. A paragraph
            // of its own, after the command: the two lines above are the
            // proof and must stay the only things called that.
            $summary .= "\n\n".Lang::t('share.text.sky', (new Sky(Signature::keysHash(
                $this->analysis->signature['public_key'],
                \is_array($hybrid) ? $hybrid['public_key'] : '',
            )))->name);
        }

        // And the date a third party attests, when one was asked for: the one
        // claim in the document that this message's own channel cannot make.
        if ($this->analysis->timestamp() !== null) {
            $summary .= "\n\n".Lang::t(
                'share.text.attested',
                Timestamp::readable($this->analysis->timestamp()['time']),
                // An authority that names itself "S.A." already ends in a full
                // stop, and the sentence added a second one.
                rtrim($this->analysis->timestamp()['authority'], '.'),
            );
        }
        // And the block, once there is one. A pending anchoring is left out:
        // a message read once should not promise something a few hours away.
        $anchor = $this->analysis->anchor;
        if ($anchor !== null && $anchor['state'] === 'anchored') {
            $summary .= "\n\n".Lang::t('share.text.anchored', $anchor['height'], OpenTimestamps::readable($anchor['time']));
        }
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
        $shareId = self::SHARE_ID;

        return <<<HTML
            <section class="plan">
              <h2>$title</h2>
              <p class="legend">$intro</p>
              <ol>$items</ol>
              <p class="share" id="$shareId"><a href="$href">$share</a></p>
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
                .htmlspecialchars(substr($block['public_key'], 0, 16).'…').'</code></dd></div>'
                // The page's own signature, named as the file it is, beside the
                // other evidence a reader is handed with this page.
                .'<div><dt>'.htmlspecialchars(Lang::t('seal.page')).'</dt><dd><code>'
                .htmlspecialchars(Signature::pagePath($this->pageName())).'</code></dd></div>';

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

            // A date a third party attests, which is the one thing the seal
            // above cannot establish on its own: `signed_at` is covered by the
            // signature, so it cannot be edited afterwards, but it is read off
            // the clock of the machine that signed — ours.
            if ($this->analysis->timestamp() !== null) {
                $token = $this->analysis->timestamp();
                $rows .= '<div><dt>'.htmlspecialchars(Lang::t('seal.timestamp')).'</dt><dd>'
                    .htmlspecialchars(Timestamp::readable($token['time'])
                        .($token['authority'] !== '' ? ' · '.$token['authority'] : '')).'</dd></div>';
            }

            // The anchoring beside the attested date, and visibly not one more
            // of them: the line above is an authority's word, this one is
            // arithmetic anybody can redo.
            if ($this->analysis->anchor !== null) {
                $rows .= '<div><dt>'.htmlspecialchars(Lang::t('seal.anchor')).'</dt><dd>'
                    .htmlspecialchars(self::anchorLine($this->analysis->anchor)).'</dd></div>';
            }

            $caveat = '<p class="seal-caveat">'.htmlspecialchars(\is_array($hybrid)
                ? Lang::t('seal.hybrid', $hybrid['algorithm'])
                : Lang::t('seal.caveat', $this->analysis->declaration->expiryYear)).'</p>';

            // What the attested date establishes, and where it stops — next to
            // the command that checks it without this tool, because a date
            // nobody can check is a decoration.
            if ($this->analysis->timestamp() !== null) {
                $scheme = $this->analysis->timestamp()['algorithm'];
                $caveat .= '<p class="legend">'.htmlspecialchars($scheme !== ''
                    ? Lang::t('seal.timestamp.proves', $scheme)
                    // Naming nothing rather than naming an empty string: the
                    // certificate could not be read here, and "signed with ,"
                    // is how a sentence admits it was built from a variable
                    // nobody checked.
                    : Lang::t('seal.timestamp.proves.unnamed')).'</p>';

                // Three commands in a block rather than one line in prose, and
                // the reason is in the note under them: the one-liner everybody
                // publishes assumes the Debian certificate path and an openssl
                // that reads the chain out of the token. Both assumptions are
                // false on systems people actually use, and a verification
                // command that fails on a reader's machine teaches them that
                // our seal is broken.
                $caveat .= '<p class="legend">'.htmlspecialchars(Lang::t('seal.timestamp.verify')).'</p>'
                    .'<pre class="recipe">'.htmlspecialchars(Lang::t(
                        'seal.timestamp.command',
                        Signature::digest($this->analysis),
                        $this->pageName().'.tsr',
                    )).'</pre>'
                    .'<p class="legend">'.htmlspecialchars(Lang::t('seal.timestamp.command.note')).'</p>';

                // The authorities that corroborate the first. Each is a separate
                // file with its own command; what matters here is that the
                // reader can see there is more than one, and in which
                // jurisdictions, because that is the whole value of asking.
                $others = $this->analysis->corroborations();
                if ($others !== []) {
                    $caveat .= '<p class="legend">'.htmlspecialchars(Lang::t('seal.timestamp.corroborated')).'</p><ul class="legend">';
                    foreach ($others as $other) {
                        $caveat .= '<li>'.htmlspecialchars(Lang::t(
                            'seal.timestamp.corroboration',
                            Timestamp::readable($other['time']),
                            $other['authority'] !== '' ? rtrim($other['authority'], '.') : Lang::t('seal.timestamp.authority'),
                            basename($other['path']),
                        )).'</li>';
                    }
                    $caveat .= '</ul>';
                }
            }

            // What the anchoring establishes, how to check it without this tool,
            // and where it stops. After the tokens, because the reader has just
            // been told what an authority's date is worth, and this is the
            // answer to the limit printed there.
            $anchor = $this->analysis->anchor;
            if ($anchor !== null) {
                $caveat .= '<p class="legend">'.htmlspecialchars(Lang::t(
                    HtmlReporter::anchorMeaning($anchor['state']),
                )).'</p>'
                    .'<p class="legend">'.htmlspecialchars(Lang::t('seal.anchor.verify')).'</p>'
                    .'<pre class="recipe">'.htmlspecialchars(Lang::t(
                        'seal.anchor.command',
                        Signature::digest($this->analysis),
                        basename($anchor['path']),
                    )).'</pre>'
                    .'<p class="legend">'.htmlspecialchars(Lang::t('seal.anchor.command.note')).'</p>';
            }

            // Why the seal can be older than the masthead. It is kept as long as
            // the findings hash to the same value, so a re-run that changes
            // nothing shows today's date at the top and the first signature and
            // attestation below. Left unexplained, those lines read as a
            // document contradicting itself — and the rule behind them is the
            // point: antecedence is what a seal buys, and replacing it destroys
            // it. Outside the timestamp block on purpose: a kept signature with
            // no attestation raises exactly the same question, and the first
            // version of this answered only half of it.
            if ($this->analysis->sealPredatesRun()) {
                $caveat .= '<p class="legend">'
                    .htmlspecialchars(Lang::t('seal.earlier', Rendered::at())).'</p>';
            }

            // What the signatures cover, in words a reader without a
            // cryptography course can follow, and then the one command that
            // checks both. The first version of this paragraph said "the report
            // has not changed since it was signed", which was false: a report
            // displays its own signature, so it cannot contain it. The second
            // said so honestly, in terms of bytes and digests, and left the
            // page uncovered. The page now has a signature of its own, filed
            // beside it, so a single character changed in it fails the check.
            //
            // The real file names, not angle brackets: this document knows what
            // it was called and which declaration it read, and asking the reader
            // to substitute placeholders is asking them not to check.
            $report = $this->pageName();
            $declared = $this->analysis->declaration->path !== ''
                ? basename($this->analysis->declaration->path)
                : '';
            $caveat .= '<p class="legend">'.htmlspecialchars(Lang::t('seal.proves.page', Signature::pagePath($report))).' <code>'
                .htmlspecialchars($declared !== ''
                    ? Lang::t('seal.verify.command', $report.'.sig', $declared)
                    : Lang::t('seal.verify.command.alone', $report.'.sig')).'</code></p>';

            // Then what the key establishes, which depends on where the expected
            // one lives. A key named in a versioned declaration is checkable by
            // that file's history; an ephemeral one rests entirely on the
            // channel that carried its fingerprint; none at all proves that a
            // key exists. Saying nothing invites the reader to assume the
            // strongest of the three.
            $caveat .= '<p class="legend">'.htmlspecialchars(($block['ephemeral'] ?? false) === true
                ? Lang::t('seal.proves.ephemeral')
                : ($this->analysis->declaration->signingPublicKey !== ''
                    ? Lang::t('seal.proves.declared')
                    : Lang::t('seal.proves.unvouched'))).'</p>';

            // The keys, drawn. Thirty-two characters of fingerprint are checked
            // once, with care, and never looked at again; a drawing is
            // recognised without being read, report after report. Last in the
            // block and under its own legend, because it is the one item here
            // that proves nothing: this page draws it, so a forged page draws
            // what it likes. The legend says so, and gives the fingerprint the
            // drawing is another view of — for a declared key too, which
            // otherwise never has its fingerprint printed.
            //
            // In the page only. The PDF is the document that gets filed, and a
            // picture that is no evidence has no place among the evidence.
            $pq = \is_array($hybrid) ? $hybrid['public_key'] : '';
            $sky = new Sky(Signature::keysHash($block['public_key'], $pq));
            $caveat .= '<figure class="seal-sky">'.$sky->svg()
                .'<figcaption><span class="seal-sky-label">'.htmlspecialchars(Lang::t('seal.sky')).'</span> '
                .'<strong>'.htmlspecialchars($sky->name).'</strong><br>'
                .htmlspecialchars(Lang::t('seal.sky.legend', Signature::fingerprint($block['public_key'], $pq)))
                // The whole hash, of which the fingerprint is half: what
                // another implementation needs to draw the same sky, so the
                // drawing can be checked by something that is not this page.
                .'<br>'.htmlspecialchars(Lang::t('seal.sky.full'))
                .' <code>'.htmlspecialchars(Signature::fullFingerprint($block['public_key'], $pq)).'</code>'
                .'</figcaption></figure>';
        }

        return '<section class="seal"><h2>'.htmlspecialchars(Lang::t('seal.title')).'</h2>'
            .'<dl class="probe-facts">'.$rows.'</dl>'
            .'<p class="legend">'.htmlspecialchars(Lang::t('seal.legend')).'</p>'
            .$caveat.'</section>';
    }

    /** The name this report was written under, which every evidence file beside it starts with. */
    private function pageName(): string
    {
        return basename($this->analysis->reportPath !== '' ? $this->analysis->reportPath : 'report.html');
    }

    /**
     * What the anchoring establishes, said per state.
     *
     * Only an anchoring that checked establishes a date. The first version
     * printed "what the anchoring establishes" under an invalid or unchecked
     * one too, so a document whose proof did not hold still told its reader
     * the findings existed no later than that block.
     */
    public static function anchorMeaning(string $state): string
    {
        return match ($state) {
            'anchored' => 'seal.anchor.proves',
            'pending' => 'seal.anchor.proves.pending',
            'invalid' => 'seal.anchor.proves.invalid',
            'unchecked' => 'seal.anchor.proves.unchecked',
            default => 'seal.anchor.proves.none',
        };
    }

    /**
     * The anchoring in one line: the block and its date, the block that could
     * not be checked, or the calendars still working on it.
     *
     * Shared with the audit document, which says the same thing to a reader in
     * another room.
     *
     * @param array{state:string, height:int, time:int, calendars:list<string>, path:string, since:string} $anchor
     */
    public static function anchorLine(array $anchor): string
    {
        return match ($anchor['state']) {
            'anchored' => Lang::t('seal.anchor.anchored', $anchor['height'], OpenTimestamps::readable($anchor['time'])),
            'invalid' => Lang::t('seal.anchor.invalid', $anchor['height']),
            'unchecked' => Lang::t('seal.anchor.claimed', $anchor['height']),
            'none' => Lang::t('seal.anchor.none'),
            default => Lang::t('seal.anchor.pending', implode(', ', $anchor['calendars']), $anchor['since']),
        };
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

        $box = '<section class="blind"><h2>'.htmlspecialchars(Lang::t('blind.title')).'</h2><ul>'.$items.'</ul>
            <p>'.htmlspecialchars(Lang::t('blind.motto')).'</p></section>';

        // The other half of the sentence. "No private key in this repository"
        // and "nobody looked for one" print as the same silence otherwise, and
        // only one of them is what the reader came for.
        $found = Absences::for($this->analysis);
        if ($found !== []) {
            $rows = '';
            foreach ($found as $line) {
                $rows .= '<li>'.htmlspecialchars($line).'</li>';
            }
            $box .= '<section class="blind absences"><h2>'.htmlspecialchars(Lang::t('absence.title')).'</h2>'
                .'<p class="legend">'.htmlspecialchars(Lang::t('absence.intro')).'</p><ul>'.$rows.'</ul></section>';
        }

        return $box;
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
            .build{font-weight:400;font-size:.62em;letter-spacing:.04em;opacity:.55;vertical-align:.12em}
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
            .absences{margin-top:1.2rem}
            code{word-break:break-all}
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
            .seal-sky{display:flex;flex-wrap:wrap;align-items:center;gap:.9rem 1.3rem;margin:1.3rem 0 0}
            .seal-sky svg{flex:none;width:13rem;height:13rem}
            .seal-sky figcaption{flex:1 1 17rem;font-size:.8rem;color:var(--muted)}
            .seal-sky strong{color:var(--ink,inherit);font-size:.95rem;letter-spacing:.03em}
            .seal-sky-label{font-size:.68rem;letter-spacing:.09em;text-transform:uppercase}
            .seal-sky code{word-break:break-all}
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
            pre.recipe{white-space:pre;overflow-x:auto;line-height:1.5}
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
            @media print{.share,.share-note,.share-text,.footer-pdf{display:none}}
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
