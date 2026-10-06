<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\Analysis;
use Sablier\Assessor;
use Sablier\Breach;
use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\Signature;
use Sablier\Version;

/**
 * The third document: the week after.
 *
 * The technical report plans a migration and the audit report weighs one. This
 * one is written once the data is already out, and it answers the single
 * question the other two cannot: the incident is over, so how long does it keep
 * costing? Record counts, categories and notification deadlines belong to the
 * incident team and to the law; the duration belongs here, and nobody else
 * computes it.
 *
 * It is a separate document rather than a section of the other two for the
 * reason that governs all three: they are read by different people in different
 * rooms, and a document read in a crisis has to be short enough to be read in
 * one sitting. It also deliberately does not look like the audit report — a
 * sans-serif face, no table of contents, five sections — because two documents
 * from the same run that look alike is how somebody files the wrong one.
 *
 * What it refuses, in the document itself and not only here:
 *
 * - **it is not a notification.** Article 33 asks for categories and
 *   approximate numbers of records and data subjects. This document contains
 *   none of them, says so in section 1, and tells the reader where that
 *   obligation actually lives;
 * - **it counts no people.** The tool has no idea how many records left. It
 *   knows what the organisation declared it was protecting and for how long;
 * - **it does not pretend the damage can be undone.** Section 4 lists what can
 *   still be done and marks plainly which of those reaches the data that left:
 *   one of them, and only where the duration was a choice rather than a law.
 */
final class IncidentReporter implements ReporterInterface
{
    public function render(Analysis $analysis): string
    {
        $lines = Breach::lines($analysis);
        $project = htmlspecialchars($analysis->declaration->project !== ''
            ? $analysis->declaration->project
            : basename($analysis->target));
        $title = htmlspecialchars(Lang::t('incident.doc_title'));
        $subtitle = htmlspecialchars(Lang::t('incident.doc_subtitle'));
        $date = (new \DateTimeImmutable())->format('d/m/Y');
        $lang = Lang::locale();
        $css = $this->css();
        $runner = htmlspecialchars(implode(' · ', array_filter([
            Lang::t('incident.doc_title'),
            $analysis->declaration->project !== '' ? $analysis->declaration->project : basename($analysis->target),
            Version::label(),
        ])));

        $sections = $this->purpose($lines)
            .$this->declared($analysis, $lines)
            .$this->duration($analysis, $lines)
            .$this->remedies()
            .$this->method($analysis)
            .$this->integrity($analysis);

        return <<<HTML
            <!DOCTYPE html>
            <html lang="$lang"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>$title — $project</title>
            <style>$css</style></head>
            <body>
            <header>
              <p class="kind">$title</p>
              <h1>$project</h1>
              <p class="subtitle">$subtitle · $date</p>
            </header>
            <div class="runner" id="runner">$runner</div>
            $sections
            </body></html>
            HTML;
    }

    /**
     * The headline figure, and immediately what it is not.
     *
     * A number at the top of a document about a breach is read as a measure of
     * the breach. This one measures the declaration, and the paragraph that
     * follows it says so before the reader has had time to quote it.
     *
     * @param list<array{domain:string, taken:string, lifetime:int, until:int, expiry:int, readable:int, from:int, plaintext:bool, harvestable:bool}> $lines
     */
    private function purpose(array $lines): string
    {
        $exposed = array_values(array_filter($lines, static fn (array $l): bool => $l['readable'] > 0));
        $worst = $exposed === [] ? 0 : max(array_column($exposed, 'readable'));
        $last = $exposed === [] ? 0 : max(array_column($exposed, 'until'));

        $body = '<p class="headline">'.htmlspecialchars($exposed === []
            ? Lang::t('incident.none_exposed', \count($lines))
            : Lang::t(
                $worst > 1 ? 'incident.exposed' : 'incident.exposed.one',
                \count($exposed), \count($lines), $worst, $last,
            )).'</p>';
        $body .= '<p>'.htmlspecialchars(Lang::t('incident.s1.body')).'</p>';
        $body .= '<p class="flag">'.htmlspecialchars(Lang::t('incident.s1.not')).'</p>';

        return $this->section(1, $body);
    }

    /**
     * The input, printed in full before anything is concluded from it.
     *
     * @param list<array{domain:string, taken:string, lifetime:int, until:int, expiry:int, readable:int, from:int, plaintext:bool, harvestable:bool}> $lines
     */
    private function declared(Analysis $analysis, array $lines): string
    {
        $rows = '';
        foreach ($lines as $line) {
            $domain = $this->domain($analysis, $line['domain']);
            $by = trim(($domain['declared_by'] ?? '').' '.($domain['declared_on'] ?? ''));
            $rows .= '<tr><td>'.htmlspecialchars($line['domain']).'</td>'
                .'<td class="n">'.$this->day($line['taken']).'</td>'
                .'<td class="n">'.$line['lifetime'].'</td>'
                .'<td>'.($by === ''
                    ? '<span class="unset">'.htmlspecialchars(Lang::t('audit.declared.unknown')).'</span>'
                    : htmlspecialchars($by)).'</td>'
                .'<td>'.htmlspecialchars($domain['note'] ?? '').'</td></tr>';
        }

        $body = '<p class="flag">'.htmlspecialchars(Lang::t('incident.s2.lead')).'</p>'
            .'<table><thead><tr>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.domain')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.taken')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.lifetime')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.declared_by')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.note')).'</th>'
            .'</tr></thead><tbody>'.$rows.'</tbody></table>';

        return $this->section(2, $body);
    }

    /**
     * The arithmetic, one row per domain, and the protection it rests on.
     *
     * @param list<array{domain:string, taken:string, lifetime:int, until:int, expiry:int, readable:int, from:int, plaintext:bool, harvestable:bool}> $lines
     */
    private function duration(Analysis $analysis, array $lines): string
    {
        $rows = '';
        foreach ($lines as $line) {
            $rows .= '<tr'.($line['readable'] > 0 ? ' class="past"' : '').'>'
                .'<td>'.htmlspecialchars($line['domain']).'</td>'
                .'<td class="n">'.$line['until'].'</td>'
                // The expiry only answers this column where the algorithm is
                // what ends the protection. Printing 2035 next to a domain
                // quantum does not reach reads as a deadline it does not have.
                .'<td class="n">'.htmlspecialchars(match (true) {
                    $line['plaintext'] => Lang::t('incident.cell.none'),
                    $line['harvestable'] => (string) $line['expiry'],
                    default => Lang::t('incident.cell.beyond'),
                }).'</td>'
                .'<td class="n">'.($line['readable'] > 0 ? (string) $line['readable'] : '—').'</td>'
                .'<td class="n">'.($line['readable'] > 0 ? (string) $line['from'] : '—').'</td>'
                .'<td>'.htmlspecialchars($this->protection($analysis, $line['domain'])).'</td></tr>';
        }

        $body = '<p>'.htmlspecialchars(Lang::t('incident.s3.lead', $analysis->declaration->expiryYear)).'</p>'
            .'<table><thead><tr>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.domain')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.until')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.expiry')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.readable')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.from')).'</th>'
            .'<th>'.htmlspecialchars(Lang::t('incident.col.protection')).'</th>'
            .'</tr></thead><tbody>'.$rows.'</tbody></table>'
            .'<p class="note">'.htmlspecialchars(Lang::t('incident.s3.note')).'</p>';

        return $this->section(3, $body);
    }

    /**
     * What can still be done, and which of it reaches what already left.
     *
     * Three of the four do not, and the document says which one does rather
     * than listing four measures that read as if they were equivalent.
     */
    private function remedies(): string
    {
        $body = '<p class="headline">'.htmlspecialchars(Lang::t('incident.s4.body')).'</p><ul>';
        foreach (['rotate', 'retention', 'reencrypt', 'notify'] as $key) {
            $reaches = $key === 'retention';
            $body .= '<li><strong>'.htmlspecialchars(Lang::t("incident.s4.$key")).'</strong> '
                .'<span class="'.($reaches ? 'reaches' : 'ahead').'">'
                .htmlspecialchars(Lang::t($reaches ? 'incident.s4.reaches' : 'incident.s4.ahead')).'</span></li>';
        }

        return $this->section(4, $body.'</ul>');
    }

    /** How the figures were produced, and what the tool cannot know. */
    private function method(Analysis $analysis): string
    {
        $body = '<p>'.htmlspecialchars(Lang::t('incident.s5.body')).'</p>'
            .'<p class="formula">'.htmlspecialchars(Lang::t('incident.s5.formula')).'</p>'
            .'<ul>';
        foreach (['declared', 'content', 'keys', 'records'] as $key) {
            $body .= '<li>'.htmlspecialchars(Lang::t("incident.s5.$key")).'</li>';
        }
        $body .= '</ul><p class="note">'.htmlspecialchars(Lang::t('incident.s5.command')).' <code>'
            .htmlspecialchars($analysis->commandLine).'</code></p>';

        return $this->section(5, $body);
    }

    /** The same seal as the other two documents, for the same reason. */
    private function integrity(Analysis $analysis): string
    {
        $body = '<p>'.htmlspecialchars(Lang::t('incident.s6.body')).'</p>'
            .'<p><code>'.htmlspecialchars(Signature::digest($analysis)).'</code></p>';

        $block = $analysis->signature;
        if ($block === null) {
            return $this->section(6, $body.'<p class="flag">'.htmlspecialchars(Lang::t('audit.s10.unsigned')).'</p>');
        }

        $signedAt = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $block['signed_at']);
        $hybrid = $block['hybrid'] ?? null;
        $body .= '<p>'.htmlspecialchars($block['algorithm'].' · '
            .($signedAt === false ? $block['signed_at'] : $signedAt->format('d/m/Y H:i'))).'</p>'
            .'<p><code>'.htmlspecialchars($block['public_key']).'</code></p>'
            .'<p>'.htmlspecialchars(\is_array($hybrid)
                ? Lang::t('seal.hybrid', $hybrid['algorithm'])
                : Lang::t('seal.single')).'</p>';

        if (($block['ephemeral'] ?? false) === true) {
            $body .= '<p>'.htmlspecialchars(Lang::t('seal.ephemeral', Signature::fingerprint(
                $block['public_key'],
                \is_array($hybrid) ? $hybrid['public_key'] : '',
            ))).'</p>';
        }

        return $this->section(6, $body);
    }

    /**
     * What was protecting a domain, named rather than summarised.
     *
     * The figure in the row before it is an arithmetic about an algorithm, so
     * the algorithm is printed next to it. A reader who disagrees with the
     * number can see which call it rests on and go and read that line.
     */
    private function protection(Analysis $analysis, string $domain): string
    {
        $names = [];
        foreach ($analysis->findings as $finding) {
            if ($finding->domain !== $domain || $finding->verdict === Assessor::NOISE) {
                continue;
            }

            $algo = Catalogue::get($finding->algorithm);
            if ($algo === null || $algo['purpose'] !== Catalogue::PURPOSE_CONFIDENTIALITY) {
                continue;
            }

            // Through the catalogue's accessor, not the raw row: one label is a
            // sentence that has to be translated, and reading the array would
            // print its marker into the one document that goes to a lawyer.
            $names[Catalogue::label($finding->algorithm)] = true;
        }

        return $names === [] ? Lang::t('incident.cell.unknown') : implode(', ', array_keys($names));
    }

    /** @return array{name?:string, paths?:list<string>, lifetime?:int, note?:string, declared_by?:string, declared_on?:string} */
    private function domain(Analysis $analysis, string $name): array
    {
        foreach ($analysis->declaration->domains as $domain) {
            if ($domain['name'] === $name) {
                return $domain;
            }
        }

        return [];
    }

    private function day(string $date): string
    {
        $parsed = \DateTimeImmutable::createFromFormat('Y-m-d', substr($date, 0, 10));

        return htmlspecialchars($parsed === false ? $date : $parsed->format('d/m/Y'));
    }

    private function section(int $number, string $body): string
    {
        return \sprintf(
            '<section id="s%d"><h2><span class="num">%d.</span> %s</h2>%s</section>',
            $number, $number, htmlspecialchars(Lang::t("incident.s$number")), $body,
        );
    }

    /**
     * Read in a crisis: one column, sans-serif, the figures in a table and
     * nothing else competing for attention. Deliberately not the audit
     * report's serif, so the two are never confused on a desk.
     */
    private function css(): string
    {
        return <<<'CSS'
            :root{--ink:#16181d;--muted:#5d6470;--paper:#fff;--line:#d8d5cf;--bad:#a3281f}
            *{box-sizing:border-box}
            body{margin:0 auto;padding:2.5rem 1.5rem 4rem;max-width:46rem;background:var(--paper);color:var(--ink);
              font:16px/1.6 -apple-system,BlinkMacSystemFont,"Helvetica Neue",Arial,sans-serif}
            header{border-bottom:3px solid var(--ink);padding-bottom:1rem;margin-bottom:2rem}
            .kind{margin:0;font-size:.75rem;letter-spacing:.14em;text-transform:uppercase;color:var(--bad);font-weight:700}
            h1{margin:.3rem 0 .2rem;font-size:1.9rem;line-height:1.15;text-wrap:balance}
            .subtitle{margin:0;color:var(--muted);font-size:.95rem}
            .runner{display:none}
            section{margin:0 0 2.25rem}
            h2{font-size:1.05rem;margin:0 0 .75rem;padding-bottom:.35rem;border-bottom:1px solid var(--line);text-wrap:balance}
            h2 .num{color:var(--muted);margin-right:.4rem;font-variant-numeric:tabular-nums}
            p{margin:0 0 .9rem}
            .headline{font-size:1.1rem;font-weight:600;line-height:1.45}
            .flag{border-left:3px solid var(--bad);padding:.5rem .9rem;background:#fbf4f3;margin-bottom:1rem}
            .note{color:var(--muted);font-size:.9rem}
            .formula{padding:.7rem .9rem;background:#f6f5f2;border:1px solid var(--line);font-size:.95rem}
            ul{margin:0 0 .9rem;padding-left:1.2rem}
            li{margin-bottom:.5rem}
            .reaches{color:var(--bad);font-weight:600}
            .ahead{color:var(--muted)}
            table{width:100%;border-collapse:collapse;margin:0 0 .9rem;font-size:.92rem}
            th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
            th{font-size:.78rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
            .n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
            tr.past td{background:#fbf4f3}
            tr.past td:first-child{font-weight:600}
            .unset{color:var(--muted);font-style:italic}
            code{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
            @media print{body{padding:0;max-width:none;font-size:11pt}.runner{display:none}}
            CSS;
    }
}
