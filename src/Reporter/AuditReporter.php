<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\ActionPlan;
use Sablier\Analysis;
use Sablier\Assessor;
use Sablier\BlindSpots;
use Sablier\Breach;
use Sablier\Catalogue;
use Sablier\Declaration;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\Signature;
use Sablier\Timestamp;
use Sablier\Version;

/**
 * The second document: the same analysis, written for people who do not write
 * code and may have to weigh it in a dispute.
 *
 * The technical report is a working document — it is read next to an editor,
 * and it assumes the reader can act. This one is read by a client, a lawyer, a
 * committee, possibly a court, and it has to survive a hostile question. Hence
 * the shape it borrows from expert reports rather than from dashboards:
 *
 *   · facts and opinion are separated, and numbered. Section 5 observes;
 *     section 7 concludes, citing the numbers it relies on. A reader can
 *     accept a fact and contest the opinion built on it, which is exactly what
 *     a cross-examination does;
 *   · the input that decides the outcome is printed in full. Every verdict
 *     here depends on lifetimes a human declared, so section 6 reproduces them
 *     and says plainly that the tool can neither verify nor derive them;
 *   · the limits are a numbered section, not a footnote;
 *   · the references are cited with the date they were last checked, because a
 *     deadline quoted from memory is worth nothing in front of someone paid to
 *     check it;
 *   · nothing about the auditor is invented. An absent name prints as "to be
 *     completed", never as a plausible default.
 *
 * It deliberately does not look like the technical report. Two documents from
 * the same run that look alike is how a reader ends up quoting the wrong one.
 */
final class AuditReporter implements ReporterInterface
{
    private Analysis $analysis;

    /** @var array<string, int> fingerprint → finding number, so the opinion can cite the facts */
    private array $numbers = [];

    public function render(Analysis $analysis): string
    {
        $this->analysis = $analysis;

        $number = 0;
        foreach ($analysis->findings as $finding) {
            $this->numbers[$finding->fingerprint()] = ++$number;
        }

        $project = htmlspecialchars($analysis->declaration->project !== ''
            ? $analysis->declaration->project
            : basename($analysis->target));
        $title = htmlspecialchars(Lang::t('audit.doc_title'));
        $subtitle = htmlspecialchars(Lang::t('audit.doc_subtitle'));
        $date = (new \DateTimeImmutable())->format('d/m/Y');
        $lang = Lang::locale();
        $css = $this->css();

        $sections = $this->scope()
            .$this->method()
            .$this->limits()
            .$this->references()
            .$this->facts()
            .$this->lifetimes()
            .$this->opinion()
            .$this->conclusion()
            .$this->glossary()
            .$this->integrity();

        $contents = $this->contents();

        // Chrome prints no page numbers — it ignores the CSS margin boxes that
        // would carry them — so a running line identifies every page instead,
        // and the document says to cite it by section and finding number.
        // Those survive a reprint, a translation and a change of renderer,
        // which a page number does not.
        $reference = $analysis->declaration->audit['reference'];
        $runner = htmlspecialchars(implode(' · ', array_filter([
            Lang::t('audit.doc_title'),
            $analysis->declaration->project !== '' ? $analysis->declaration->project : basename($analysis->target),
            $reference,
            Version::label(),
        ])));

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
            $contents
            $sections
            </body></html>
            HTML;
    }

    private function contents(): string
    {
        $items = '';
        for ($i = 1; $i <= 10; ++$i) {
            $items .= '<li><a href="#s'.$i.'">'.htmlspecialchars(Lang::t("audit.s$i")).'</a></li>';
        }

        return '<nav class="toc"><h2>'.htmlspecialchars(Lang::t('audit.toc')).'</h2><ol>'.$items.'</ol></nav>';
    }

    private function section(int $number, string $body): string
    {
        return \sprintf(
            '<section id="s%d"><h2><span class="num">%d.</span> %s</h2>%s</section>',
            $number, $number, htmlspecialchars(Lang::t("audit.s$number")), $body,
        );
    }

    /** @param array<string, string> $rows label → value, already escaped */
    private static function definitions(array $rows): string
    {
        $out = '';
        foreach ($rows as $label => $value) {
            $out .= '<div><dt>'.htmlspecialchars($label).'</dt><dd>'.$value.'</dd></div>';
        }

        return '<dl class="fields">'.$out.'</dl>';
    }

    /** Never invent an identity: an empty field says it is empty. */
    private function supplied(string $value): string
    {
        return $value !== ''
            ? htmlspecialchars($value)
            : '<span class="todo">'.htmlspecialchars(Lang::t('audit.todo')).'</span>';
    }

    private function scope(): string
    {
        $audit = $this->analysis->declaration->audit;
        $volume = $this->analysis->importedFrom !== ''
            ? Lang::t('report.imported_from', $this->analysis->importedFrom, $this->analysis->filesRead)
            : Lang::t('report.files_read', $this->analysis->filesRead);

        $rows = [
            Lang::t('audit.f.client') => $this->supplied($audit['client']),
            Lang::t('audit.f.auditor') => $this->supplied($audit['auditor']),
            Lang::t('audit.f.organisation') => $this->supplied($audit['organisation']),
            Lang::t('audit.f.reference') => $this->supplied($audit['reference']),
            Lang::t('audit.f.mandate') => $this->supplied($audit['mandate']),
            Lang::t('audit.f.target') => '<code>'.htmlspecialchars($this->analysis->target).'</code>',
            Lang::t('audit.f.date') => htmlspecialchars((new \DateTimeImmutable())->format('d/m/Y')),
            Lang::t('audit.f.volume') => htmlspecialchars($volume),
            Lang::t('audit.f.tool') => htmlspecialchars(Version::label()),
        ];
        if ($this->analysis->commandLine !== '') {
            $rows[Lang::t('audit.f.command')] = '<code>'.htmlspecialchars($this->analysis->commandLine).'</code>';
        }

        return $this->section(1, self::definitions($rows).'<p class="note">'.htmlspecialchars(Lang::t('audit.s1.note')).'</p>');
    }

    private function method(): string
    {
        $body = '<p>'.htmlspecialchars(Lang::t('audit.s2.p1')).'</p>'
            .'<p>'.htmlspecialchars(Lang::t('audit.s2.p2')).'</p>'
            .'<p>'.htmlspecialchars(Lang::t('audit.s2.p3')).'</p>'
            .'<p class="formula">'.htmlspecialchars(Lang::t('audit.s2.formula')).'</p>'
            .'<p>'.htmlspecialchars(Lang::t('audit.s2.p4')).'</p>';

        if ($this->analysis->importedFrom !== '') {
            $body .= '<p class="flag">'.htmlspecialchars(Lang::t('report.imported_banner', $this->analysis->importedFrom)).'</p>';
        }

        return $this->section(2, $body);
    }

    private function limits(): string
    {
        $items = '';
        foreach (BlindSpots::for($this->analysis) as $spot) {
            $items .= '<li>'.htmlspecialchars($spot).'</li>';
        }
        $items .= '<li>'.htmlspecialchars(Lang::t('audit.s3.confidence')).'</li>';

        return $this->section(3, '<p>'.htmlspecialchars(Lang::t('audit.s3.intro')).'</p><ul>'.$items.'</ul>');
    }

    private function references(): string
    {
        $declaration = $this->analysis->declaration;
        $rows = [
            // Cited precisely enough to be checked, which is the only kind of
            // citation worth printing in a document meant to be contested. The
            // NIST reference is a draft and says so: presenting an initial
            // public draft as settled guidance is how an audit loses a room.
            'FIPS 203 / 204 / 205 (2024)' => 'audit.ref.fips',
            'NIST IR 8547 ipd (2024)' => 'audit.ref.nist8547',
            'CNSA 2.0 (NSA)' => 'audit.ref.cnsa',
            'Recommandation (UE) 2024/1101' => 'audit.ref.eu',
            'UE — feuille de route NIS CG (23/06/2025)' => 'audit.ref.roadmap',
            'ANSSI — avis sur la migration post-quantique' => 'audit.ref.anssi',
        ];
        $body = '<p>'.htmlspecialchars(Lang::t('audit.s4.intro')).'</p><table><tbody>';
        foreach ($rows as $label => $key) {
            $body .= '<tr><th scope="row">'.htmlspecialchars($label).'</th><td>'.htmlspecialchars(Lang::t($key)).'</td></tr>';
        }
        $checked = \DateTimeImmutable::createFromFormat('Y-m-d', $declaration->deadlinesCheckedOn);

        return $this->section(4, $body.'</tbody></table>'
            .'<p>'.htmlspecialchars($declaration->graded()
                ? Lang::t('audit.s4.retained.graded', $declaration->deprecationYear, $declaration->expiryYear)
                : Lang::t('audit.s4.retained', $declaration->expiryYear)).' '
            .htmlspecialchars(Lang::t('audit.s4.checked', $checked === false ? $declaration->deadlinesCheckedOn : $checked->format('d/m/Y'))).'</p>');
    }

    private function facts(): string
    {
        $rows = '';
        foreach ($this->analysis->findings as $finding) {
            $evidence = trim($finding->evidence) !== '' ? mb_strimwidth($finding->evidence, 0, 90, '…') : '—';
            $rows .= \sprintf(
                '<tr><td class="n">%d</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>',
                $this->numbers[$finding->fingerprint()],
                htmlspecialchars(Catalogue::label($finding->algorithm)),
                htmlspecialchars($finding->file.($finding->line > 0 ? ':'.$finding->line : '')),
                htmlspecialchars($evidence),
                htmlspecialchars(Lang::t('confidence.'.$finding->confidence)),
            );
        }

        $head = '<tr><th>'.htmlspecialchars(Lang::t('audit.col.n')).'</th><th>'.htmlspecialchars(Lang::t('audit.col.what'))
            .'</th><th>'.htmlspecialchars(Lang::t('audit.col.where')).'</th><th>'.htmlspecialchars(Lang::t('audit.col.evidence'))
            .'</th><th>'.htmlspecialchars(Lang::t('audit.col.confidence')).'</th></tr>';

        return $this->section(5, '<p>'.htmlspecialchars(Lang::t('audit.s5.intro')).'</p>'
            .'<table class="facts"><thead>'.$head.'</thead><tbody>'.$rows.'</tbody></table>');
    }

    private function lifetimes(): string
    {
        $declaration = $this->analysis->declaration;
        $body = '<p class="flag">'.htmlspecialchars(Lang::t('audit.s6.intro')).'</p>';

        if ($declaration->domains === []) {
            $body .= '<p>'.htmlspecialchars(Lang::t('audit.s6.none')).'</p>';
        } else {
            // The level column only appears where the regime grades: under a
            // flat one it would repeat the same deadline on every row, which is
            // noise in a document somebody has to read under pressure.
            $graded = $declaration->graded();
            $head = '<tr><th>'.htmlspecialchars(Lang::t('audit.col.domain')).'</th><th>'.htmlspecialchars(Lang::t('audit.col.lifetime'))
                .'</th>'.($graded ? '<th>'.htmlspecialchars(Lang::t('audit.col.level')).'</th>' : '')
                .'<th>'.htmlspecialchars(Lang::t('audit.col.paths')).'</th><th>'.htmlspecialchars(Lang::t('audit.col.note'))
                .'</th><th>'.htmlspecialchars(Lang::t('audit.col.declared')).'</th></tr>';
            $rows = '';
            foreach ($declaration->domains as $domain) {
                // Who and when, or an explicit gap: a lifetime whose author
                // nobody recorded is one nobody will think to question.
                $by = $domain['declared_by'] !== '' || $domain['declared_on'] !== ''
                    ? trim($domain['declared_by'].' '.($domain['declared_on'] !== '' ? '· '.$domain['declared_on'] : ''))
                    : null;
                $level = '';
                if ($graded) {
                    $name = $declaration->riskLevel($domain['lifetime'], $domain['trust_anchor']);
                    $level = '<td>'.htmlspecialchars(Lang::t("risk.$name").' · '
                        .$declaration->expiryFor($domain['lifetime'], $domain['trust_anchor'])).'</td>';
                }
                $rows .= \sprintf(
                    '<tr><td>%s</td><td class="n">%d</td>%s<td><code>%s</code></td><td>%s</td><td>%s</td></tr>',
                    htmlspecialchars($domain['name']),
                    $domain['lifetime'],
                    $level,
                    htmlspecialchars(implode(', ', $domain['paths'])),
                    htmlspecialchars($domain['note']),
                    $by !== null
                        ? htmlspecialchars($by)
                        : '<span class="unset">'.htmlspecialchars(Lang::t('audit.declared.unknown')).'</span>',
                );
            }
            $body .= '<table><thead>'.$head.'</thead><tbody>'.$rows.'</tbody></table>';
        }

        $body .= '<p>'.htmlspecialchars(Lang::t('audit.s6.default', $declaration->defaultLifetime)).'</p>';

        // Whether the input this whole opinion rests on was signed by anybody.
        // Printed in the section that reproduces it, because a reader weighing
        // the durations is exactly the reader who should know whether somebody
        // put their name to them — and whether the file has moved since.
        $endorsement = $declaration->endorsement();
        if ($endorsement === null) {
            $body .= '<p class="flag">'.htmlspecialchars(Lang::t('endorse.audit.none')).'</p>';
        } elseif ($endorsement['valid']) {
            $body .= '<p>'.htmlspecialchars(Lang::t('endorse.audit', $endorsement['signed_at'], $endorsement['fingerprint'])).'</p>';
        } else {
            $body .= '<p class="flag">'.htmlspecialchars(Lang::t('endorse.audit.broken', Lang::t($endorsement['reason']))).'</p>';
        }
        if ($declaration->graded()) {
            // The level is computed from a lifetime somebody declared, and the
            // framework's own test is whether a break would still cause
            // significant damage. That judgement is the declarer's, and saying
            // so is the difference between citing a framework and hiding behind
            // one.
            $body .= '<p class="note">'.htmlspecialchars(Lang::t('audit.s6.graded', Declaration::LONG_TERM_YEARS)).'</p>';
        }

        // The same chart as the technical report, in the section whose numbers
        // it draws: a jury reads a bar against a line long before it reads a
        // table of years.
        $body .= Breach::render($this->analysis).Timeline::render($this->analysis);

        return $this->section(6, $body);
    }

    /**
     * The opinion, verdict by verdict, citing the facts it rests on.
     *
     * Findings that share a sentence share a paragraph: twenty identical
     * explanations would bury the two that differ, and the numbers next to the
     * paragraph say exactly which observations it covers.
     */
    private function opinion(): string
    {
        $grouped = [];
        foreach ($this->analysis->findings as $finding) {
            $grouped[$finding->verdict][$finding->because][] = $finding;
        }

        $body = '<p>'.htmlspecialchars(Lang::t('audit.s7.intro')).'</p>';
        foreach (Assessor::order() as $verdict) {
            if (!isset($grouped[$verdict])) {
                continue;
            }
            $body .= '<h3 class="verdict-'.$verdict.'">'.htmlspecialchars(Assessor::label($verdict)).'</h3>';
            foreach ($grouped[$verdict] as $because => $findings) {
                $numbers = array_map(fn (Finding $f): int => $this->numbers[$f->fingerprint()], $findings);
                sort($numbers);
                $body .= '<p>'.htmlspecialchars((string) $because).'</p>'
                    .'<p class="cites">'.htmlspecialchars(Lang::t('audit.s7.concerns')).' '
                    .implode(', ', array_map(static fn (int $n): string => 'n°'.$n, $numbers)).'</p>';

                // A published defect belongs next to the opinion that relies
                // on it: a reader who does not take our word for it has a
                // number, a date and a third party to go and read.
                // Not under a verdict that says "nothing to do": a published
                // defect printed beside "probably not security" reads as a
                // contradiction, and the reader is right to stumble on it.
                $references = \in_array($verdict, [Assessor::CLEAR, Assessor::NOISE], true)
                    ? []
                    : $findings[0]->references();
                if ($references !== []) {
                    $links = array_map(
                        static fn (string $reference): string => \sprintf(
                            '<a href="%s">%s</a>',
                            htmlspecialchars(Catalogue::referenceUrl($reference)),
                            htmlspecialchars($reference),
                        ),
                        $references,
                    );
                    $body .= '<p class="cites">'.htmlspecialchars(Lang::t('audit.s7.references')).' '
                        .implode(' · ', $links).'</p>';
                }

                $replacement = Catalogue::get($findings[0]->algorithm)['replacement'] ?? '';
                if ($replacement !== '' && \in_array($verdict, [Assessor::COMPROMISED, Assessor::URGENT, Assessor::MIGRATE], true)) {
                    $body .= '<p class="fix"><span>'.htmlspecialchars(Lang::t('label.replacement')).'</span> '
                        .htmlspecialchars($replacement).'</p>';
                }
            }
        }

        return $this->section(7, $body);
    }

    private function conclusion(): string
    {
        $items = '';
        foreach (ActionPlan::for($this->analysis) as $action) {
            $items .= '<li><strong>'.htmlspecialchars($action['title']).'</strong><p>'.htmlspecialchars($action['body']).'</p></li>';
        }

        return $this->section(8, '<ol class="plan">'.$items.'</ol>');
    }

    private function glossary(): string
    {
        $terms = ['harvest', 'confidentiality', 'authenticity', 'lifetime', 'expiry', 'symmetric', 'hybrid'];
        $rows = '';
        foreach ($terms as $term) {
            $rows .= '<div><dt>'.htmlspecialchars(Lang::t("audit.g.$term")).'</dt><dd>'
                .htmlspecialchars(Lang::t("audit.g.$term.def")).'</dd></div>';
        }

        return $this->section(9, '<p>'.htmlspecialchars(Lang::t('audit.s9.intro')).'</p><dl class="glossary">'.$rows.'</dl>');
    }

    private function integrity(): string
    {
        $declaration = $this->analysis->declaration;
        $digest = Signature::digest($this->analysis);
        $body = '<p>'.htmlspecialchars(Lang::t('audit.s10.digest')).'</p>'
            .self::definitions([Lang::t('seal.digest') => '<code>'.htmlspecialchars($digest).'</code>']);

        if ($this->analysis->signature !== null) {
            $block = $this->analysis->signature;
            $signedAt = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $block['signed_at']);
            $body .= self::definitions([
                Lang::t('seal.signed') => htmlspecialchars($block['algorithm'].' · '.($signedAt === false ? $block['signed_at'] : $signedAt->format('d/m/Y H:i'))),
                Lang::t('seal.key') => '<code>'.htmlspecialchars($block['public_key']).'</code>',
            ]);
            if (($block['previous'] ?? '') !== '') {
                $body .= self::definitions([
                    Lang::t('audit.s10.previous') => '<code>'.htmlspecialchars((string) $block['previous']).'</code>',
                ]);
            }
            // The attested date, when one was asked for. In this document more
            // than in the other: it is the one that gets filed, and a filed
            // document is read years later by somebody asking when it was
            // written rather than whether it is pretty.
            if ($this->analysis->timestamp !== null) {
                $token = $this->analysis->timestamp;
                $body .= self::definitions([
                    Lang::t('seal.timestamp') => htmlspecialchars(Timestamp::readable($token['time'])
                        .($token['authority'] !== '' ? ' · '.$token['authority'] : '')),
                ]);
                $body .= '<p>'.htmlspecialchars(Lang::t('seal.timestamp.proves', $token['algorithm'])).'</p>';
            }

            // Which signatures the file carries. A report whose own signature
            // is quantum-vulnerable has no business advising anybody about
            // theirs without saying so in the same paragraph.
            $hybrid = $block['hybrid'] ?? null;
            $body .= '<p>'.htmlspecialchars(\is_array($hybrid)
                ? Lang::t('seal.hybrid', $hybrid['algorithm'])
                : Lang::t('seal.single')).'</p>';

            // A key that signed once and was destroyed ties the document to
            // nobody by itself. The fingerprint is what the reader was given by
            // another road, so the document prints it rather than assuming the
            // reader still has the message.
            if (($block['ephemeral'] ?? false) === true) {
                $body .= '<p>'.htmlspecialchars(Lang::t('seal.ephemeral', Signature::fingerprint(
                    $block['public_key'],
                    \is_array($hybrid) ? $hybrid['public_key'] : '',
                ))).'</p>';
            }
            $body .= '<p>'.htmlspecialchars(Lang::t('audit.s10.verify')).' <code>sablier verify &lt;'
                .htmlspecialchars(Lang::t('audit.doc_title')).'&gt;.sig --declare=&lt;declaration&gt;</code></p>';
            if (!\is_array($hybrid)) {
                $body .= '<p class="flag">'.htmlspecialchars(Lang::t('seal.caveat', $declaration->expiryYear)).'</p>';
            }
        } else {
            $body .= '<p class="flag">'.htmlspecialchars(Lang::t('audit.s10.unsigned')).'</p>';
        }

        $statement = $this->analysis->declaration->audit['statement'];
        $body .= '<h3>'.htmlspecialchars(Lang::t('audit.statement')).'</h3>';
        $body .= $statement !== ''
            ? '<blockquote>'.htmlspecialchars($statement).'</blockquote>'
            : '<p class="todo">'.htmlspecialchars(Lang::t('audit.statement.missing')).'</p>';

        return $this->section(10, $body);
    }

    /**
     * A document, not a dashboard: serif, one column, numbered, printable as
     * it stands. The palette is a single ink — a report that argues in colour
     * loses the argument the moment it is photocopied.
     */
    private function css(): string
    {
        return <<<'CSS'
            :root{--ink:#16181d;--muted:#55595f;--paper:#fff;--line:#c9c6c0;--flag:#8a5210;
                  --bad:#8f241c;--cool:#2a4c7d}
            *{box-sizing:border-box}
            body{max-width:47rem;margin:0 auto;padding:2.5rem 1.5rem 4rem;background:var(--paper);color:var(--ink);
                 font-family:Georgia,'Iowan Old Style','Times New Roman',serif;font-size:1rem;line-height:1.55}
            header{border-bottom:2px solid var(--ink);padding-bottom:1.1rem;margin-bottom:1.6rem}
            .kind{margin:0;font-size:.74rem;letter-spacing:.18em;text-transform:uppercase;color:var(--muted)}
            h1{margin:.3rem 0 .2rem;font-size:1.8rem;line-height:1.2}
            .subtitle{margin:0;color:var(--muted);font-size:.92rem}
            h2{font-size:1.1rem;margin:2.4rem 0 .8rem;padding-bottom:.3rem;border-bottom:1px solid var(--line)}
            h2 .num{color:var(--muted)}
            h3{font-size:.95rem;margin:1.5rem 0 .4rem}
            p{margin:.7rem 0}
            code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.84em;word-break:break-word}
            .toc{border:1px solid var(--line);padding:.9rem 1.2rem;margin-bottom:1rem}
            .toc h2{margin:0 0 .4rem;border:none;font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
            .toc ol{margin:0;padding-left:1.4rem;font-size:.92rem}
            .toc a{color:inherit}
            .fields{margin:.6rem 0;display:grid;gap:.1rem}
            .fields div{display:grid;grid-template-columns:12rem 1fr;gap:.6rem;padding:.3rem 0;border-bottom:1px dotted var(--line)}
            .fields dt{color:var(--muted);font-size:.86rem}
            .fields dd{margin:0}
            @media (max-width:36rem){.fields div{grid-template-columns:1fr}}
            .note,.cites{color:var(--muted);font-size:.88rem}
            /* Two different gaps: a field somebody must fill before the
               document is used, and a fact nobody recorded. Flagging the
               second as urgently as the first would make both invisible. */
            .todo{color:var(--flag);font-style:italic}
            .unset{color:var(--muted);font-style:italic}
            .formula{border-left:3px solid var(--ink);padding:.4rem 0 .4rem .9rem;margin:.9rem 0;font-style:italic}
            .flag{border-left:3px solid var(--flag);padding:.4rem 0 .4rem .9rem;color:var(--flag);font-size:.92rem}
            table{width:100%;border-collapse:collapse;margin:.9rem 0;font-size:.88rem}
            th,td{text-align:left;vertical-align:top;padding:.35rem .5rem;border-bottom:1px solid var(--line)}
            thead th{font-size:.76rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
            td.n,th[scope=row]{white-space:nowrap}
            td.n{text-align:right;color:var(--muted)}
            .facts td:nth-child(2){white-space:nowrap}
            ul,ol{padding-left:1.3rem}
            li{margin:.35rem 0}
            .plan li{margin:.8rem 0}
            .plan p{margin:.2rem 0}
            .fix{font-size:.9rem}
            .fix span{font-size:.72rem;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);margin-right:.4rem}
            .glossary{margin:.6rem 0}
            .glossary div{margin:.7rem 0}
            .glossary dt{font-weight:700}
            .glossary dd{margin:.15rem 0 0}
            blockquote{margin:.6rem 0;padding-left:1rem;border-left:3px solid var(--line);font-style:italic}

            /* The chart, in this document's ink: one blue for a duration, one
               red for a duration a harvestable algorithm has to outlive. */
            .timeline{margin:1.4rem 0 .4rem}
            .timeline h2{font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);
                         border:none;margin:0 0 .6rem;font-family:inherit}
            .timeline .chart{position:relative;border-left:1px solid var(--line);padding:1.9rem 0 .4rem}
            .mark{position:absolute;top:0;bottom:0;border-left:1px dashed var(--muted);padding-left:.4rem}
            .mark.expiry{border-left:2px solid var(--bad)}
            .mark span{font-size:.62rem;color:var(--muted);line-height:1.2;display:block;font-family:ui-monospace,Menlo,monospace}
            .mark.expiry span{color:var(--bad)}
            .row{display:grid;grid-template-columns:9rem 1fr 4rem;gap:.6rem;align-items:center;margin:.3rem 0}
            .lbl{font-size:.78rem;color:var(--muted);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
            .track{background:#00000008;height:13px;border-radius:2px;position:relative}
            .bar{height:100%;background:var(--cool);border-radius:2px}
            .bar.over{background:var(--bad)}
            .yrs{font-size:.7rem;color:var(--muted);font-variant-numeric:tabular-nums}
            .legend{font-size:.84rem;color:var(--muted);margin:.7rem 0 0}
            .crossings{margin-top:1.2rem;border-top:1px solid var(--line);padding-top:.8rem;break-inside:avoid}
            .crossings h3{margin:0 0 .4rem;font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
            .crossings ul{margin:0;padding-left:1.1rem;font-size:.92rem}
            .crossings li{margin:.2rem 0}
            .crossings li.past{color:var(--bad)}
            @media (max-width:36rem){.row{grid-template-columns:6rem 1fr 3.2rem}}
            h3.verdict-compromised,h3.verdict-urgent{color:#8f241c}

            .runner{display:none}
            @page{margin:20mm 17mm}
            @media print{
                body{max-width:none;margin:0;padding:0;font-size:10.5pt}
                /* Repeated on every sheet: a page that leaves the stapler
                   still says what it belongs to and what produced it. */
                .runner{display:block;position:fixed;bottom:0;left:0;right:0;
                        border-top:1px solid var(--line);padding-top:3pt;
                        font-size:7.5pt;color:var(--muted)}
                .toc{break-after:page}
                section{break-inside:auto}
                h2,h3{break-after:avoid}
                tr{break-inside:avoid}
                .glossary div,.plan li,.timeline{break-inside:avoid}
            }
            CSS;
    }
}
