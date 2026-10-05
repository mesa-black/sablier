<?php

declare(strict_types=1);

namespace Sablier\Web;

use Sablier\Declaration;
use Sablier\Interview as Questions;
use Sablier\Lang;
use Sablier\Value;

/**
 * The interview, in a browser.
 *
 * The terminal version works and nobody should have to use it in front of a
 * client. A page with one subject at a time, a button that starts the clock
 * and a timer the person can see is not a nicer skin on the same thing: it
 * changes who can run the session, which was the point of the session.
 *
 * Three rules it keeps from the rest of the project:
 *
 *   · the page is self-contained — no font, no framework, no request leaves
 *     the machine. The server is bound to the loopback and dies with the
 *     command that started it;
 *   · the script here is the interview's own, and nowhere near a report. The
 *     report still ships without a line of JavaScript; this is an application,
 *     and it says so;
 *   · the timings that matter are measured on the server, from when the page
 *     was served to when the answer came back. The counter on screen is for
 *     the person, not for the record.
 */
final class Interview
{
    public function __construct(private readonly Session $session)
    {
    }

    /** @param array<string, string> $post */
    public function handle(string $method, string $path, array $post): string
    {
        return match (true) {
            $path === '/' => $this->intro(),
            $path === '/start' && $method === 'POST' => $this->start($post),
            $path === '/context' => $this->context(),
            $path === '/subject' && $method === 'POST' => $this->answer($post),
            $path === '/subject' => $this->subject(),
            $path === '/feedback' && $method === 'POST' => $this->feedback($post),
            $path === '/feedback' => $this->askFeedback(),
            $path === '/done' => $this->done(),
            default => $this->redirect('/'),
        };
    }

    // --- pages ------------------------------------------------------------

    private function intro(): string
    {
        $areas = $this->session->map('areas');

        // The agenda lists places, and nothing else. It used to print the
        // family of algorithms as the heading and the paths beside it: a
        // reader who does not write the code learns nothing from either, and
        // the first person asked said so.
        $subjects = '';
        foreach ($areas as $area) {
            $area = Value::map($area);
            $subjects .= \sprintf(
                '<li%s><strong>%s</strong></li>',
                \count(Value::strings($area['paths'] ?? null)) > 1 ? ' class="many"' : '',
                htmlspecialchars(Value::bool($area['technical'] ?? null)
                    ? Lang::t('web.subject.label.technical')
                    : self::humanise(Value::string($area['path'] ?? null))),
            );
        }

        return $this->page(
            Lang::t('web.intro.title'),
            '<p class="purpose">'.htmlspecialchars(Lang::t('web.purpose', $this->project())).'</p>'
            .'<p class="lead">'.htmlspecialchars(Lang::t('web.intro.lead', \count($areas), $this->project())).'</p>'
            .'<ol class="questions">'
            .'<li>'.htmlspecialchars(Lang::t('declare.q.name.first')).'</li>'
            .'<li>'.htmlspecialchars(Lang::t('web.q.harm')).'</li>'
            .'<li>'.htmlspecialchars(Lang::t('declare.q.retention')).'</li>'
            .'</ol>'
            .'<p>'.htmlspecialchars(Lang::t('web.intro.rules')).'</p>'
            .'<ul class="subjects">'.$subjects.'</ul>'
            .'<form method="post" action="/start"><button type="submit">'
            .htmlspecialchars(Lang::t('web.intro.button')).'</button></form>'
            .'<p class="note">'.htmlspecialchars(Lang::t('web.intro.note')).'</p>',
        );
    }

    /** @param array<string, string> $post */
    private function start(array $post): string
    {
        $this->session->set('started_at', microtime(true));
        $this->session->set('served_at', microtime(true));

        return $this->redirect('/context');
    }

    private function context(): string
    {
        $this->session->set('served_at', microtime(true));

        // Read off the regimes the tool actually implements, never a list typed
        // here: the two drifted, and the interview offered a health regime that
        // the handler below then discarded in silence. A person chose it, the
        // session kept "general", and nothing anywhere said so.
        $regimes = '';
        foreach (array_keys(Declaration::REGIMES) as $key) {
            $regimes .= \sprintf(
                '<label class="choice"><input type="radio" name="regime" value="%s"%s> %s</label>',
                htmlspecialchars($key),
                $key === 'general' ? ' checked' : '',
                htmlspecialchars(Lang::t("web.regime.$key")),
            );
        }

        return $this->page(
            Lang::t('web.context.title'),
            '<form method="post" action="/subject">'
            .'<input type="hidden" name="step" value="context">'
            .'<p class="lead">'.htmlspecialchars(Lang::t('web.context.lead')).'</p>'
            .'<label class="field"><span class="q">'.htmlspecialchars(Lang::t('web.q.who')).'</span>'
            .'<span class="hint">'.htmlspecialchars(Lang::t('web.q.who.hint')).'</span>'
            .'<input type="text" name="who" autofocus autocomplete="off"></label>'
            .($this->session->int('started_in') > 0
                ? '<p class="technical">'.htmlspecialchars(Lang::t('web.context.started', $this->session->int('started_in'))).'</p>'
                : '')
            .'<label class="field"><span class="q">'.htmlspecialchars(Lang::t('declare.q.service')).'</span>'
            .'<input type="text" name="service_until" inputmode="numeric" placeholder="2032"></label>'
            .'<fieldset><legend>'.htmlspecialchars(Lang::t('web.context.regime')).'</legend>'.$regimes.'</fieldset>'
            .'<button type="submit">'.htmlspecialchars(Lang::t('web.next')).'</button>'
            .'</form>',
        );
    }

    /**
     * One subject, one question that matters, and nothing to decipher.
     *
     * The first dry run with somebody playing the non-technical part produced
     * four lessons, and this screen is what is left of them:
     *
     *   · a file path told the person nothing. "I do not know what this file
     *     is" was typed into the name field, so the heading is now the part of
     *     the application in words, and the paths are small print for whoever
     *     wants them;
     *   · "what would we be talking about" was answered with the incident —
     *     "a hack of my server" — rather than with a name. So the field asks
     *     for a name, carries examples, and comes pre-filled when the tool
     *     honestly knows the answer;
     *   · the duration question was answered three times out of four and the
     *     retention question once. The one that works is now a row of buttons,
     *     and the one that does not is optional and explicitly about a legal
     *     obligation;
     *   · "I do not know" is a button rather than a confession typed into a
     *     text field, and it records the subject as skipped, which is exactly
     *     what it is.
     */
    private function subject(): string
    {
        $index = $this->session->int('index');
        $areas = array_values($this->session->map('areas'));
        if (!isset($areas[$index])) {
            return $this->redirect('/feedback');
        }

        $this->session->set('served_at', microtime(true));
        $area = Value::map($areas[$index]);
        $algorithms = Value::strings($area['algorithms'] ?? null);
        $path = Value::string($area['path'] ?? null);
        $places = Value::strings($area['paths'] ?? null);
        // The place names the subject; the cryptography only explains what
        // happens there. A suggestion taken from the algorithm family offered
        // "content digests" as the name of a kind of data, which is a mechanism
        // answering a question about data — and the one thing a person outside
        // the team cannot make sense of.
        $technical = Value::bool($area['technical'] ?? null);
        $place = self::humanise($path);
        // Never pre-filled: `Entity` is a word from the code, and a reader
        // accepts whatever is already in the box.
        $suggested = '';

        // Signatures are published on purpose: the question is not what a leak
        // would cost but how long the proof has to hold.
        $signature = Questions::isSignature($algorithms);
        $years = '';
        foreach (Questions::consequences($this->session->int('started_in')) as $choice) {
            $years .= \sprintf(
                '<label class="year"><input type="radio" name="harm" value="%d"> %s</label>',
                $choice['value'],
                htmlspecialchars($signature ? $choice['trust'] : $choice['harm']),
            );
        }

        $used = '';
        foreach ($this->session->map('answers') as $answer) {
            $given = Value::string(Value::map($answer)['name'] ?? null);
            if ($given !== '') {
                $used .= '<button type="button" class="reuse" data-name="'.htmlspecialchars($given).'">'
                    .htmlspecialchars($given).'</button>';
            }
        }
        if ($used !== '') {
            $used = '<p class="reuses"><span>'.htmlspecialchars(Lang::t('web.q.name.reuse')).'</span>'.$used.'</p>';
        }

        return $this->page(
            // One place is named; several are counted, and listed under the
            // form. "The « Billing » part" is a heading somebody recognises;
            // "the « Billing » part and four others" is a riddle.
            match (true) {
                $technical => Lang::t('web.subject.title.technical', $index + 1, \count($areas)),
                \count($places) > 1 => Lang::t('web.subject.title.places', $index + 1, \count($areas), \count($places)),
                default => Lang::t('web.subject.title', $index + 1, \count($areas), $place),
            },
            '<p class="found">'.htmlspecialchars(Lang::t(Questions::subject($algorithms))).'</p>'
            // Plumbing, and whoever is in the room may not be the person who
            // answers for it. Said before the questions rather than after.
            .($technical ? '<p class="technical">'.htmlspecialchars(Lang::t('web.subject.technical')).'</p>' : '')
            // Nothing said here changes today's verdict, and a person asked a
            // question that cannot change an outcome deserves to know it.
            .(!$technical && !Value::bool($area['decides'] ?? null)
                ? '<p class="technical">'.htmlspecialchars(Lang::t('web.subject.noop')).'</p>'
                : '')
            .'<form method="post" action="/subject">'
            .'<input type="hidden" name="step" value="subject">'
            .'<label class="field"><span class="q">'.htmlspecialchars(Lang::t('web.q.name')).'</span>'
            .'<span class="hint">'.htmlspecialchars(Lang::t('web.q.name.hint')).'</span>'
            .'<input type="text" name="name" id="name" value="'.htmlspecialchars($suggested).'" autofocus autocomplete="off"></label>'
            .$used
            // Not a fieldset: a legend is painted on the border, so a question
            // this long wrapped across the line and the browser's own legend
            // rule greyed it down to a caption — the one question that decides
            // the verdict, rendered smaller than the optional ones.
            .'<div class="field" role="radiogroup" aria-labelledby="harm">'
            .'<span class="q" id="harm">'.htmlspecialchars(Lang::t($signature ? 'web.q.trust' : 'web.q.harm')).'</span>'
            .'<span class="hint">'.htmlspecialchars(Lang::t($signature ? 'web.q.trust.hint' : 'web.q.harm.hint')).'</span>'
            .'<div class="years">'.$years.'</div></div>'
            .'<input type="hidden" name="kind" value="'.($signature ? 'signature' : 'secret').'">'
            .'<label class="field optional"><span class="q">'.htmlspecialchars(Lang::t('web.q.retention')).'</span>'
            .'<span class="hint">'.htmlspecialchars(Lang::t('web.q.retention.hint')).'</span>'
            .'<input type="text" name="retention" inputmode="numeric" autocomplete="off"></label>'
            .'<label class="field optional"><span class="q">'.htmlspecialchars(Lang::t('declare.q.note')).'</span>'
            .'<textarea name="note" rows="3"></textarea></label>'
            .'<div class="actions"><button type="submit" name="action" value="answer">'.htmlspecialchars(Lang::t('web.next')).'</button>'
            .'<button type="submit" name="action" value="unknown" class="ghost">'.htmlspecialchars(Lang::t('web.unknown')).'</button>'
            .'<button type="submit" name="action" value="skip" class="ghost">'.htmlspecialchars(Lang::t('web.skip')).'</button></div>'
            .'</form>'
            // Where exactly, folded. It is what an auditor checks and what a
            // developer recognises, and it is noise to the person being asked
            // — who answers about data, not about files. Closed by default:
            // present for whoever wants it, absent from the conversation.
            .'<details class="where"><summary>'.htmlspecialchars(Lang::t('web.details')).'</summary>'
            .'<p>'.htmlspecialchars(Lang::t('declare.area.where', implode(', ', \count($places) > 1
                ? $places
                : Value::strings($area['names'] ?? null)))).'</p></details>',
            timer: true,
        );
    }

    /** What the client calls the thing being audited, on every screen. */
    private function project(): string
    {
        return $this->session->string('project', basename($this->session->string('target')));
    }

    /** `src/Feedback` reads as "Feedback": the last word, and no slash. */
    private static function humanise(string $path): string
    {
        $parts = explode('/', $path);

        return end($parts) ?: $path;
    }

    /** @param array<string, string> $post */
    private function answer(array $post): string
    {
        $seconds = $this->sinceServed();

        if (($post['step'] ?? '') === 'context') {
            $year = $this->year($post['service_until'] ?? '');
            $project = [];
            if ($year !== null) {
                $project['service_until'] = $year;
            }
            $regime = $post['regime'] ?? 'general';
            if (isset(Declaration::REGIMES[$regime])) {
                $project['regime'] = $regime;
            }
            $this->session->set('who', trim($post['who'] ?? ''));
            $this->session->set('context', $project);
            $this->session->set('context_seconds', $seconds);

            return $this->redirect('/subject');
        }

        $index = $this->session->int('index');
        $areas = array_values($this->session->map('areas'));
        $area = Value::map($areas[$index] ?? []);
        $places = Value::strings($area['paths'] ?? null);
        $name = trim($post['name'] ?? '');
        $record = $this->session->map('record');
        $answers = $this->session->map('answers');

        $action = $post['action'] ?? '';
        if ($action === 'skip' || $action === 'unknown' || $name === '') {
            $record[] = [
                'area' => Questions::where($places),
                'places' => $places,
                'skipped' => true,
                // Not knowing and choosing not to answer are two results, and
                // the difference is the whole point of running the session.
                'reason' => $action === 'unknown' ? 'does_not_know' : 'skipped',
                'seconds' => $seconds,
            ];
        } else {
            $retention = $this->years($post['retention'] ?? '');
            $harm = $this->years($post['harm'] ?? '');
            $lifetime = Questions::lifetime($retention ?? 0, $harm ?? 0);
            // Ten years of required proof is what this project calls a trust
            // anchor: the one case where a signature has to be migrated early.
            $anchor = ($post['kind'] ?? '') === 'signature' && ($harm ?? 0) >= 10;
            $answers[] = [
                'name' => $name,
                'paths' => Value::strings($area['patterns'] ?? null),
                'lifetime' => $lifetime,
                'note' => trim($post['note'] ?? ''),
                'trust_anchor' => $anchor,
                'declared_by' => $this->session->string('who'),
            ];
            $record[] = [
                'area' => Questions::where($places),
                'places' => $places,
                'name' => $name,
                'retention_years' => $retention,
                'harm_years' => $harm,
                'lifetime_years' => $lifetime,
                'skipped' => false,
                'seconds' => $seconds,
            ];
        }

        $this->session->set('record', $record);
        $this->session->set('answers', $answers);
        $this->session->set('index', $index + 1);

        return $this->redirect('/subject');
    }

    /**
     * Two questions about the interview rather than about the project.
     *
     * The session exists to validate the tool as much as to fill a
     * declaration, and the person in the chair is the only one who can say
     * which question was badly put. Their answers go to the session record,
     * never to the report: the report is about their system, and this is about
     * ours.
     */
    private function askFeedback(): string
    {
        $this->session->set('served_at', microtime(true));

        return $this->page(
            Lang::t('web.feedback.title'),
            '<p class="lead">'.htmlspecialchars(Lang::t('web.feedback.lead')).'</p>'
            .'<form method="post" action="/feedback">'
            .'<label class="field"><span class="q">'.htmlspecialchars(Lang::t('web.feedback.missing')).'</span>'
            .'<textarea name="missing" rows="5" autofocus></textarea></label>'
            .'<label class="field"><span class="q">'.htmlspecialchars(Lang::t('web.feedback.unclear')).'</span>'
            .'<textarea name="unclear" rows="5"></textarea></label>'
            .'<button type="submit">'.htmlspecialchars(Lang::t('web.feedback.finish')).'</button>'
            .'</form>',
        );
    }

    /** @param array<string, string> $post */
    private function feedback(array $post): string
    {
        $this->session->set('feedback', [
            'missing' => trim($post['missing'] ?? ''),
            'unclear' => trim($post['unclear'] ?? ''),
            'seconds' => $this->sinceServed(),
        ]);

        return $this->redirect('/done');
    }

    /**
     * The end: write what was said, run the analysis again, show the move.
     *
     * The report is what the hour produced, and showing it while the person is
     * still in the room is the only moment they can contest a verdict their
     * own answer caused.
     */
    private function done(): string
    {
        $elapsed = microtime(true) - (float) Value::string($this->session->data['started_at'] ?? null, (string) microtime(true));
        $written = $this->write();

        $rows = '';
        foreach ($this->session->map('record') as $entry) {
            $entry = Value::map($entry);
            $rows .= \sprintf(
                '<tr><td>%s</td><td>%s</td><td class="n">%s</td><td class="n">%.0f s</td></tr>',
                htmlspecialchars(Value::string($entry['area'] ?? null)),
                htmlspecialchars(Value::string($entry['name'] ?? null, '—')),
                // "I do not know" and "skip this" are two different results and
                // the log has always kept them apart. The recap said "skipped"
                // for both, which hides the one that matters: a subject nobody
                // can answer is what the whole session is testing for.
                ($entry['skipped'] ?? false) === true
                    ? htmlspecialchars(Lang::t(Value::string($entry['reason'] ?? null) === 'does_not_know'
                        ? 'declare.times.unknown'
                        : 'declare.times.skipped'))
                    : Value::int($entry['lifetime_years'] ?? null).' '.htmlspecialchars(Lang::t('unit.years')),
                (float) Value::string($entry['seconds'] ?? null, '0'),
            );
        }

        $counts = '';
        foreach ($written['counts'] as $verdict => $count) {
            $counts .= '<li><span class="count">'.$count.'</span> '.htmlspecialchars($verdict).'</li>';
        }

        return $this->page(
            Lang::t('web.done.title'),
            '<p class="lead">'.htmlspecialchars(Lang::t('web.done.lead',
                \count($this->session->map('answers')),
                self::duration($elapsed),
            )).'</p>'
            .'<table><tbody>'.$rows.'</tbody></table>'
            .'<h2>'.htmlspecialchars(Lang::t('web.done.verdicts')).'</h2>'
            .'<ul class="verdicts">'.$counts.'</ul>'
            .'<p><a class="button" href="/report" target="_blank" rel="noopener">'.htmlspecialchars(Lang::t('web.done.report')).'</a></p>'
            .'<p class="note">'.htmlspecialchars(Lang::t('web.done.files', basename($written['declaration']), basename($written['log']))).'</p>',
        );
    }

    /**
     * @return array{declaration:string, log:string, counts:array<string,int>}
     */
    private function write(): array
    {
        $out = $this->session->string('out');
        $log = $this->session->string('log');

        /** @var array<string, mixed> $existing */
        $existing = is_file($out) ? Value::map(json_decode((string) file_get_contents($out), true)) : [];
        $answers = [];
        foreach ($this->session->map('answers') as $answer) {
            $answer = Value::map($answer);
            $answers[] = [
                'name' => Value::string($answer['name'] ?? null),
                'paths' => Value::strings($answer['paths'] ?? null),
                'lifetime' => Value::int($answer['lifetime'] ?? null),
                'note' => Value::string($answer['note'] ?? null),
                'trust_anchor' => ($answer['trust_anchor'] ?? false) === true,
                'declared_by' => Value::string($answer['declared_by'] ?? null),
            ];
        }

        /** @var array<string, mixed> $context */
        $context = [...$existing, ...$this->session->map('context')];
        $merged = Questions::merge($context, $answers);
        file_put_contents($out, json_encode($merged, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE)."\n");

        file_put_contents($log, json_encode([
            'project' => basename($this->session->string('target')),
            'finished_at' => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM),
            'answered' => \count($answers),
            'record' => $this->session->map('record'),
            // What the person said about the questions themselves: the only
            // part of this file that is about the tool rather than the project.
            'feedback' => $this->session->map('feedback'),
        ], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE)."\n");

        return [
            'declaration' => $out,
            'log' => $log,
            'counts' => $this->rescan($out),
        ];
    }

    /** @return array<string, int> */
    private function rescan(string $declarationPath): array
    {
        $report = $this->session->string('report');
        $command = \sprintf(
            '%s %s scan %s --declare=%s --out=%s --no-probe --quiet 2>/dev/null',
            escapeshellarg(\PHP_BINARY),
            escapeshellarg(\dirname(__DIR__, 2).'/bin/sablier'),
            escapeshellarg($this->session->string('target')),
            escapeshellarg($declarationPath),
            escapeshellarg($report),
        );
        @shell_exec($command);

        $json = \dirname($report).'/.sablier-web.json';
        @shell_exec(str_replace('--quiet', '--json='.escapeshellarg($json).' --quiet', $command));

        $counts = [];
        foreach (Value::map(json_decode((string) @file_get_contents($json), true)) as $row) {
            $verdict = Value::string(Value::map($row)['verdict'] ?? null);
            if ($verdict !== '') {
                $counts[Lang::t("verdict.$verdict")] = ($counts[Lang::t("verdict.$verdict")] ?? 0) + 1;
            }
        }
        @unlink($json);

        return $counts;
    }

    // --- plumbing ---------------------------------------------------------

    /** Seconds between the page being served and the answer coming back. */
    private function sinceServed(): float
    {
        $served = (float) Value::string($this->session->data['served_at'] ?? null, (string) microtime(true));

        return round(microtime(true) - $served, 1);
    }

    private function years(string $raw): ?int
    {
        $raw = trim($raw);

        return preg_match('/^\d{1,3}$/', $raw) === 1 ? (int) $raw : null;
    }

    private function year(string $raw): ?int
    {
        $raw = trim($raw);

        return preg_match('/^(20|21)\d{2}$/', $raw) === 1 ? (int) $raw : null;
    }

    private static function duration(float $seconds): string
    {
        return $seconds < 60
            ? \sprintf('%d s', (int) $seconds)
            : \sprintf('%d min %02d s', (int) ($seconds / 60), (int) $seconds % 60);
    }

    private function redirect(string $to): string
    {
        header('Location: '.$to, true, 302);

        return '';
    }

    private function page(string $title, string $body, bool $timer = false): string
    {
        $lang = Lang::locale();
        $css = self::css();
        $project = htmlspecialchars($this->project());
        $clock = $timer
            ? '<div class="clock" id="clock" aria-hidden="true">0:00</div>'
            .'<script>(function(){var s=Date.now(),e=document.getElementById("clock");'
            .'setInterval(function(){var t=Math.floor((Date.now()-s)/1000);'
            .'e.textContent=Math.floor(t/60)+":"+String(t%60).padStart(2,"0");},1000);'
            .'document.querySelectorAll(".reuse").forEach(function(b){b.addEventListener("click",function(){'
            .'document.getElementById("name").value=b.dataset.name;});});})();</script>'
            : '';

        return <<<HTML
            <!DOCTYPE html>
            <html lang="$lang"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sablier — {$title}</title>
            <style>$css</style></head>
            <body>
            <header><span class="brand">SABLIER<span class="project">$project</span></span>$clock</header>
            <main><h1>{$title}</h1>$body</main>
            </body></html>
            HTML;
    }

    public static function css(): string
    {
        return <<<'CSS'
            :root{--ink:#16181d;--muted:#55595f;--paper:#fbfaf8;--line:#dcd8d2;--accent:#2a4c7d;--bad:#8f241c}
            *{box-sizing:border-box}
            body{margin:0;background:var(--paper);color:var(--ink);line-height:1.55;
                 font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
            header{display:flex;justify-content:space-between;align-items:center;gap:1rem;
                   padding:1rem 1.5rem;border-bottom:1px solid var(--line)}
            .brand{font-weight:700;letter-spacing:.22em;font-size:.8rem}
            .project{font-weight:400;letter-spacing:0;color:var(--muted);margin-left:.7rem;text-transform:none}
            .clock{font-variant-numeric:tabular-nums;color:var(--muted);font-size:.85rem}
            main{max-width:40rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
            h1{font-size:1.5rem;line-height:1.25;margin:0 0 1.2rem;text-wrap:balance}
            h2{font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:2.2rem 0 .6rem}
            .lead{font-size:1.05rem}
            .found{border-left:3px solid var(--accent);padding:.5rem 0 .5rem 1rem;margin:1.4rem 0 1.8rem;font-size:1.05rem}
            .technical{margin:-1rem 0 1.8rem;padding:.6rem .9rem;border:1px dashed var(--line);border-radius:4px;color:var(--muted);font-size:.95rem}
            .purpose{background:#00000008;border-radius:3px;padding:.9rem 1.1rem;margin:0 0 1.6rem}
            .q{font-weight:600}
            .reuses{margin:-.8rem 0 1.6rem;display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;font-size:.85rem;color:var(--muted)}
            .reuse{margin:0;padding:.25rem .6rem;font-size:.85rem;background:transparent;color:var(--ink);
                   border:1px solid var(--line);border-radius:999px;cursor:pointer}
            .hint{display:block;color:var(--muted);font-size:.85rem;margin:.2rem 0 .5rem}
            .optional .q{font-weight:400;color:var(--muted)}
            .years{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.6rem}
            .year{border:1px solid var(--line);border-radius:3px;padding:.45rem .8rem;cursor:pointer;background:#fff}
            .year:has(input:checked){border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
            .year input{margin-right:.35rem}
            .where{color:var(--muted);font-size:.85rem;margin:2rem 0 1.8rem}
            .where summary{cursor:pointer;font-family:inherit}
            .where p{margin:.5rem 0 0;font-family:ui-monospace,Menlo,monospace;font-size:.85rem}
            .field{display:block;margin:1.4rem 0}
            .field span{display:block;margin-bottom:.4rem}
            input[type=text],textarea{width:100%;padding:.7rem .8rem;font-size:1rem;font-family:inherit;line-height:1.5;
                             border:1px solid var(--line);border-radius:3px;background:#fff;color:inherit}
            textarea{resize:vertical;min-height:4.5rem}
            input[type=text]:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:1px}
            fieldset{border:1px solid var(--line);border-radius:3px;margin:1.4rem 0;padding:.8rem 1rem}
            legend{color:var(--muted);font-size:.85rem;padding:0 .3rem}
            .choice{display:block;margin:.4rem 0}
            button,.button{display:inline-block;margin-top:1.2rem;padding:.75rem 1.4rem;font-size:1rem;font-family:inherit;
                           border:1px solid var(--ink);border-radius:3px;background:var(--ink);color:var(--paper);
                           cursor:pointer;text-decoration:none}
            button.ghost{background:transparent;color:var(--muted);border-color:var(--line);margin-left:.6rem}
            .actions{display:flex;flex-wrap:wrap;align-items:center}
            .questions{color:var(--muted);padding-left:1.2rem}
            .questions li{margin:.5rem 0}
            .subjects{list-style:none;padding:0;margin:1.6rem 0}
            .subjects li{border-top:1px solid var(--line);padding:.7rem 0;display:flex;justify-content:space-between;gap:1rem}
            .subjects span{color:var(--muted);font-size:.85rem;text-align:right}
            .subjects span code{white-space:nowrap}
            /* Several places under one description: the list of paths needs a
               line of its own, or it squeezes the label into two. */
            .subjects li.many{flex-direction:column;align-items:flex-start;gap:.25rem}
            .subjects li.many span{text-align:left}
            table{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.92rem}
            td{border-bottom:1px solid var(--line);padding:.45rem .4rem;vertical-align:top}
            td.n{text-align:right;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
            .verdicts{list-style:none;padding:0;margin:.4rem 0}
            .verdicts li{margin:.3rem 0}
            .count{display:inline-block;min-width:1.8rem;text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
            .note{color:var(--muted);font-size:.85rem;margin-top:2rem}
            /* Every surface that was given a literal white above has to be
               given one here too. A dark override placed before the rule it
               overrides loses on source order, which is how a text area ended
               up white with light grey text in it — unreadable, and only on
               the screen somebody was typing a sentence into. */
            @media (prefers-color-scheme:dark){
                :root{--ink:#e9e6e1;--paper:#15161a;--line:#33363d;--muted:#9a9790;--accent:#8aa8d8}
                input[type=text],textarea,.year{background:#1d1f24;color:var(--ink)}
                input[type=text]::placeholder,textarea::placeholder{color:var(--muted)}
                .purpose{background:#ffffff0a}
                button,.button{background:var(--ink);color:var(--paper)}
                button.ghost{background:transparent;color:var(--ink)}
            }
            CSS;
    }
}
