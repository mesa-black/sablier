<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The interview as one file, for a room with no network.
 *
 * The served version needs a PHP process, a port and a browser pointed at it.
 * None of those exist where this one is meant to go: a closed network, a client
 * who will not run a command, a machine nobody is allowed to connect to.
 *
 * So the subjects and the questions are baked into a single HTML file. It is
 * opened from a memory stick or an attachment, answered in a browser with the
 * network cable out, and what comes back is a block of JSON carrying durations
 * and the names the person gave — never the inventory that produced it. The
 * report is then built by the auditor, on the machine where it belongs.
 *
 * The merging rules are deliberately *not* reimplemented here. The file
 * collects answers; `sablier declare --import=` runs them through the same
 * Interview::merge the web interview uses, so there is one definition of what a
 * second answer with the same name does.
 */
final class Worksheet
{
    /** Bumped when the shape of the answer file changes. */
    public const int FORMAT = 1;

    /**
     * @param list<array{path:string, paths:list<string>, pattern:string, patterns:list<string>, decides:bool, technical:bool, files:int, names:list<string>, algorithms:list<string>}> $areas
     */
    public static function render(string $project, array $areas, string $generatedOn): string
    {
        // The order is fixed the moment this file is written, so every heading
        // and every count is rendered here rather than reassembled in a browser
        // from a format string and a regular expression.
        $subjects = [];
        foreach ($areas as $index => $area) {
            $many = \count($area['paths']) > 1;
            // The place names the subject, and the cryptography only explains
            // what happens there. A label taken from the algorithm family put
            // "content digests" where a data name belongs, which is a mechanism
            // offered as an answer to "what data is this?".
            $place = self::humanise($area['path']);
            $subjects[] = [
                'paths' => $area['paths'],
                'patterns' => $area['patterns'],
                'names' => $area['names'],
                'technical' => $area['technical'],
                // Whether anything they say here can change today's verdict.
                // Five subjects in a row made only of digests was what SMTR
                // actually looked like, and a person asked five questions that
                // cannot change an outcome, without being told so, concludes
                // the whole exercise is theatre.
                'decides' => $area['decides'],
                'title' => match (true) {
                    $area['technical'] => Lang::t('web.subject.title.technical', $index + 1, \count($areas)),
                    $many => Lang::t('web.subject.title.places', $index + 1, \count($areas), \count($area['paths'])),
                    default => Lang::t('web.subject.title', $index + 1, \count($areas), $place),
                },
                'count' => $many
                    ? Lang::t('web.intro.places', \count($area['paths']))
                    : Lang::t('web.intro.files', $area['files']),
                'found' => Lang::t(Interview::subject($area['algorithms'])),
                // What the agenda lists. The place for business data, a plain
                // word for plumbing — never a family of algorithms.
                'label' => $area['technical'] ? Lang::t('web.subject.label.technical') : $place,
                'signature' => Interview::isSignature($area['algorithms']),
                // Never pre-filled. The field used to arrive carrying a
                // crypto family, then the directory name — and `Entity` or
                // `Billing` is a word from the code, not a kind of data. A
                // tired reader accepts whatever is in the box, so a wrong
                // suggestion here becomes a domain called "Entity" in a
                // declaration somebody signs. The place is in the heading and
                // the files are listed below; the name is theirs to give.
                'suggested' => '',
            ];
        }

        $years = [];
        foreach ([0, 1, 3, 5, 10, 20, 30] as $value) {
            $years[] = ['value' => $value, 'harm' => $value === 0 ? Lang::t('web.harm.none') : Lang::t('web.harm.years', $value),
                'trust' => $value === 0 ? Lang::t('web.trust.none') : Lang::t('web.harm.years', $value)];
        }

        $data = [
            'format' => self::FORMAT,
            'project' => $project,
            'generated_on' => $generatedOn,
            'lang' => Lang::locale(),
            'subjects' => $subjects,
            'years' => $years,
            'regimes' => [
                // Off the regimes the tool implements, so this list cannot
                // drift from them the way the served interview's did.
                ...array_map(
                    static fn (string $key): array => ['key' => $key, 'label' => Lang::t("web.regime.$key")],
                    array_keys(Declaration::REGIMES),
                ),
            ],
            't' => [
                'introTitle' => Lang::t('web.intro.title'),
                'purpose' => Lang::t('web.purpose', $project),
                'lead' => Lang::t('web.intro.lead', \count($areas), $project),
                'q1' => Lang::t('declare.q.name.first'),
                'q2' => Lang::t('declare.q.retention'),
                'q3' => Lang::t('declare.q.damage'),
                'rules' => Lang::t('web.intro.rules'),
                'start' => Lang::t('web.intro.button'),
                'offlineNote' => Lang::t('worksheet.note'),
                'contextTitle' => Lang::t('web.context.title'),
                'contextLead' => Lang::t('web.context.lead'),
                'who' => Lang::t('web.q.who'),
                'whoHint' => Lang::t('web.q.who.hint'),
                'service' => Lang::t('declare.q.service'),
                'regime' => Lang::t('web.context.regime'),
                'name' => Lang::t('web.q.name'),
                'nameHint' => Lang::t('web.q.name.hint'),
                'reuse' => Lang::t('web.q.name.reuse'),
                'harm' => Lang::t('web.q.harm'),
                'harmHint' => Lang::t('web.q.harm.hint'),
                'trust' => Lang::t('web.q.trust'),
                'trustHint' => Lang::t('web.q.trust.hint'),
                'retention' => Lang::t('web.q.retention'),
                'retentionHint' => Lang::t('web.q.retention.hint'),
                'note' => Lang::t('declare.q.note'),
                'where' => Lang::t('declare.area.where', '%s'),
                'next' => Lang::t('web.next'),
                'unknown' => Lang::t('web.unknown'),
                'skip' => Lang::t('web.skip'),
                'feedbackTitle' => Lang::t('web.feedback.title'),
                'feedbackLead' => Lang::t('web.feedback.lead'),
                'missing' => Lang::t('web.feedback.missing'),
                'unclear' => Lang::t('web.feedback.unclear'),
                'finish' => Lang::t('worksheet.finish'),
                'technicalNote' => Lang::t('web.subject.technical'),
                'noopNote' => Lang::t('web.subject.noop'),
                'doneTitle' => Lang::t('worksheet.done.title'),
                'doneLead' => Lang::t('worksheet.done.lead'),
                'download' => Lang::t('worksheet.download'),
                'copy' => Lang::t('worksheet.copy'),
                'copied' => Lang::t('worksheet.copied'),
                'skipped' => Lang::t('declare.times.skipped'),
                'doesNotKnow' => Lang::t('declare.times.unknown'),
                'years' => Lang::t('unit.years'),
                'handBack' => Lang::t('worksheet.hand_back'),
            ],
        ];

        $json = json_encode($data, \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES);
        // A closing tag inside the payload would end the script element early,
        // which is how a data island becomes a broken page.
        $json = str_replace('</', '<\\/', (string) $json);
        $css = self::css();
        $script = self::script();
        $lang = Lang::locale();
        $title = htmlspecialchars(Lang::t('worksheet.title', $project));

        return <<<HTML
            <!DOCTYPE html>
            <html lang="$lang"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>$title</title>
            <style>$css</style></head>
            <body>
            <header><span class="brand">SABLIER<span class="project">$project</span></span>
            <span class="clock" id="clock" aria-hidden="true">0:00</span></header>
            <main id="main"></main>
            <script id="data" type="application/json">$json</script>
            <script>$script</script>
            </body></html>
            HTML;
    }

    /** `src/Billing` is the Billing part, the way somebody says it out loud. */
    private static function humanise(string $path): string
    {
        $last = basename($path);

        return $last === '' ? $path : $last;
    }

    /**
     * The stylesheet of the served interview, plus what only this file needs.
     *
     * Shared rather than copied: a worksheet that drifts from the interview
     * it stands in for is a second product nobody asked for.
     */
    private static function css(): string
    {
        return Web\Interview::css().<<<'CSS'

            .out{width:100%;min-height:9rem;font-family:ui-monospace,Menlo,Consolas,monospace;
                 font-size:.8rem;line-height:1.4;margin:.6rem 0 1rem}
            .row{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}
            .done-note{color:var(--muted);font-size:.9rem}
            table{width:100%;border-collapse:collapse;margin:1.4rem 0}
            td{border-top:1px solid var(--line);padding:.55rem 0;font-size:.92rem}
            td.n{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
            CSS;
    }

    /**
     * The whole flow, in the browser, with nothing to fetch.
     *
     * No framework and no build step on purpose: this file is meant to be read
     * by somebody's security officer before it is carried into a room, and a
     * bundle nobody can read is a bundle nobody will allow in.
     */
    private static function script(): string
    {
        return <<<'JS'
            (function () {
              var D = JSON.parse(document.getElementById('data').textContent);
              var T = D.t, main = document.getElementById('main'), clock = document.getElementById('clock');
              var state = {step: 'intro', index: 0, context: {}, answers: [], record: [], feedback: {},
                           startedAt: 0, servedAt: 0};

              function esc(s) {
                return String(s === undefined || s === null ? '' : s)
                  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;');
              }
              function fmt(template, value) { return String(template).replace('%s', value); }
              function seconds() { return Math.round((Date.now() - state.servedAt) / 100) / 10; }
              function duration(s) {
                return s < 60 ? Math.round(s) + ' s'
                  : Math.floor(s / 60) + ' min ' + String(Math.round(s % 60)).padStart(2, '0') + ' s';
              }

              setInterval(function () {
                if (!state.startedAt) { return; }
                var t = Math.floor((Date.now() - state.startedAt) / 1000);
                clock.textContent = Math.floor(t / 60) + ':' + String(t % 60).padStart(2, '0');
              }, 1000);

              function intro() {
                var rows = D.subjects.map(function (s) {
                  var paths = s.paths.map(function (p) { return '<code>' + esc(p) + '</code>'; }).join(' ');
                  return '<li' + (s.paths.length > 1 ? ' class="many"' : '') + '><strong>' + esc(s.label) +
                         '</strong><span>' + esc(s.count) + ' · ' + paths + '</span></li>';
                }).join('');
                main.innerHTML = '<h1>' + esc(T.introTitle) + '</h1>' +
                  '<p class="purpose">' + esc(T.purpose) + '</p>' +
                  '<p class="lead">' + esc(T.lead) + '</p>' +
                  '<ol class="questions"><li>' + esc(T.q1) + '</li><li>' + esc(T.q2) + '</li><li>' +
                  esc(T.q3) + '</li></ol>' +
                  '<p>' + esc(T.rules) + '</p>' +
                  '<ul class="subjects">' + rows + '</ul>' +
                  '<div class="actions"><button type="button" id="go">' + esc(T.start) + '</button></div>' +
                  '<p class="note">' + esc(T.offlineNote) + '</p>';
                document.getElementById('go').addEventListener('click', function () {
                  state.startedAt = Date.now();
                  state.servedAt = Date.now();
                  state.step = 'context';
                  render();
                });
              }

              function context() {
                var regimes = D.regimes.map(function (r, i) {
                  return '<label class="choice"><input type="radio" name="regime" value="' + esc(r.key) + '"' +
                         (i === 0 ? ' checked' : '') + '> ' + esc(r.label) + '</label>';
                }).join('');
                main.innerHTML = '<h1>' + esc(T.contextTitle) + '</h1>' +
                  '<p class="lead">' + esc(T.contextLead) + '</p>' +
                  '<label class="field"><span class="q">' + esc(T.who) + '</span>' +
                  '<span class="hint">' + esc(T.whoHint) + '</span>' +
                  '<input type="text" id="who" autocomplete="off" autofocus></label>' +
                  '<label class="field"><span class="q">' + esc(T.service) + '</span>' +
                  '<input type="text" id="service" inputmode="numeric" placeholder="2032"></label>' +
                  '<div class="field" role="radiogroup" aria-labelledby="regime-q">' +
                  '<span class="q" id="regime-q">' + esc(T.regime) + '</span>' + regimes + '</div>' +
                  '<div class="actions"><button type="button" id="next">' + esc(T.next) + '</button></div>';
                document.getElementById('next').addEventListener('click', function () {
                  var year = parseInt(document.getElementById('service').value, 10);
                  state.context = {
                    who: document.getElementById('who').value.trim(),
                    regime: (document.querySelector('input[name=regime]:checked') || {}).value || 'general'
                  };
                  if (year >= 2024 && year <= 2100) { state.context.service_until = year; }
                  state.contextSeconds = seconds();
                  state.step = 'subject';
                  state.servedAt = Date.now();
                  render();
                });
              }

              function subject() {
                var s = D.subjects[state.index];
                var used = state.answers.map(function (a) { return a.name; })
                  .filter(function (v, i, all) { return v && all.indexOf(v) === i; });
                var chips = used.length === 0 ? '' :
                  '<p class="used">' + esc(T.reuse) + ' ' + used.map(function (name) {
                    return '<button type="button" class="reuse" data-name="' + esc(name) + '">' + esc(name) + '</button>';
                  }).join(' ') + '</p>';
                var years = D.years.map(function (y) {
                  return '<label class="year"><input type="radio" name="harm" value="' + y.value + '"> ' +
                         esc(s.signature ? y.trust : y.harm) + '</label>';
                }).join('');
                var where = s.paths.length > 1 ? s.paths.join(', ') : s.names.join(', ');

                main.innerHTML = '<h1>' + esc(s.title) + '</h1>' +
                  '<p class="found">' + esc(s.found) + '</p>' +
                  (s.technical ? '<p class="technical">' + esc(T.technicalNote) + '</p>' : '') +
                  (!s.technical && !s.decides ? '<p class="technical">' + esc(T.noopNote) + '</p>' : '') +
                  '<label class="field"><span class="q">' + esc(T.name) + '</span>' +
                  '<span class="hint">' + esc(T.nameHint) + '</span>' +
                  '<input type="text" id="name" value="' + esc(s.suggested) + '" autocomplete="off" autofocus></label>' +
                  chips +
                  '<div class="field" role="radiogroup" aria-labelledby="harm-q">' +
                  '<span class="q" id="harm-q">' + esc(s.signature ? T.trust : T.harm) + '</span>' +
                  '<span class="hint">' + esc(s.signature ? T.trustHint : T.harmHint) + '</span>' +
                  '<div class="years">' + years + '</div></div>' +
                  '<label class="field optional"><span class="q">' + esc(T.retention) + '</span>' +
                  '<span class="hint">' + esc(T.retentionHint) + '</span>' +
                  '<input type="text" id="retention" inputmode="numeric" autocomplete="off"></label>' +
                  '<label class="field optional"><span class="q">' + esc(T.note) + '</span>' +
                  '<textarea id="note" rows="3"></textarea></label>' +
                  '<div class="actions"><button type="button" id="answer">' + esc(T.next) + '</button>' +
                  '<button type="button" id="unknown" class="ghost">' + esc(T.unknown) + '</button>' +
                  '<button type="button" id="skip" class="ghost">' + esc(T.skip) + '</button></div>' +
                  '<p class="where">' + esc(fmt(T.where, where)) + '</p>';

                Array.prototype.forEach.call(document.querySelectorAll('.reuse'), function (b) {
                  b.addEventListener('click', function () { document.getElementById('name').value = b.dataset.name; });
                });
                document.getElementById('answer').addEventListener('click', function () { record('answer'); });
                document.getElementById('unknown').addEventListener('click', function () { record('unknown'); });
                document.getElementById('skip').addEventListener('click', function () { record('skip'); });
              }

              function place(paths) {
                return paths.length > 1 ? paths[0] + ' +' + (paths.length - 1) : paths[0];
              }

              function record(action) {
                var s = D.subjects[state.index];
                var name = document.getElementById('name').value.trim();
                var took = seconds();

                if (action !== 'answer' || name === '') {
                  state.record.push({area: place(s.paths), places: s.paths, skipped: true,
                                     reason: action === 'unknown' ? 'does_not_know' : 'skipped', seconds: took});
                } else {
                  var picked = document.querySelector('input[name=harm]:checked');
                  var harm = picked ? parseInt(picked.value, 10) : 0;
                  var retention = parseInt(document.getElementById('retention').value, 10);
                  if (isNaN(retention) || retention < 0) { retention = 0; }
                  // Whichever is longer: data you must keep is data that can
                  // still be stolen. The same rule as Interview::lifetime.
                  var lifetime = Math.max(harm, retention);
                  state.answers.push({name: name, paths: s.patterns, lifetime: lifetime,
                                      note: document.getElementById('note').value.trim(),
                                      trust_anchor: s.signature && harm >= 10,
                                      declared_by: state.context.who || ''});
                  state.record.push({area: place(s.paths), places: s.paths, name: name,
                                     retention_years: retention, harm_years: harm,
                                     lifetime_years: lifetime, skipped: false, seconds: took});
                }

                state.index += 1;
                state.servedAt = Date.now();
                state.step = state.index >= D.subjects.length ? 'feedback' : 'subject';
                render();
              }

              function feedback() {
                main.innerHTML = '<h1>' + esc(T.feedbackTitle) + '</h1>' +
                  '<p class="lead">' + esc(T.feedbackLead) + '</p>' +
                  '<label class="field"><span class="q">' + esc(T.missing) + '</span>' +
                  '<textarea id="missing" rows="4" autofocus></textarea></label>' +
                  '<label class="field"><span class="q">' + esc(T.unclear) + '</span>' +
                  '<textarea id="unclear" rows="4"></textarea></label>' +
                  '<div class="actions"><button type="button" id="finish">' + esc(T.finish) + '</button></div>';
                document.getElementById('finish').addEventListener('click', function () {
                  state.feedback = {missing: document.getElementById('missing').value.trim(),
                                    unclear: document.getElementById('unclear').value.trim(),
                                    seconds: seconds()};
                  state.step = 'done';
                  render();
                });
              }

              function payload() {
                return {
                  format: D.format,
                  project: D.project,
                  generated_on: D.generated_on,
                  answered_on: new Date().toISOString().slice(0, 10),
                  elapsed_seconds: Math.round((Date.now() - state.startedAt) / 1000),
                  context: state.context,
                  context_seconds: state.contextSeconds || 0,
                  answers: state.answers,
                  record: state.record,
                  feedback: state.feedback
                };
              }

              function done() {
                var text = JSON.stringify(payload(), null, 2);
                var rows = state.record.map(function (r) {
                  var middle = r.skipped ? (r.reason === 'does_not_know' ? T.doesNotKnow : T.skipped)
                                         : r.lifetime_years + ' ' + T.years;
                  return '<tr><td>' + esc(r.area) + '</td><td>' + esc(r.name || '—') + '</td>' +
                         '<td class="n">' + esc(middle) + '</td><td class="n">' + Math.round(r.seconds) + ' s</td></tr>';
                }).join('');
                main.innerHTML = '<h1>' + esc(T.doneTitle) + '</h1>' +
                  '<p class="lead">' + esc(T.doneLead.replace('%d', state.answers.length)
                    .replace('%s', duration(Math.round((Date.now() - state.startedAt) / 1000)))) + '</p>' +
                  '<table>' + rows + '</table>' +
                  '<p>' + esc(T.handBack) + '</p>' +
                  '<div class="row"><button type="button" id="dl">' + esc(T.download) + '</button>' +
                  '<button type="button" id="cp" class="ghost">' + esc(T.copy) + '</button></div>' +
                  '<textarea class="out" id="json" readonly rows="12"></textarea>';
                document.getElementById('json').value = text;
                document.getElementById('dl').addEventListener('click', function () {
                  var blob = new Blob([text], {type: 'application/json'});
                  var a = document.createElement('a');
                  a.href = URL.createObjectURL(blob);
                  a.download = 'reponses-' + D.project.replace(/[^A-Za-z0-9._-]+/g, '-') + '.json';
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
                });
                document.getElementById('cp').addEventListener('click', function () {
                  var field = document.getElementById('json');
                  field.select();
                  try { document.execCommand('copy'); } catch (e) { /* the textarea is still selected */ }
                  document.getElementById('cp').textContent = T.copied;
                });
              }

              function render() {
                ({intro: intro, context: context, subject: subject, feedback: feedback, done: done})[state.step]();
                window.scrollTo(0, 0);
              }

              render();
            })();
            JS;
    }
}
