<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The questions, and who they are for.
 *
 * Every verdict in this tool rests on one number nobody can read from code:
 * how long each kind of data has to stay confidential. The scoping study calls
 * this the thing that can kill the project, and it is right — not because the
 * number is hard to compute, but because the person who knows it does not
 * write code, and has never been asked to put it into words.
 *
 * So the interview does not ask for it. It asks two questions people answer
 * every week:
 *
 *   · **how long must you keep this?** Retention is a legal fact somebody in
 *     the company already knows, written in an accountant's contract or a
 *     regulation. Nobody hesitates on it;
 *   · **if it leaked, how long would it still hurt?** The answer is usually
 *     shorter than retention and occasionally much longer, and the gap between
 *     the two is the most interesting thing said in the whole session.
 *
 * The lifetime is the larger of the two, because data that must be kept is
 * data that still exists to be stolen. Deriving it rather than asking for it
 * is the entire point: a question somebody can answer produces a number, and a
 * question nobody can answer produces a blank file and a tool nobody uses.
 *
 * Two refusals, for the same reason as everywhere else in this codebase. The
 * interview starts from paths the scan actually found, so the questions are
 * about files that exist rather than about categories somebody invented. And
 * an answer it does not understand is asked again rather than guessed at — a
 * declaration filled with defaults nobody chose is worse than no declaration,
 * because the report would wear its confident typeface over it.
 */
final class Interview
{
    /**
     * What to ask about, grouped so that one subject is one question.
     *
     * The first run against a real project asked eight questions, three of
     * which were `.env`, `.env.dev` and `.env.test` — the same subject, to
     * somebody who cannot tell those files apart and should not have to. It
     * also asked about two images whose extension lies about their content,
     * which is a developer's confirmation and not a business decision.
     *
     * So: files at the root that share a stem are one area, and a finding with
     * no identified algorithm raises no question here. Both refusals buy the
     * same thing — an hour spent on the questions only this person can answer.
     *
     * Areas that would be introduced by the same sentence are then one subject,
     * however many directories they live in. Five places computing a fingerprint
     * were five questions whose only difference was a directory name nobody in
     * the room recognises; the question now names the five places and is asked
     * once. If the answer turns out to differ from one to the next, that is a
     * second domain somebody adds to the declaration afterwards — which is a
     * decision, where five identical questions were only a toll.
     *
     * @param list<Finding> $findings
     *
     * @return list<array{path:string, paths:list<string>, pattern:string, patterns:list<string>, decides:bool, files:int, names:list<string>, algorithms:list<string>}>
     */
    public static function areas(array $findings, Declaration $declaration): array
    {
        $areas = [];
        foreach ($findings as $finding) {
            // Already declared, or not a question for this room: a digest used
            // as a cache key needs no lifetime, and neither does a file whose
            // algorithm nobody could read.
            if ($finding->domainDeclared
                || $finding->verdict === Assessor::NOISE
                || $finding->algorithm === 'undetermined') {
                continue;
            }

            [$path, $pattern] = self::area($finding->file);
            $areas[$path]['pattern'] = $pattern;
            // Whether an answer here can change anything. SHA-256 is sound at
            // every lifetime, so a subject made only of it is a minute spent
            // for nothing — and on one real project it was the first question
            // of the session. Asked last rather than dropped: the declaration
            // outlives this scan, and the next one may find something there.
            $areas[$path]['decides'] = ($areas[$path]['decides'] ?? false)
                || $finding->verdict !== Assessor::CLEAR;
            $areas[$path]['files'][$finding->file] = true;
            $areas[$path]['algorithms'][$finding->algorithm] = true;
        }

        $out = [];
        foreach ($areas as $path => $area) {
            $names = array_keys($area['files']);
            sort($names);
            $out[] = [
                'path' => $path,
                'pattern' => $area['pattern'],
                'decides' => $area['decides'],
                'files' => \count($names),
                'names' => \array_slice($names, 0, 3),
                'algorithms' => array_keys($area['algorithms']),
            ];
        }

        usort($out, static fn (array $a, array $b): int => [$b['decides'], $b['files']] <=> [$a['decides'], $a['files']]
            ?: strcmp($a['path'], $b['path']));

        // One subject per sentence. The label is what the agenda prints, so two
        // areas sharing it are, to the person being asked, the same question.
        $merged = [];
        foreach ($out as $area) {
            $key = self::label($area['algorithms']);
            if (!isset($merged[$key])) {
                $merged[$key] = [
                    'path' => $area['path'],
                    'paths' => [$area['path']],
                    'pattern' => $area['pattern'],
                    'patterns' => [$area['pattern']],
                    'decides' => $area['decides'],
                    'files' => $area['files'],
                    'names' => $area['names'],
                    'algorithms' => $area['algorithms'],
                ];

                continue;
            }

            $merged[$key]['paths'][] = $area['path'];
            $merged[$key]['patterns'][] = $area['pattern'];
            $merged[$key]['decides'] = $merged[$key]['decides'] || $area['decides'];
            $merged[$key]['files'] += $area['files'];
            $merged[$key]['names'] = \array_slice([...$merged[$key]['names'], ...$area['names']], 0, 3);
            $merged[$key]['algorithms'] = array_values(array_unique([...$merged[$key]['algorithms'], ...$area['algorithms']]));
        }

        $out = array_values($merged);
        usort($out, static fn (array $a, array $b): int => [$b['decides'], $b['files']] <=> [$a['decides'], $a['files']]
            ?: strcmp($a['path'], $b['path']));

        return $out;
    }

    /**
     * How a subject is named in the record, when it covers several places.
     *
     * The log is read in a table, and five directories spelled out push the
     * duration off the edge. The first place plus a count says as much in a
     * column that fits; the declaration holds the five paths in full.
     *
     * @param list<string> $paths
     */
    public static function where(array $paths): string
    {
        $first = $paths[0] ?? '';

        return \count($paths) > 1 ? \sprintf('%s +%d', $first, \count($paths) - 1) : $first;
    }

    /**
     * What was found here, said without a single technical word.
     *
     * The first dry run showed an area as "`.env` — cryptographie relevée :
     * Aucun chiffrement", which loses a non-technical person in two lines and
     * takes the session with them. The tool knows what it found; it does not
     * know what the data is. So it describes the first in plain language and
     * asks about the second, instead of printing an algorithm name and hoping.
     *
     * Priority rather than a list: an area holds several findings, and the one
     * that sets the scene is the most telling, not the most frequent.
     *
     * @param list<string> $algorithms
     */
    public static function subject(array $algorithms): string
    {
        $has = static fn (string ...$wanted): bool => array_intersect($wanted, $algorithms) !== [];

        return match (true) {
            $has('plaintext') => 'declare.subject.plaintext',
            $has('ecdh', 'dh') => 'declare.subject.vault',
            $has('rsa') => 'declare.subject.asymmetric',
            $has('aes-128', 'aes-256', 'chacha20', 'des', 'rc4') => 'declare.subject.encrypted',
            $has('rsa-sign', 'ecdsa', 'ed25519', 'ml-dsa') => 'declare.subject.signature',
            $has('bcrypt', 'argon2') => 'declare.subject.passwords',
            $has('md5', 'sha1', 'sha256', 'sha512') => 'declare.subject.digest',
            default => 'declare.subject.other',
        };
    }

    /**
     * How long a declared lifetime goes unquestioned before it is stale.
     *
     * Two years: long enough that nobody is asked the same question twice a
     * year, short enough that the person who answered is probably still there
     * to be asked again.
     */
    public const int STALE_AFTER_YEARS = 2;

    /** @param list<array{declared_on?:string}> $domains */
    public static function stale(array $domains, ?\DateTimeImmutable $now = null): int
    {
        $now ??= new \DateTimeImmutable();
        $limit = $now->modify('-'.self::STALE_AFTER_YEARS.' years');

        $count = 0;
        foreach ($domains as $domain) {
            $on = $domain['declared_on'] ?? '';
            $date = $on === '' ? false : \DateTimeImmutable::createFromFormat('Y-m-d', $on);
            if ($date !== false && $date < $limit) {
                ++$count;
            }
        }

        return $count;
    }

    /**
     * Whether this subject is about proving who sent something.
     *
     * The duration question — "if this got out, how long would it hurt" —
     * assumes the thing is secret. A signature is not: it is published on
     * purpose, and what matters is how long somebody must still be able to
     * prove it was yours. Asking the confidentiality question there produces
     * an answer to a question nobody asked.
     *
     * @param list<string> $algorithms
     */
    public static function isSignature(array $algorithms): bool
    {
        return self::subject($algorithms) === 'declare.subject.signature';
    }

    /**
     * The same thing in three words, for a list rather than a question.
     *
     * The sentence above introduces a subject somebody is about to be asked
     * about; stacked three times on an agenda it reads as the same paragraph
     * repeated, and the reader cannot tell the items apart. A list wants a
     * label, the question wants a sentence, and they are not the same text.
     *
     * @param list<string> $algorithms
     */
    public static function label(array $algorithms): string
    {
        return self::subject($algorithms).'.label';
    }

    /**
     * The subject a file belongs to, and the pattern that will catch its kin.
     *
     * Two levels of directory at most: `src/Billing/Application/Foo.php` is the
     * billing domain, and nobody in a meeting calls it anything else. At the
     * root, the stem before the first dot: `.env.test` belongs with `.env`,
     * and `Caddyfile` belongs with itself.
     *
     * @return array{0:string, 1:string} the label, then the glob for the declaration
     */
    public static function area(string $file): array
    {
        $directory = \dirname($file);
        if ($directory === '.' || $directory === '') {
            $name = basename($file);
            $stem = str_starts_with($name, '.')
                ? '.'.explode('.', substr($name, 1))[0]
                : explode('.', $name)[0];

            return $stem === $name ? [$name, $name] : [$stem, $stem.'*'];
        }

        $parts = explode('/', $directory);
        $label = \count($parts) <= 2 ? $directory : implode('/', \array_slice($parts, 0, 2));

        return [$label, $label.'/*'];
    }

    /**
     * Retention and damage in, one lifetime out.
     *
     * The larger of the two, because data kept is data that can still be
     * stolen, and a leak that stops hurting before the retention ends does not
     * shorten the window an adversary has to work with.
     */
    public static function lifetime(int $retentionYears, int $damageYears): int
    {
        return max(0, $retentionYears, $damageYears);
    }

    /**
     * The declaration as it will be written, with the answers folded in.
     *
     * The existing file is kept whole: an interview adds domains, it never
     * silently rewrites a lifetime somebody argued about last quarter.
     *
     * @param array<string, mixed>                                                    $existing
     * @param list<array{name:string, paths:list<string>, lifetime:int, note:string, trust_anchor?:bool, declared_by?:string}> $answers
     *
     * @return array<string, mixed>
     */
    public static function merge(array $existing, array $answers): array
    {
        $domains = Value::map($existing['domains'] ?? null);
        foreach ($answers as $answer) {
            // The same name given twice is the same data in two places, not a
            // second domain overwriting the first. A dry run produced "accès
            // technique" and "acces" for two areas, and an earlier version
            // would have kept one path and silently dropped the other.
            $existingDomain = Value::map($domains[$answer['name']] ?? null);
            $paths = [...Value::strings($existingDomain['paths'] ?? null), ...$answer['paths']];
            $domain = [
                'paths' => array_values(array_unique($paths)),
                'lifetime_years' => max($answer['lifetime'], Value::int($existingDomain['lifetime_years'] ?? null)),
                'note' => trim(Value::string($existingDomain['note'] ?? null).' '.$answer['note']),
            ];
            // A lifetime nobody signed is a lifetime nobody will revisit.
            if (($answer['declared_by'] ?? '') !== '') {
                $domain['declared_by'] = $answer['declared_by'];
            }
            $domain['declared_on'] = (new \DateTimeImmutable())->format('Y-m-d');
            // A long-lived trust anchor is a different claim from a long-lived
            // secret, and the declaration has a word for it.
            if (($answer['trust_anchor'] ?? false) === true) {
                $domain['trust_anchor'] = true;
            }
            $domains[$answer['name']] = $domain;
        }

        $existing['domains'] = $domains;

        return $existing;
    }
}
