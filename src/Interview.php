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
     * @param list<Finding> $findings
     *
     * @return list<array{path:string, pattern:string, files:int, names:list<string>, algorithms:list<string>}>
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
                'files' => \count($names),
                'names' => \array_slice($names, 0, 3),
                'algorithms' => array_keys($area['algorithms']),
            ];
        }

        usort($out, static fn (array $a, array $b): int => $b['files'] <=> $a['files'] ?: strcmp($a['path'], $b['path']));

        return $out;
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
     * @param list<array{name:string, paths:list<string>, lifetime:int, note:string}> $answers
     *
     * @return array<string, mixed>
     */
    public static function merge(array $existing, array $answers): array
    {
        $domains = Value::map($existing['domains'] ?? null);
        foreach ($answers as $answer) {
            $domains[$answer['name']] = [
                'paths' => $answer['paths'],
                'lifetime_years' => $answer['lifetime'],
                'note' => $answer['note'],
            ];
        }

        $existing['domains'] = $domains;

        return $existing;
    }
}
