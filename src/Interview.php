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
     * What to ask about, grouped by the directory the findings sit in.
     *
     * One question per area rather than per finding: nobody can answer
     * twenty-three times, and the fifth answer would be noise anyway.
     *
     * @param list<Finding> $findings
     *
     * @return list<array{path:string, files:int, algorithms:list<string>}>
     */
    public static function areas(array $findings, Declaration $declaration): array
    {
        $areas = [];
        foreach ($findings as $finding) {
            // Already declared, or not worth a question: a digest used as a
            // cache key does not need a confidentiality lifetime.
            if ($finding->domainDeclared || $finding->verdict === Assessor::NOISE) {
                continue;
            }

            $path = self::area($finding->file);
            $areas[$path]['files'][$finding->file] = true;
            $areas[$path]['algorithms'][$finding->algorithm] = true;
        }

        $out = [];
        foreach ($areas as $path => $area) {
            $out[] = [
                'path' => $path,
                'files' => \count($area['files']),
                'algorithms' => array_values(array_filter(
                    array_keys($area['algorithms']),
                    static fn (string $algorithm): bool => $algorithm !== 'undetermined',
                )),
            ];
        }

        usort($out, static fn (array $a, array $b): int => $b['files'] <=> $a['files'] ?: strcmp($a['path'], $b['path']));

        return $out;
    }

    /**
     * The directory that reads like a subject rather than a file.
     *
     * Two levels at most: `src/Billing/Application/Foo.php` is the billing
     * domain, and nobody in a meeting calls it anything else.
     */
    public static function area(string $file): string
    {
        $directory = \dirname($file);
        if ($directory === '.' || $directory === '') {
            return $file;
        }

        $parts = explode('/', $directory);

        return \count($parts) <= 2 ? $directory : implode('/', \array_slice($parts, 0, 2));
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
     * @param array<array-key, mixed>                                              $existing
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
