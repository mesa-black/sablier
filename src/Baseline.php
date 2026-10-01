<?php

declare(strict_types=1);

namespace Sablier;

/**
 * What changed since the last analysis, and whether a pipeline may pass.
 *
 * The hourglass metaphor demands this: a report identical to last year's can
 * turn red without a line of code moving, because the exposure window is
 * computed from today. A tool that only ever prints a snapshot cannot show
 * that, and a verdict nobody compares is a verdict nobody acts on.
 *
 * The reference is the JSON report of a previous run — no second format, and a
 * file meant to be versioned, so the movement is reviewed where the code is.
 *
 * It is explicitly **not** a suppression file. A red finding that already sat
 * in the reference still blocks, because the only thing that silences a
 * finding here is an acceptance: a reason, an expiry date, and a reviewer. A
 * baseline that mutes what it recorded is how these tools empty themselves out
 * within six months.
 */
final class Baseline
{
    /** @var array<string, array<array-key, mixed>> indexed by fingerprint */
    private array $rows = [];

    /** @param array<array-key, mixed> $rows */
    private function __construct(
        public readonly string $path,
        array $rows,
    ) {
        foreach ($rows as $row) {
            $row = Value::map($row);
            $fingerprint = Value::string($row['fingerprint'] ?? null);
            if ($fingerprint !== '') {
                $this->rows[$fingerprint] = $row;
            }
        }
    }

    /** Null when the file is missing or is not a JSON report: the caller says so and stops. */
    public static function load(string $path): ?self
    {
        if (!is_file($path)) {
            return null;
        }

        $rows = json_decode((string) file_get_contents($path), true);

        return \is_array($rows) ? new self($path, $rows) : null;
    }

    public function count(): int
    {
        return \count($this->rows);
    }

    /**
     * Severity is the order a human reads the verdicts in — there is no second
     * table to keep in step with the first.
     */
    private static function rank(string $verdict): int
    {
        /** @var array<string, int>|null $rank */
        static $rank = null;
        $rank ??= array_flip(array_reverse(Assessor::order()));

        return $rank[$verdict] ?? 0;
    }

    /**
     * Three reasons to stop, and one piece of good news.
     *
     * A finding appears once, under the first reason that catches it: a new
     * red finding is new, not new *and* red. Resolved findings never block —
     * they are printed because a baseline that only ever grows is one nobody
     * refreshes.
     *
     * @param list<Finding> $findings
     *
     * @return array{new: list<Finding>, worsened: list<array{finding: Finding, from: string}>, red: list<Finding>, resolved: list<array<array-key, mixed>>, decisions: int}
     */
    public function compare(array $findings): array
    {
        $new = $worsened = $red = [];
        $seen = [];

        foreach ($findings as $finding) {
            $fingerprint = $finding->fingerprint();
            $seen[$fingerprint] = true;
            $previous = $this->rows[$fingerprint] ?? null;

            if ($previous === null) {
                if (!\in_array($finding->verdict, [Assessor::CLEAR, Assessor::NOISE], true)) {
                    $new[] = $finding;
                }
                continue;
            }

            $before = Value::string($previous['verdict'] ?? null, $finding->verdict);
            if (self::rank($finding->verdict) > self::rank($before)) {
                $worsened[] = ['finding' => $finding, 'from' => $before];
                continue;
            }

            // Known, unchanged — and still red. An acceptance is the only way
            // out, which is the whole point: it carries a reason and a date.
            if (\in_array($finding->verdict, [Assessor::COMPROMISED, Assessor::URGENT], true)) {
                $red[] = $finding;
            }
        }

        $resolved = [];
        foreach ($this->rows as $fingerprint => $row) {
            $verdict = Value::string($row['verdict'] ?? null);
            if (!isset($seen[$fingerprint]) && !\in_array($verdict, [Assessor::CLEAR, Assessor::NOISE], true)) {
                $resolved[] = $row;
            }
        }

        return [
            'new' => $new,
            'worsened' => $worsened,
            'red' => $red,
            'resolved' => $resolved,
            'decisions' => \count($new) + \count($worsened) + \count($red),
        ];
    }
}
