<?php

declare(strict_types=1);

namespace Sablier;

use Sablier\Detector\DetectorInterface;

/**
 * Walks a tree and offers each file to the detectors.
 *
 * It knows how to traverse and what to skip. It knows nothing about
 * cryptography, about PHP, about certificates — adding a language or a file
 * format now means writing a detector and registering it, never touching this
 * class.
 */
final class Scanner
{
    /**
     * Matched on every path segment, not just the prefix: the first real scan
     * counted an entire project twice because a git worktree sat inside it, and
     * a nested vendor/ was read in full.
     */
    private const array SKIP_DIRS = ['.git', '.kilo', '.idea', '.vscode', '.svn', 'vendor', 'node_modules', 'var', 'build'];

    private const int MAX_BYTES = 2_000_000;

    /**
     * @param list<DetectorInterface> $detectors
     * @param list<string>   $exclude globs from the declaration, matched on the relative path
     */
    public function __construct(
        private readonly array $detectors,
        private readonly array $exclude = [],
    ) {
    }

    /** @return array{findings: list<Finding>, files: int, blind: list<string>, searched: array<string, array{files:int, findings:int}>} */
    public function scan(string $root): array
    {
        $root = rtrim(realpath($root) ?: $root, '/');
        $findings = [];
        $files = 0;

        // What each detector actually opened, and what it produced. A report
        // that lists what it did not look at owes the other half of the
        // sentence: the things it did look for and did not find. Without this
        // tally, "no private key in this repository" and "nobody looked" print
        // as the same silence.
        //
        // The names are resolved once: a reflection call per detector per file
        // would make an honest claim cost a measurable part of the scan.
        $names = [];
        $opened = [];
        $produced = [];
        foreach ($this->detectors as $index => $detector) {
            $names[$index] = (new \ReflectionClass($detector))->getShortName();
            $opened[$names[$index]] = 0;
            $produced[$names[$index]] = 0;
        }

        foreach ($this->walk($root) as $file) {
            ++$files;
            foreach ($this->detectors as $index => $detector) {
                if (!$detector->supports($file)) {
                    continue;
                }
                ++$opened[$names[$index]];
                foreach ($detector->detect($file) as $finding) {
                    $findings[] = $finding;
                    ++$produced[$names[$index]];
                }
            }
        }

        $searched = [];
        foreach ($opened as $name => $count) {
            $searched[$name] = ['files' => $count, 'findings' => $produced[$name]];
        }

        $blind = [];
        foreach ($this->detectors as $detector) {
            $blind = [...$blind, ...$detector->blindSpots()];
        }

        return [
            'findings' => $findings,
            'files' => $files,
            'blind' => array_values(array_unique($blind)),
            'searched' => $searched,
        ];
    }

    /** @return \Generator<SourceFile> */
    private function walk(string $root): \Generator
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                static function (\SplFileInfo $file) use ($root): bool {
                    $relative = ltrim(str_replace($root, '', $file->getPathname()), '/');

                    return array_intersect(explode('/', $relative), self::SKIP_DIRS) === [];
                },
            ),
        );

        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile() || $file->getSize() > self::MAX_BYTES) {
                continue;
            }

            $source = SourceFile::fromSplFileInfo($file, $root);
            foreach ($this->exclude as $glob) {
                if (fnmatch($glob, $source->relativePath, \FNM_NOESCAPE)) {
                    continue 2;
                }
            }

            yield $source;
        }
    }
}
