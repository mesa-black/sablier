<?php

declare(strict_types=1);

namespace Sablier;

/**
 * A set of files, sealed as the files they are.
 *
 * The findings signature covers what a scan found; the page signature covers
 * one page. Neither covers data somebody publishes — a month of measurements,
 * a directory of evidence — and those are exactly the files a reader wants to
 * know were not touched after the date they were said to be taken.
 *
 * A seal is one file, `seal.sig`, inside the directory it covers. It lists
 * every other file in it, recursively, each with its size and its SHA-256, and
 * signs a digest of that list with the same key and the same two schemes as a
 * report. The tokens and the proof that date it sit beside it under the names
 * a report's do: `seal.tsr`, `seal.2.tsr`, `seal.ots`.
 *
 * The digest is computed over a canonical text that starts with its own label,
 * `sablier-files/1`, so a seal can never be passed off as a findings signature:
 * the same bytes signed for one purpose do not verify for the other. The list
 * itself is in the file in clear, for the reader; it is not trusted, it is
 * recomputed into the digest the signature covers, so a list edited by hand
 * fails before any file on disk is looked at.
 */
final class Seal
{
    public const string LABEL = 'sablier-files/1';

    public const string FILE = 'seal.sig';

    /** Where the seal of a directory is written, and what its tokens and proof are named after. */
    public static function path(string $dir): string
    {
        return rtrim($dir, '/').'/'.self::FILE;
    }

    /** The name the tokens and the proof hang off: `seal`, so `seal.tsr`, `seal.ots`. */
    public static function base(string $dir): string
    {
        return rtrim($dir, '/').'/seal';
    }

    /**
     * Every file under a directory, as the seal lists it.
     *
     * Sorted by path with a byte comparison, so the list does not depend on
     * the order a filesystem returns entries in, nor on the locale. The seal
     * and the artefacts that date it are left out — they cannot cover
     * themselves — and so is nothing else: a file nobody meant to publish is
     * still a file a reader is handed, and leaving it out silently would let
     * it change unseen.
     *
     * A symbolic link is refused rather than followed: what it points at is
     * not in the directory, and its target can change without a byte of the
     * directory changing.
     *
     * @return array{files:list<array{path:string, size:int, sha256:string}>, refused:list<string>}
     */
    public static function inventory(string $dir): array
    {
        $root = rtrim($dir, '/');
        $files = [];
        $refused = [];
        $walk = static function (string $relative) use (&$walk, &$files, &$refused, $root): void {
            $here = $relative === '' ? $root : $root.'/'.$relative;
            $entries = scandir($here);
            if ($entries === false) {
                $refused[] = $relative === '' ? '.' : $relative;

                return;
            }
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $path = $relative === '' ? $entry : $relative.'/'.$entry;
                $full = $root.'/'.$path;
                if (is_link($full)) {
                    $refused[] = $path;
                } elseif (is_dir($full)) {
                    $walk($path);
                } elseif ($relative !== '' || !self::isOwn($entry)) {
                    $hash = hash_file('sha256', $full);
                    $size = filesize($full);
                    if ($hash === false || $size === false) {
                        $refused[] = $path;
                    } else {
                        $files[] = ['path' => $path, 'size' => $size, 'sha256' => $hash];
                    }
                }
            }
        };
        $walk('');
        usort($files, static fn (array $a, array $b): int => strcmp($a['path'], $b['path']));
        sort($refused, \SORT_STRING);

        return ['files' => $files, 'refused' => $refused];
    }

    /**
     * The digest a seal signs: the canonical text of its list.
     *
     * One line per file, `sha256 size path`, in the order given, which
     * inventory() makes canonical. A path cannot hold a newline here: a file
     * named with one would otherwise be able to forge a second line.
     *
     * @param list<array{path:string, size:int, sha256:string}> $files
     */
    public static function digest(array $files): string
    {
        $lines = [self::LABEL];
        foreach ($files as $file) {
            $lines[] = $file['sha256'].' '.$file['size'].' '.str_replace(["\n", "\r"], ['\n', '\r'], $file['path']);
        }

        return hash('sha256', implode("\n", $lines)."\n");
    }

    /**
     * The list a seal carries, read back without trusting its shape.
     *
     * @param array<mixed> $block
     *
     * @return list<array{path:string, size:int, sha256:string}>|null null when the list is not one
     */
    public static function listed(array $block): ?array
    {
        $listed = $block['files'] ?? null;
        if (!\is_array($listed) || !array_is_list($listed)) {
            return null;
        }
        $files = [];
        foreach ($listed as $file) {
            if (!\is_array($file)
                || !\is_string($file['path'] ?? null) || $file['path'] === ''
                || !\is_int($file['size'] ?? null)
                || !\is_string($file['sha256'] ?? null) || preg_match('/^[0-9a-f]{64}$/', $file['sha256']) !== 1) {
                return null;
            }
            $files[] = ['path' => $file['path'], 'size' => $file['size'], 'sha256' => $file['sha256']];
        }

        return $files;
    }

    /**
     * What differs between the files a seal lists and the files on disk.
     *
     * Three kinds, kept apart because they call for three different
     * questions: a file changed, a file that is gone, a file that appeared.
     *
     * @param list<array{path:string, size:int, sha256:string}> $sealed
     * @param list<array{path:string, size:int, sha256:string}> $present
     *
     * @return array{modified:list<array{path:string, sealed:int, size:int}>, missing:list<string>, added:list<string>}
     */
    public static function compare(array $sealed, array $present): array
    {
        $now = [];
        foreach ($present as $file) {
            $now[$file['path']] = $file;
        }
        $modified = [];
        $missing = [];
        foreach ($sealed as $file) {
            $here = $now[$file['path']] ?? null;
            unset($now[$file['path']]);
            if ($here === null) {
                $missing[] = $file['path'];
            } elseif (!hash_equals($file['sha256'], $here['sha256'])) {
                $modified[] = ['path' => $file['path'], 'sealed' => $file['size'], 'size' => $here['size']];
            }
        }

        // The paths from the entries, not the keys: PHP turns a key like "2"
        // into an integer, and a file named 2 would come back as a number.
        return ['modified' => $modified, 'missing' => $missing, 'added' => array_values(array_map(static fn (array $f): string => $f['path'], $now))];
    }

    /** The seal and what dates it: never listed, since they cannot cover themselves. */
    private static function isOwn(string $name): bool
    {
        return $name === self::FILE
            || $name === 'seal.ots'
            || preg_match('/^seal(\.\d+)?\.tsr$/', $name) === 1;
    }
}
