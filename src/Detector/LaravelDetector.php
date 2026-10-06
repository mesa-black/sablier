<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;
use Sablier\Value;

/**
 * Laravel's call sites, where the algorithm is somewhere else.
 *
 * The configuration detector already reads `config/app.php` and
 * `config/hashing.php` and reports the cipher and the password driver declared
 * there. That is one finding per application, and it says nothing about how much
 * of the application depends on it. `Crypt::encryptString()` called in forty
 * places is forty things to look at the day that cipher has to change, and this
 * tool measures exactly that — the migration effort is the third factor of the
 * risk model and the one it counts in places rather than estimating in days.
 *
 * Two decisions worth stating.
 *
 * **Medium confidence, on purpose.** The call does not name an algorithm: the
 * cipher comes from `config/app.php`, the hashing driver from
 * `config/hashing.php`. The algorithm written here is the default each of those
 * files ships with, and every value they accept lands on the same verdict —
 * `aes-128-cbc` and `aes-256-gcm` are both symmetric and both CLEAR, `bcrypt` and
 * `argon2id` likewise — so naming one cannot mislead the reader about what to do.
 * Where that is not true, this tool says `undetermined` and asks.
 *
 * **The bare helpers are read only in a file that knows Laravel.** `encrypt()`
 * and `decrypt()` are global functions with the most generic names in the
 * language; outside an application that imports `Illuminate`, they belong to
 * somebody else and mean something else.
 */
final class LaravelDetector implements DetectorInterface
{
    public function supports(SourceFile $file): bool
    {
        return $file->hasExtension('php');
    }

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();
        // The cheapest possible proof that this is a Laravel application, and
        // the guard that keeps `encrypt(` from meaning anything anywhere else.
        if (!str_contains($content, 'Illuminate\\')) {
            return;
        }

        $rules = [
            // The facades, which name themselves.
            ['/\bCrypt::(?:encrypt|decrypt)\w*\s*\(/', 'aes-256', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.laravel.crypt'],
            ['/\bHash::(?:make|check|needsRehash)\s*\(/', 'bcrypt', Catalogue::PURPOSE_INTEGRITY, 'detail.laravel.hash'],
            // The helpers, which do not.
            ['/(?<![\w>$])(?:encrypt|decrypt)\s*\(/', 'aes-256', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.laravel.crypt'],
            ['/(?<![\w>$])bcrypt\s*\(/', 'bcrypt', Catalogue::PURPOSE_INTEGRITY, 'detail.laravel.hash'],
        ];

        foreach ($rules as [$pattern, $algorithm, $purpose, $detail]) {
            if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }

            foreach ($matches[0] as [$hit, $rawOffset]) {
                $offset = Value::int($rawOffset);
                // A definition is not a use: `function encrypt(` in a helper
                // file would otherwise be counted as a call site, and the effort
                // figure is only worth printing if it counts calls.
                $before = substr($content, max(0, $offset - 20), min(20, $offset));
                if (preg_match('/\bfunction\s+$/', $before) === 1) {
                    continue;
                }

                yield new Finding(
                    algorithm: $algorithm,
                    purpose: $purpose,
                    file: $file->relativePath,
                    line: $file->lineAt($offset),
                    evidence: rtrim(trim(Value::string($hit)), '('),
                    confidence: Finding::CONFIDENCE_MEDIUM,
                    detail: Lang::t($detail),
                );
            }
        }
    }
}
