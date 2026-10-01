<?php

declare(strict_types=1);

namespace Sablier;

/**
 * PDF export, by borrowing a browser the system already has.
 *
 * Same rule as the TLS probe: use a tool that is present, never add a
 * dependency, and say plainly when it is missing instead of failing quietly.
 * Bundling a PDF engine in a tool that reads cryptographic material would mean
 * shipping a large third-party renderer to defend forever, for a feature the
 * reader can also get with Ctrl-P.
 */
final class Pdf
{
    /** Tried in order; the first one that exists wins. */
    private const array CANDIDATES = [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        'google-chrome-stable',
        'google-chrome',
        'chromium-browser',
        'chromium',
        'microsoft-edge',
    ];

    /**
     * Glob patterns tried last: a Chromium a developer tool already downloaded.
     * Not a browser the system installed, so it comes after everything else —
     * but on a development machine it is often the only one there.
     */
    private const array FALLBACK_GLOBS = [
        '~/Library/Caches/ms-playwright/chromium*/chrome-mac/headless_shell',
        '~/Library/Caches/ms-playwright/chromium*/chrome-mac/Chromium.app/Contents/MacOS/Chromium',
        '~/.cache/ms-playwright/chromium*/chrome-linux/headless_shell',
        '~/.cache/ms-playwright/chromium*/chrome-linux/chrome',
        '~/.cache/puppeteer/chrome/*/chrome-linux64/chrome',
    ];

    public static function browser(): ?string
    {
        foreach (self::CANDIDATES as $candidate) {
            if (str_contains($candidate, '/')) {
                if (is_executable($candidate)) {
                    return $candidate;
                }
                continue;
            }
            $found = trim((string) @shell_exec('command -v '.escapeshellarg($candidate).' 2>/dev/null'));
            if ($found !== '') {
                return $found;
            }
        }

        $home = getenv('HOME') ?: '';
        foreach (self::FALLBACK_GLOBS as $pattern) {
            foreach (glob(str_replace('~', $home, $pattern)) ?: [] as $match) {
                if (is_executable($match)) {
                    return $match;
                }
            }
        }

        return null;
    }

    /** @return array{0:bool, 1:string} success and a message for the operator */
    public static function render(string $htmlPath, string $pdfPath): array
    {
        $browser = self::browser();
        if ($browser === null) {
            return [false, Lang::t('pdf.no_browser')];
        }

        $absolute = realpath($htmlPath);
        if ($absolute === false) {
            return [false, Lang::t('pdf.missing_html', $htmlPath)];
        }

        $printable = self::unfolded($absolute);

        // A private profile in a temporary directory: the export must not touch
        // the operator's own browser session.
        $profile = sys_get_temp_dir().'/sablier-pdf-'.bin2hex(random_bytes(4));
        $command = \sprintf(
            '%s --headless --disable-gpu --no-sandbox --user-data-dir=%s --no-pdf-header-footer --print-to-pdf=%s %s 2>/dev/null',
            escapeshellarg($browser),
            escapeshellarg($profile),
            escapeshellarg($pdfPath),
            escapeshellarg('file://'.($printable ?? $absolute)),
        );
        @shell_exec($command);
        self::removeDirectory($profile);
        if ($printable !== null) {
            @unlink($printable);
        }

        if (!is_file($pdfPath) || filesize($pdfPath) === 0) {
            return [false, Lang::t('pdf.failed', basename($browser))];
        }

        return [true, Lang::t('pdf.written', $pdfPath, number_format(filesize($pdfPath) / 1024, 0, ',', ' '))];
    }

    /**
     * The same report, with every disclosure already open.
     *
     * A reader can click a <details>; paper cannot. Printing the file as it
     * stands turns each collapsed block into a question with no answer under
     * it, so the export prints a copy with the attribute set rather than
     * relying on a print rule the installed Chrome may not know yet. The copy
     * is a temporary file next to the report's own directory contents, deleted
     * as soon as the browser is done, and it is still only ever read from
     * disk: nothing is sent anywhere.
     *
     * Returns null when the copy cannot be written — printing the original is
     * a worse PDF, not a failure.
     */
    private static function unfolded(string $htmlPath): ?string
    {
        $html = @file_get_contents($htmlPath);
        if ($html === false) {
            return null;
        }

        $opened = preg_replace('/<details(?![^>]*\bopen\b)/i', '<details open', $html);
        if ($opened === null) {
            return null;
        }

        $copy = sys_get_temp_dir().'/sablier-print-'.bin2hex(random_bytes(4)).'.html';

        return @file_put_contents($copy, $opened) === false ? null : $copy;
    }

    private static function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($path);
    }
}
