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
    /**
     * Tried in order; the first one that exists wins.
     *
     * Absolute paths are macOS bundles, which no PATH lookup would find. The
     * bare names are for everywhere else: a Linux distribution puts its
     * browser in the PATH under one of these, whether it came from the
     * distribution, from Google's repository, from a snap shim in /snap/bin or
     * from flatpak's exported binaries. The two /opt paths are what the
     * Debian and RPM packages actually install behind their wrapper.
     */
    private const array CANDIDATES = [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        'google-chrome-stable',
        'google-chrome',
        'chrome',
        'chromium-browser',
        'chromium',
        'brave-browser',
        'microsoft-edge',
        'microsoft-edge-stable',
        '/snap/bin/chromium',
        '/opt/google/chrome/chrome',
        '/usr/lib/chromium/chromium',
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
        '~/.cache/puppeteer/chrome-headless-shell/*/chrome-headless-shell-linux64/chrome-headless-shell',
    ];

    /**
     * The browser of last resort, borrowed rather than installed.
     *
     * Same rule as the launcher that borrows a PHP: a machine without a
     * browser is not a machine that has to grow one, and asking an auditor to
     * install Chrome on a client's laptop to print a report is a worse answer
     * than a container that disappears afterwards. Alpine, and pinned —
     * `make cve` checks this image like the other three.
     */
    private const string CONTAINER_IMAGE = 'zenika/alpine-chrome:124';

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
        $absolute = realpath($htmlPath);
        if ($absolute === false) {
            return [false, Lang::t('pdf.missing_html', $htmlPath)];
        }

        $browser = self::browser();
        $container = $browser === null ? self::container() : null;
        if ($browser === null && $container === null) {
            return [false, Lang::t('pdf.no_browser')];
        }

        $printable = self::unfolded($absolute);
        $source = $printable ?? $absolute;

        // A private profile in a temporary directory: the export must not touch
        // the operator's own browser session.
        $profile = sys_get_temp_dir().'/sablier-pdf-'.bin2hex(random_bytes(4));
        $command = $browser !== null
            ? self::localCommand($browser, $profile, $source, $pdfPath)
            : self::containerCommand((string) $container, $source, $pdfPath);

        @shell_exec($command);
        self::removeDirectory($profile);
        if ($printable !== null) {
            @unlink($printable);
        }

        if (!is_file($pdfPath) || filesize($pdfPath) === 0) {
            return [false, Lang::t('pdf.failed', $browser !== null ? basename($browser) : self::CONTAINER_IMAGE)];
        }

        $written = Lang::t('pdf.written', $pdfPath, number_format(filesize($pdfPath) / 1024, 0, ',', ' '));

        // Which browser produced the file is not a detail: one of them is a
        // container this machine did not have five seconds ago.
        return [true, $browser !== null ? $written : $written.' — '.Lang::t('pdf.via_container', self::CONTAINER_IMAGE)];
    }

    private static function localCommand(string $browser, string $profile, string $source, string $pdfPath): string
    {
        return \sprintf(
            '%s --headless --disable-gpu --no-sandbox --user-data-dir=%s --no-pdf-header-footer --print-to-pdf=%s %s 2>/dev/null',
            escapeshellarg($browser),
            escapeshellarg($profile),
            escapeshellarg($pdfPath),
            escapeshellarg('file://'.$source),
        );
    }

    /**
     * The same command, one mount away.
     *
     * The page is mounted read-only and the destination directory writable,
     * nothing else: the container sees the report it is printing and the place
     * the PDF goes, and not the rest of the disk. The file belongs to whoever
     * ran the command rather than to root.
     */
    private static function containerCommand(string $docker, string $source, string $pdfPath): string
    {
        $target = realpath(\dirname($pdfPath));
        if ($target === false) {
            return '';
        }

        return \sprintf(
            '%s run --rm --user %s:%s --volume %s:/in:ro --volume %s:/out --entrypoint chromium-browser %s'
            .' --headless --disable-gpu --no-sandbox --user-data-dir=/tmp/sablier --no-pdf-header-footer'
            .' --print-to-pdf=%s %s 2>/dev/null',
            escapeshellarg($docker),
            escapeshellarg((string) self::currentUid()),
            escapeshellarg((string) self::currentGid()),
            escapeshellarg(\dirname($source)),
            escapeshellarg($target),
            escapeshellarg(self::CONTAINER_IMAGE),
            escapeshellarg('/out/'.basename($pdfPath)),
            escapeshellarg('file:///in/'.basename($source)),
        );
    }

    /**
     * Who is running this, as the kernel sees it.
     *
     * getmyuid() answers about the owner of the script file, which is not the
     * same person the moment the repository is shared or checked out by root.
     * ext-posix knows the difference and is present in every CLI build this
     * tool supports; the fallback is there for the one that is not.
     */
    private static function currentUid(): int
    {
        return \function_exists('posix_getuid') ? posix_getuid() : (int) getmyuid();
    }

    private static function currentGid(): int
    {
        return \function_exists('posix_getgid') ? posix_getgid() : (int) getmygid();
    }

    /** Docker, only if it is both installed and answering. */
    private static function container(): ?string
    {
        $docker = trim((string) @shell_exec('command -v docker 2>/dev/null'));

        return $docker !== '' ? $docker : null;
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
        /** @var iterable<\SplFileInfo> $items */
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
