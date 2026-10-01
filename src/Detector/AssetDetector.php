<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;

/**
 * What is hiding in the files nobody reads.
 *
 * Assets are the blind spot of every inventory: a repository's images, fonts
 * and archives are copied, reviewed by nobody, and shipped. They are also a
 * convenient place to leave something — a key pasted at the end of a logo, a
 * payload appended after the last image chunk, a .png that is not a png.
 *
 * This is deliberately **not** steganography detection. Finding a message
 * hidden in the low bits of an image is a research problem with a false
 * positive rate that would bury every real finding this tool prints. What is
 * here is the opposite: three facts a reader can verify with `xxd` in ten
 * seconds, graded by how much they actually prove.
 *
 *   · **Key material inside a binary asset.** A PEM header in a png is not an
 *     accident and not ambiguous — and it was already detected, because the
 *     key detector reads every file rather than the ones with key-shaped
 *     names. What this adds is the sentence that says where it was found.
 *   · **Bytes after the end of the image.** PNG ends at IEND, JPEG at FFD9,
 *     and a file that continues past it carries something else. That something
 *     is often harmless — a colour profile tool, a CMS watermarking pass — so
 *     it is reported as undetermined, with the byte count, and never as a
 *     verdict. The reader confirms or dismisses it; the tool does not guess.
 *   · **A file whose extension lies about its content.** The magic bytes say
 *     what it is; an archive or a certificate wearing an image extension is
 *     worth a look, and again only a look.
 *
 * The last two say "to confirm" out loud. A tool that cries wolf about holiday
 * photos loses the right to be believed about a backup key.
 */
final class AssetDetector implements DetectorInterface
{
    /** Extensions people stop reading once they are in the tree. */
    private const array ASSETS = [
        'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'tif', 'tiff',
        'mp3', 'mp4', 'webm', 'wav', 'avi', 'mov',
        'woff', 'woff2', 'ttf', 'otf', 'eot',
        'zip', 'gz', 'bz2', 'xz', 'tar', 'jar', 'war',
    ];

    /** Magic bytes, long enough to be a fact rather than a coincidence. */
    private const array MAGIC = [
        'png' => "\x89PNG\r\n\x1a\n",
        'gif' => 'GIF8',
        'jpg' => "\xFF\xD8\xFF",
        'jpeg' => "\xFF\xD8\xFF",
        'bmp' => 'BM',
        'zip' => "PK\x03\x04",
        'gz' => "\x1f\x8b",
        'woff' => 'wOFF',
        'woff2' => 'wOF2',
        'ttf' => "\x00\x01\x00\x00",
        'otf' => 'OTTO',
    ];

    /** Reading a whole video to look for a PEM header helps nobody. */
    private const int MAX_BYTES = 8_388_608;

    public function supports(SourceFile $file): bool
    {
        return $file->hasExtension(...self::ASSETS);
    }

    public function blindSpots(): array
    {
        return [Lang::t('blind.assets')];
    }

    public function detect(SourceFile $file): iterable
    {
        $size = @filesize($file->path);
        if ($size === false || $size === 0 || $size > self::MAX_BYTES) {
            return;
        }

        $content = $file->content();

        // A key pasted into an image is already reported, by the detector whose
        // job that is — it looks for a PEM header in any file, not just the
        // ones named like a key. Reporting it twice would be this tool failing
        // its own noise criterion in the first file it was asked about.
        if (str_contains($content, '-----BEGIN')) {
            return;
        }

        yield from $this->trailingBytes($file, $content);
        yield from $this->wrongMagic($file, $content);
    }

    /**
     * What follows the end of the image.
     *
     * Both formats declare their own end, so the question needs no heuristic:
     * either there are bytes after it or there are not. What those bytes are
     * is another matter entirely, and not one this tool pretends to settle.
     *
     * @return iterable<Finding>
     */
    private function trailingBytes(SourceFile $file, string $content): iterable
    {
        $end = match (true) {
            $file->hasExtension('png') && str_starts_with($content, self::MAGIC['png']) => self::pngEnd($content),
            $file->hasExtension('jpg', 'jpeg') && str_starts_with($content, self::MAGIC['jpg']) => self::jpegEnd($content),
            default => null,
        };

        if ($end === null) {
            return;
        }

        $trailing = \strlen($content) - $end;
        // A couple of padding bytes is how half the world's export pipelines
        // finish a file. The threshold is where "padding" stops being a word
        // anyone would use.
        if ($trailing < 64) {
            return;
        }

        yield new Finding(
            algorithm: 'undetermined',
            purpose: Catalogue::PURPOSE_UNKNOWN,
            file: $file->relativePath,
            line: 0,
            evidence: Lang::t('evidence.asset.trailing', $trailing),
            confidence: Finding::CONFIDENCE_MEDIUM,
            detail: Lang::t('detail.asset.trailing', $end),
        );
    }

    /** @return iterable<Finding> */
    private function wrongMagic(SourceFile $file, string $content): iterable
    {
        $expected = self::MAGIC[$file->extension] ?? null;
        if ($expected === null || str_starts_with($content, $expected)) {
            return;
        }

        yield new Finding(
            algorithm: 'undetermined',
            purpose: Catalogue::PURPOSE_UNKNOWN,
            file: $file->relativePath,
            line: 0,
            evidence: Lang::t('evidence.asset.magic', $file->extension, self::printable(substr($content, 0, 8))),
            confidence: Finding::CONFIDENCE_MEDIUM,
            detail: Lang::t('detail.asset.magic'),
        );
    }

    /** The offset just past the IEND chunk, or null when the file never ends. */
    private static function pngEnd(string $content): ?int
    {
        $position = strrpos($content, 'IEND');

        // IEND, then its four CRC bytes: that is the end of a PNG, by spec.
        return $position === false ? null : $position + 8;
    }

    /** The offset just past the EOI marker, or null when there is none. */
    private static function jpegEnd(string $content): ?int
    {
        $position = strrpos($content, "\xFF\xD9");

        return $position === false ? null : $position + 2;
    }

    /** Magic bytes printed so a human can compare them with what they expected. */
    private static function printable(string $bytes): string
    {
        $out = '';
        foreach (str_split($bytes) as $byte) {
            // Printable ASCII and nothing else: ctype_print() answers for the
            // current locale, and a byte it calls printable still arrives in
            // the report as a question mark once the page is encoded.
            $code = \ord($byte);
            $out .= $code >= 0x20 && $code <= 0x7E ? $byte : '\x'.bin2hex($byte);
        }

        return $out;
    }
}
