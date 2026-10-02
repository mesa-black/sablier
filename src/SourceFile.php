<?php

declare(strict_types=1);

namespace Sablier;

/**
 * One file offered to the detectors.
 *
 * Content is read once and shared: a detector must never re-read the disk, and
 * several detectors may legitimately want the same file — a Dockerfile is both
 * a shell-ish script and a place where keys get baked in.
 */
final class SourceFile
{
    private ?string $content = null;

    public function __construct(
        public readonly string $path,
        public readonly string $relativePath,
        public readonly string $name,
        public readonly string $extension,
    ) {
    }

    public static function fromSplFileInfo(\SplFileInfo $file, string $root): self
    {
        return new self(
            path: $file->getPathname(),
            relativePath: ltrim(str_replace($root, '', $file->getPathname()), '/'),
            name: $file->getFilename(),
            extension: strtolower($file->getExtension()),
        );
    }

    public function content(): string
    {
        return $this->content ??= (string) file_get_contents($this->path);
    }

    public function hasExtension(string ...$extensions): bool
    {
        return \in_array($this->extension, $extensions, true);
    }

    /**
     * 1-based line number of a byte offset in the content.
     *
     * A negative offset is clamped rather than trusted: PREG_OFFSET_CAPTURE
     * reports -1 for a group that did not take part in the match, and
     * substr_count would read that as "stop one byte from the end" — a wrong
     * line number, silently, which is worse than no line at all.
     *
     * Callers receive that offset inside a [text, offset] pair, and the static
     * analysers disagree about its type — one reads it as a string, another as
     * an int that may be -1. They convert it before calling in, which is why
     * this parameter can simply be an int.
     */
    public function lineAt(int $offset): int
    {
        return substr_count($this->content(), "\n", 0, max(0, $offset)) + 1;
    }

    /** The whole source line containing a byte offset, untrimmed. */
    public function lineTextAt(int $offset): string
    {
        $content = $this->content();
        $offset = max(0, $offset);
        $start = strrpos(substr($content, 0, $offset), "\n");
        $start = $start === false ? 0 : $start + 1;
        $end = strpos($content, "\n", $offset);

        return substr($content, $start, ($end === false ? \strlen($content) : $end) - $start);
    }

    /** Test code is real, but it protects nothing. */
    public function isTestCode(): bool
    {
        return preg_match('#(^|/)(tests?|spec|fixtures?)/#i', $this->relativePath) === 1
            || preg_match('#(Test|TestCase|Spec)\.php$#', $this->relativePath) === 1;
    }

    /**
     * The name of the function a match sits in, when it sits in one.
     *
     * Measured need: twenty public repositories produced forty digests inside
     * methods called `getHashCode`, `getIndexedFilename`, `generateClassName`.
     * The line says `return md5(`, which carries no hint at all; the name three
     * lines above says everything. Sixty lines back is enough for any body
     * worth reading and cheap enough to do per match.
     */
    public function functionAt(int $offset): string
    {
        $before = substr($this->content(), 0, max(0, $offset));
        $lines = array_slice(explode("\n", $before), -60);
        for ($i = \count($lines) - 1; $i >= 0; --$i) {
            if (preg_match('/function\s+(\w+)/', $lines[$i], $m) === 1) {
                return $m[1];
            }
        }

        return '';
    }

    /** A match inside a comment is a mention, not a call. */
    public function isCommentAt(int $offset): bool
    {
        return preg_match('#^\s*(//|\*|/\*|\#)#', $this->lineTextAt($offset)) === 1;
    }
}
