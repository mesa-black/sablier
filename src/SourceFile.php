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

    /** 1-based line number of a byte offset in the content. */
    public function lineAt(int $offset): int
    {
        return substr_count($this->content(), "\n", 0, $offset) + 1;
    }

    /** The whole source line containing a byte offset, untrimmed. */
    public function lineTextAt(int $offset): string
    {
        $content = $this->content();
        $start = strrpos(substr($content, 0, $offset), "\n");
        $start = $start === false ? 0 : $start + 1;
        $end = strpos($content, "\n", $offset);

        return substr($content, $start, ($end === false ? \strlen($content) : $end) - $start);
    }

    /** Test code is real, but it protects nothing. */
    public function isTestCode(): bool
    {
        return preg_match('#(^|/)(tests?|spec|fixtures?)/#i', $this->relativePath) === 1;
    }
}
