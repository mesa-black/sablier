<?php

declare(strict_types=1);

namespace Sablier;

/**
 * A PDF, written here, with no browser involved.
 *
 * The pretty export borrows Chromium. On a closed site there is no Chromium to
 * borrow and no container to pull one from, and a report that cannot be printed
 * is a report that cannot be signed, filed, or read by the people an audit is
 * written for.
 *
 * So this writes the file itself: pages, the three fonts every reader already
 * has, lines of text, rules and tables. It is deliberately a typesetter and not
 * a browser — no colours to speak of, no images, no layout engine — because the
 * document it has to produce is a numbered report somebody reads once and
 * keeps, and that document is made of headings, paragraphs and tables.
 *
 * It also does the one thing the browser would not: a page number on every
 * page. Chrome ignores the CSS that would carry one, which is why the HTML
 * export settles for a running line instead.
 */
final class PdfWriter
{
    private const float WIDTH = 595.28;   // A4, in points
    private const float HEIGHT = 841.89;
    private const float MARGIN = 56.0;
    private const float LEADING = 1.38;

    /** @var array<int, string> finished page content streams, by page index */
    private array $pages = [];

    private string $current = '';
    private float $y;
    private int $page = 0;

    /** @var list<array{page:int, label:string}> */
    private array $footers = [];

    public function __construct(
        private readonly string $title,
        private readonly string $footer,
    ) {
        $this->y = self::HEIGHT - self::MARGIN;
        $this->newPage();
    }

    public function heading(string $text, int $level = 1): void
    {
        $size = match ($level) {
            1 => 15.0,
            2 => 11.5,
            default => 10.0,
        };
        $this->space($level === 1 ? 16.0 : 11.0);
        // A heading alone at the foot of a page is a heading on the wrong page.
        $this->ensure($size * self::LEADING * 3);
        $this->write($text, $size, 'F2');
        $this->space(4.0);
    }

    public function paragraph(string $text, float $size = 9.5, float $indent = 0.0): void
    {
        if (trim($text) === '') {
            return;
        }

        $this->write($text, $size, 'F1', $indent);
        $this->space(5.0);
    }

    public function bullet(string $text, float $size = 9.5): void
    {
        $this->ensure($size * self::LEADING);
        $this->put('F1', $size, self::MARGIN, $this->y, '•');
        $this->write($text, $size, 'F1', 14.0, false);
        $this->space(3.0);
    }

    /** @param array<string, string> $pairs */
    public function fields(array $pairs, float $size = 9.5): void
    {
        foreach ($pairs as $label => $value) {
            $this->ensure($size * self::LEADING);
            $top = $this->y;
            $this->put('F2', $size, self::MARGIN, $top, $label);
            $this->write($value, $size, 'F1', 150.0, false);
            $this->space(2.0);
        }
        $this->space(4.0);
    }

    /**
     * @param list<list<string>> $rows the first row is the header
     * @param list<float>        $widths as fractions of the text column
     */
    public function table(array $rows, array $widths, float $size = 8.5): void
    {
        $this->space(6.0);
        $usable = self::WIDTH - 2 * self::MARGIN;
        foreach ($rows as $index => $row) {
            $font = $index === 0 ? 'F2' : 'F1';
            $height = 0.0;
            // Measure before drawing: a row is only as tall as its longest cell,
            // and it must not be split across two pages.
            foreach ($row as $column => $cell) {
                $width = ($widths[$column] ?? 0.2) * $usable - 6;
                $height = max($height, \count($this->wrap($cell, $size, $font, $width)) * $size * self::LEADING);
            }
            $this->ensure($height + 6);

            $top = $this->y;
            $offset = 0.0;
            foreach ($row as $column => $cell) {
                $width = ($widths[$column] ?? 0.2) * $usable;
                $this->y = $top;
                $this->write($cell, $size, $font, $offset, false, $width - 6);
                $offset += $width;
            }
            $this->y = $top - $height - 3;
            $this->rule();
        }
        $this->space(6.0);
    }

    /**
     * The timeline, drawn rather than described.
     *
     * The one figure both reports carry: a bar per domain, as long as the data
     * must stay confidential, against the years at which the algorithms
     * protecting it stop being credible. A bar that crosses a mark is the whole
     * argument of the document, so it is worth drawing even without a browser.
     *
     * @param list<array{name:string, years:int, exposed:bool}> $bars
     * @param list<array{year:int, label:string}>               $marks
     */
    public function chart(array $bars, int $start, int $end, array $marks): void
    {
        if ($bars === []) {
            return;
        }

        $span = max(1, $end - $start);
        $labelWidth = 118.0;
        $yearsWidth = 54.0;
        $left = self::MARGIN + $labelWidth;
        $track = self::WIDTH - 2 * self::MARGIN - $labelWidth - $yearsWidth;
        $rowHeight = 15.0;

        $this->space(18.0);
        $this->ensure($rowHeight * (\count($bars) + 1) + 24);

        // The marks first, so the bars sit on top of their lines.
        $top = $this->y + 10;
        $bottom = $this->y - $rowHeight * \count($bars) + 4;
        foreach ($marks as $mark) {
            $x = $left + ($mark['year'] - $start) / $span * $track;
            $this->current .= \sprintf(
                "0.72 G 0.5 w [2 2] 0 d %.2f %.2f m %.2f %.2f l S [] 0 d\n",
                $x, $top, $x, $bottom,
            );
            $this->current .= $this->text('F1', 7.0, $x - 9, $top + 4, (string) $mark['year'], '0.45 g');
            $this->current .= $this->text('F1', 6.5, $x - 9, $bottom - 9, $mark['label'], '0.45 g');
        }

        foreach ($bars as $bar) {
            $y = $this->y;
            $width = max(2.0, min($track, $bar['years'] / $span * $track));
            $this->put('F1', 8.0, self::MARGIN, $y, self::clip($bar['name'], 'F1', 8.0, $labelWidth - 8));
            // Grey track, then the bar: a reader sees at once how much of the
            // horizon a domain eats, not only where it ends.
            $this->current .= \sprintf("0.90 g %.2f %.2f %.2f %.2f re f\n", $left, $y - 1, $track, 6.0);
            $this->current .= \sprintf(
                "%s %.2f %.2f %.2f %.2f re f\n",
                $bar['exposed'] ? '0.56 0.14 0.11 rg' : '0.17 0.30 0.49 rg',
                $left, $y - 1, $width, 6.0,
            );
            $this->current .= $this->text(
                'F1', 8.0, $left + $track + 8, $y,
                \sprintf('%d %s', $bar['years'], Lang::t($bar['years'] > 1 ? 'unit.years' : 'unit.year')),
                '0.35 g',
            );
            $this->y -= $rowHeight;
        }

        $this->space(14.0);
    }

    /** A label that would run into the bars, cut with an ellipsis. */
    private static function clip(string $text, string $font, float $size, float $width): string
    {
        if (self::measure($text, $font) * $size / 1000 <= $width) {
            return $text;
        }

        $cut = self::fit($text.'…', $font, $size, $width);

        return rtrim(substr($text, 0, max(1, $cut - 1))).'…';
    }

    public function rule(): void
    {
        $this->ensure(6.0);
        $this->current .= \sprintf(
            "0.85 G 0.4 w %.2f %.2f m %.2f %.2f l S\n",
            self::MARGIN, $this->y, self::WIDTH - self::MARGIN, $this->y,
        );
        $this->space(6.0);
    }

    public function space(float $points): void
    {
        $this->y -= $points;
    }

    /** The finished file, page numbers filled in now that the count is known. */
    public function output(): string
    {
        $this->closePage();
        $total = \count($this->pages);
        foreach ($this->footers as $footer) {
            $line = \sprintf('%s · %d/%d', $footer['label'], $footer['page'] + 1, $total);
            $this->pages[$footer['page']] .= $this->text('F1', 7.5, self::MARGIN, self::MARGIN - 18, $line, '0.45 g');
        }

        return $this->assemble();
    }

    // --- layout ------------------------------------------------------------

    private function newPage(): void
    {
        $this->current = '';
        $this->y = self::HEIGHT - self::MARGIN;
        $this->footers[] = ['page' => $this->page, 'label' => $this->footer];
    }

    private function closePage(): void
    {
        $this->pages[$this->page] = $this->current;
    }

    private function ensure(float $needed): void
    {
        if ($this->y - $needed >= self::MARGIN) {
            return;
        }

        $this->closePage();
        ++$this->page;
        $this->newPage();
    }

    /**
     * One run of text, wrapped, starting at the current line.
     *
     * @param float $width 0 for the full text column
     */
    private function write(string $text, float $size, string $font, float $indent = 0.0, bool $advanceFirst = true, float $width = 0.0): void
    {
        $column = ($width > 0 ? $width : self::WIDTH - 2 * self::MARGIN - $indent);
        $lines = $this->wrap($text, $size, $font, $column);
        foreach ($lines as $index => $line) {
            if ($index > 0 || $advanceFirst) {
                $this->ensure($size * self::LEADING);
            }
            $this->put($font, $size, self::MARGIN + $indent, $this->y, $line);
            $this->y -= $size * self::LEADING;
        }
    }

    private function put(string $font, float $size, float $x, float $y, string $text): void
    {
        $this->current .= $this->text($font, $size, $x, $y, $text);
    }

    private function text(string $font, float $size, float $x, float $y, string $text, string $colour = '0 g'): string
    {
        return \sprintf(
            "BT %s /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n",
            $colour, $font, $size, $x, $y, self::escape($text),
        );
    }

    /** How many bytes of a word fit in the width, at least one. */
    private static function fit(string $word, string $font, float $size, float $width): int
    {
        $length = \strlen($word);
        for ($cut = 1; $cut < $length; ++$cut) {
            if (self::measure(substr($word, 0, $cut + 1), $font) * $size / 1000 > $width) {
                return $cut;
            }
        }

        return max(1, $length);
    }

    /** @return list<string> */
    private function wrap(string $text, float $size, string $font, float $width): array
    {
        $words = preg_split('/\s+/u', trim($text)) ?: [];
        $lines = [];
        $line = '';
        foreach ($words as $word) {
            // A path, a digest or a command line is one word and can be wider
            // than the page. Break it rather than let it run into the margin.
            while (self::measure($word, $font) * $size / 1000 > $width) {
                $cut = self::fit($word, $font, $size, $width);
                if ($line !== '') {
                    $lines[] = $line;
                    $line = '';
                }
                $lines[] = substr($word, 0, $cut);
                $word = substr($word, $cut);
            }

            $candidate = $line === '' ? $word : $line.' '.$word;
            if ($line !== '' && self::measure($candidate, $font) * $size / 1000 > $width) {
                $lines[] = $line;
                $line = $word;

                continue;
            }
            $line = $candidate;
        }
        if ($line !== '') {
            $lines[] = $line;
        }

        return $lines === [] ? [''] : $lines;
    }

    // --- the parts a PDF reader needs ---------------------------------------

    private function assemble(): string
    {
        $objects = [];
        $count = \count($this->pages);
        // 1 catalog, 2 pages, then a pair per page, then the three fonts.
        $first = 3;
        $fontBase = $first + $count * 2;

        $kids = [];
        for ($i = 0; $i < $count; ++$i) {
            $kids[] = \sprintf('%d 0 R', $first + $i * 2);
        }

        $objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
        $objects[2] = \sprintf(
            "<< /Type /Pages /Count %d /Kids [%s] >>",
            $count, implode(' ', $kids),
        );

        for ($i = 0; $i < $count; ++$i) {
            $objects[$first + $i * 2] = \sprintf(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font "
                ."<< /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >> >> /Contents %d 0 R >>",
                self::WIDTH, self::HEIGHT, $fontBase, $fontBase + 1, $fontBase + 2, $first + $i * 2 + 1,
            );
            $stream = $this->pages[$i];
            $objects[$first + $i * 2 + 1] = \sprintf(
                "<< /Length %d >>\nstream\n%s\nendstream",
                \strlen($stream) + 1, $stream,
            );
        }

        foreach (['Helvetica', 'Helvetica-Bold', 'Courier'] as $index => $name) {
            $objects[$fontBase + $index] = \sprintf(
                "<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>",
                $name,
            );
        }

        $objects[$fontBase + 3] = \sprintf(
            "<< /Title (%s) /Producer (Sablier %s) /CreationDate (D:%s) >>",
            self::escape($this->title), Version::NUMBER, date('YmdHis'),
        );

        $out = "%PDF-1.4\n";
        $offsets = [];
        ksort($objects);
        foreach ($objects as $id => $body) {
            $offsets[$id] = \strlen($out);
            $out .= \sprintf("%d 0 obj\n%s\nendobj\n", $id, $body);
        }

        $xref = \strlen($out);
        $total = max(array_keys($objects)) + 1;
        $out .= \sprintf("xref\n0 %d\n0000000000 65535 f \n", $total);
        for ($id = 1; $id < $total; ++$id) {
            $out .= \sprintf("%010d 00000 n \n", $offsets[$id] ?? 0);
        }
        $out .= \sprintf(
            "trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n",
            $total, $fontBase + 3, $xref,
        );

        return $out;
    }

    /** PDF strings are Latin-1 here, and three characters have to be escaped. */
    private static function escape(string $text): string
    {
        return str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], self::latin($text));
    }

    /**
     * Windows-1252, whatever it takes.
     *
     * A single character the encoding has no room for — the ⟹ of the Mosca
     * inequality, say — made iconv fail outright, and a failed conversion
     * returning the original UTF-8 printed every accent in the paragraph as two
     * characters. So the few symbols this tool actually uses are spelled out
     * first, and the conversion then degrades rather than gives up.
     */
    private static function latin(string $text): string
    {
        $text = strtr($text, [
            '⟹' => ' => ', '⇒' => ' => ', '→' => ' -> ', '⟶' => ' -> ', '←' => ' <- ',
            '≥' => '>=', '≤' => '<=', '≠' => '!=', '×' => 'x', '✓' => 'v', '✗' => 'x',
            '✕' => 'x', '★' => '*', '•' => '-', '–' => '-', '─' => '-',
        ]);

        foreach (['Windows-1252//TRANSLIT//IGNORE', 'Windows-1252//IGNORE'] as $target) {
            $latin = @iconv('UTF-8', $target, $text);
            if ($latin !== false) {
                return $latin;
            }
        }

        return (string) preg_replace('/[^\x20-\x7E]/', '?', $text);
    }

    /**
     * The width of a string in thousandths of the point size.
     *
     * The three fonts used here are the ones every reader carries, so their
     * metrics are known rather than measured. An accented letter is as wide as
     * the letter it is built on, which is true in these fonts and close enough
     * everywhere it is not.
     */
    private static function measure(string $text, string $font): int
    {
        $widths = $font === 'F2' ? self::bold() : self::regular();
        $total = 0;
        foreach (str_split(self::latin($text)) as $char) {
            $code = \ord($char);
            $total += $widths[$code] ?? ($code > 127 ? ($widths[self::base($code)] ?? 556) : 556);
        }

        return $total;
    }

    /** The unaccented letter behind a Latin-1 code point. */
    private static function base(int $code): int
    {
        return match (true) {
            $code >= 0xC0 && $code <= 0xC5 => \ord('A'),
            $code === 0xC7 => \ord('C'),
            $code >= 0xC8 && $code <= 0xCB => \ord('E'),
            $code >= 0xCC && $code <= 0xCF => \ord('I'),
            $code === 0xD1 => \ord('N'),
            $code >= 0xD2 && $code <= 0xD6 => \ord('O'),
            $code >= 0xD9 && $code <= 0xDC => \ord('U'),
            $code >= 0xE0 && $code <= 0xE5 => \ord('a'),
            $code === 0xE7 => \ord('c'),
            $code >= 0xE8 && $code <= 0xEB => \ord('e'),
            $code >= 0xEC && $code <= 0xEF => \ord('i'),
            $code === 0xF1 => \ord('n'),
            $code >= 0xF2 && $code <= 0xF6 => \ord('o'),
            $code >= 0xF9 && $code <= 0xFC => \ord('u'),
            default => \ord('o'),
        };
    }

    /** @return array<int, int> */
    private static function regular(): array
    {
        return self::widths(
            '278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 556 556 556 556 556 556 556 556 '
            .'556 556 278 278 584 584 584 556 1015 667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 '
            .'667 778 722 667 611 722 667 944 667 667 611 278 278 278 469 556 333 556 556 500 556 556 278 556 '
            .'556 222 222 500 222 833 556 556 556 556 333 500 278 556 500 722 500 500 500 334 260 334 584',
        );
    }

    /** @return array<int, int> */
    private static function bold(): array
    {
        return self::widths(
            '278 333 474 556 556 889 722 238 333 333 389 584 278 333 278 278 556 556 556 556 556 556 556 556 '
            .'556 556 333 333 584 584 584 611 975 722 722 722 722 667 611 778 722 278 556 722 611 833 722 778 '
            .'667 778 722 667 611 722 667 944 667 667 611 333 278 333 584 556 333 556 611 556 611 556 333 611 '
            .'611 278 278 556 278 889 611 611 611 611 389 556 333 611 556 778 556 556 500 389 280 389 584',
        );
    }

    /** @return array<int, int> */
    private static function widths(string $widths): array
    {
        $out = [];
        $code = 32;
        foreach (explode(' ', $widths) as $width) {
            $out[$code++] = (int) $width;
        }

        return $out;
    }
}
