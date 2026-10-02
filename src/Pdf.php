<?php

declare(strict_types=1);

namespace Sablier;

/**
 * PDF export, written here, with nothing borrowed.
 *
 * This used to hunt for Chrome in fourteen places and fall back to a pinned
 * Chromium container. It produced a prettier file, and it cost: a browser to
 * find or an image to pull, a temporary profile, a copy of the report with its
 * disclosures forced open — and one more container in the four this project
 * promises are free of known vulnerabilities.
 *
 * None of it survived the question a closed site asks: what do you do when
 * there is no browser and no network? The answer turned out to be good enough
 * everywhere, once it learned to draw the one figure that matters. So the
 * fourteen paths are gone, the container is gone, and the export does one thing
 * on every machine — including the one that is not allowed to reach anything.
 *
 * What is lost is colour and typography. What is gained is a page number on
 * every page, which the browser would never give us, a file eighteen times
 * smaller, and an export that cannot fail for want of something to borrow.
 */
final class Pdf
{
    /** @return array{0:bool, 1:string} success and a message for the operator */
    public static function render(string $htmlPath, string $pdfPath): array
    {
        $absolute = realpath($htmlPath);
        if ($absolute === false) {
            return [false, Lang::t('pdf.missing_html', $htmlPath)];
        }

        return self::typeset($absolute, $pdfPath);
    }

    /**
     * The report, set in type.
     *
     * It reads the HTML this tool just wrote — not the web at large — so the
     * subset is known: headings, paragraphs, lists, definition pairs, tables,
     * and the chart, which the reporter leaves beside the figure as data rather
     * than making this guess it back out of inline styles.
     *
     * @return array{0:bool, 1:string}
     */
    public static function typeset(string $htmlPath, string $pdfPath): array
    {
        if (!class_exists(\DOMDocument::class)) {
            return [false, Lang::t('pdf.no_dom')];
        }

        $html = (string) file_get_contents($htmlPath);
        $document = new \DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML('<?xml encoding="UTF-8">'.$html, \LIBXML_NOWARNING | \LIBXML_NOERROR);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        $titles = $document->getElementsByTagName('title');
        $title = $titles->length > 0 ? trim((string) $titles->item(0)?->textContent) : basename($htmlPath);
        $runner = $document->getElementById('runner');
        $footer = $runner !== null ? self::flatten($runner->textContent) : $title;

        $writer = new PdfWriter($title, $footer);
        $writer->heading($title, 1);
        $writer->rule();

        $body = $document->getElementsByTagName('body')->item(0);
        if ($body !== null) {
            self::walk($body, $writer);
        }

        file_put_contents($pdfPath, $writer->output());

        return [true, Lang::t('pdf.typeset', $pdfPath, round(filesize($pdfPath) / 1024))];
    }

    /**
     * Block by block, in the order a reader meets them.
     *
     * A recursive walk rather than a query per tag, because the order on the
     * page is the order of the document and an audit report read out of order
     * is an audit report that proves nothing.
     */
    private static function walk(\DOMNode $node, PdfWriter $writer): void
    {
        foreach ($node->childNodes as $child) {
            if (!$child instanceof \DOMElement) {
                continue;
            }

            $name = strtolower($child->tagName);
            if ($name === 'template' && $child->getAttribute('id') === 'chart') {
                self::chart($child->textContent, $writer);

                continue;
            }
            if (\in_array($name, ['script', 'style', 'svg', 'head', 'template'], true)) {
                continue;
            }

            switch ($name) {
                case 'h1':
                case 'h2':
                    $writer->heading(self::flatten($child->textContent), 2);
                    break;
                case 'h3':
                case 'h4':
                    $writer->heading(self::flatten($child->textContent), 3);
                    break;
                case 'p':
                    $writer->paragraph(self::flatten($child->textContent));
                    break;
                case 'li':
                    $writer->bullet(self::flatten($child->textContent));
                    break;
                case 'dl':
                    $writer->fields(self::pairs($child));
                    break;
                case 'table':
                    $rows = self::rows($child);
                    if ($rows !== []) {
                        $columns = \count($rows[0]);
                        $writer->table($rows, array_fill(0, $columns, 1 / max(1, $columns)));
                    }
                    break;
                case 'hr':
                    $writer->rule();
                    break;
                default:
                    self::walk($child, $writer);
            }
        }
    }

    /** The figure, from the inert template the reporter wrote beside it. */
    private static function chart(string $json, PdfWriter $writer): void
    {
        $data = Value::map(json_decode($json, true));
        $bars = [];
        foreach (Value::map($data['bars'] ?? null) as $entry) {
            $bar = Value::map($entry);
            $bars[] = [
                'name' => Value::string($bar['name'] ?? null),
                'years' => Value::int($bar['years'] ?? null),
                'exposed' => Value::bool($bar['exposed'] ?? null),
            ];
        }

        $marks = [];
        foreach (Value::map($data['marks'] ?? null) as $entry) {
            $mark = Value::map($entry);
            $marks[] = ['year' => Value::int($mark['year'] ?? null), 'label' => Value::string($mark['label'] ?? null)];
        }

        $writer->chart($bars, Value::int($data['start'] ?? null), Value::int($data['end'] ?? null), $marks);
    }

    /** @return array<string, string> */
    private static function pairs(\DOMElement $list): array
    {
        $pairs = [];
        $label = '';
        foreach ($list->getElementsByTagName('*') as $element) {
            $name = strtolower($element->tagName);
            if ($name === 'dt') {
                $label = self::flatten($element->textContent);
            } elseif ($name === 'dd' && $label !== '') {
                $pairs[$label] = self::flatten($element->textContent);
                $label = '';
            }
        }

        return $pairs;
    }

    /** @return list<list<string>> */
    private static function rows(\DOMElement $table): array
    {
        $rows = [];
        foreach ($table->getElementsByTagName('tr') as $line) {
            $cells = [];
            foreach ($line->childNodes as $cell) {
                if ($cell instanceof \DOMElement && \in_array(strtolower($cell->tagName), ['td', 'th'], true)) {
                    $cells[] = self::flatten($cell->textContent);
                }
            }
            if ($cells !== []) {
                $rows[] = $cells;
            }
        }

        return $rows;
    }

    private static function flatten(string $text): string
    {
        return trim((string) preg_replace('/\s+/u', ' ', $text));
    }

}
