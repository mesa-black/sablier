<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\Analysis;
use Sablier\Catalogue;
use Sablier\Finding;

/**
 * The inventory as data, for whatever gates on it.
 *
 * Every field here is a stable token rather than a translated label: a pipeline
 * that breaks when somebody switches the report to Spanish is not a pipeline, and
 * a baseline committed to a repository must diff on facts rather than on a
 * language. That claim used to be written at the top of this file while the file
 * emitted `"confidence": "haute"` and `"domain": "non déclaré"` beside English
 * keys and English verdicts — found by somebody reading a committed baseline.
 *
 * `because` is the one exception, and it is deliberate: its whole job is to be a
 * sentence a person reads, so it follows the report's language. Nothing compares
 * it — a finding is identified by its fingerprint — and a baseline captured in
 * one language stays comparable in another. That is asserted by a test rather
 * than by this paragraph.
 */
final class JsonReporter implements ReporterInterface
{
    public function render(Analysis $analysis): string
    {
        $findings = array_map(static fn (Finding $f): array => [
            'fingerprint' => $f->fingerprint(),
            'algorithm' => $f->algorithm,
            'purpose' => $f->purpose,
            'file' => $f->file,
            'line' => $f->line,
            // The declared name, which is the team's own and the same in every
            // language. The label of an *undeclared* domain is translated, so it
            // is left out entirely: `declared: false` already says what it meant,
            // and saying it twice meant saying it in French.
            'domain' => $f->domainDeclared ? $f->domain : '',
            'declared' => $f->domainDeclared,
            'lifetime_years' => $f->lifetime,
            'verdict' => $f->verdict,
            'confidence' => $f->confidence,
            'inventory' => $f->inventory,
            'because' => $f->because,
            'references' => $f->references(),
            'accepted_until' => $f->acceptedUntil,
        ], $analysis->findings);

        return (string) json_encode(
            $findings,
            \JSON_PRETTY_PRINT | \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES,
        );
    }
}
