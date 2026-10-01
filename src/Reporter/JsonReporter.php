<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\Analysis;
use Sablier\Catalogue;
use Sablier\Finding;

/**
 * The inventory as data, for whatever gates on it.
 *
 * Verdicts are emitted as their stable keys rather than their translated
 * labels: a pipeline that breaks when someone switches the report to Spanish is
 * not a pipeline.
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
            'domain' => $f->domain,
            'declared' => $f->domainDeclared,
            'lifetime_years' => $f->lifetime,
            'verdict' => $f->verdict,
            'confidence' => $f->confidence,
            'inventory' => $f->inventory,
            'because' => $f->because,
            'references' => Catalogue::references($f->algorithm),
            'accepted_until' => $f->acceptedUntil,
        ], $analysis->findings);

        return (string) json_encode(
            $findings,
            \JSON_PRETTY_PRINT | \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES,
        );
    }
}
