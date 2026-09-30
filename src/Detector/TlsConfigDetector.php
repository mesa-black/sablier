<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;

/**
 * TLS declared in the repository — which is an intention, not a fact. Every file
 * read here adds a blind spot to the report, because only the live probe can say
 * what a server actually negotiates.
 */
final class TlsConfigDetector implements Detector
{
    /** @var list<string> */
    private array $blindSpots = [];

    public function supports(SourceFile $file): bool
    {
        return $file->name === 'Caddyfile' || $file->hasExtension('conf', 'cnf');
    }

    public function blindSpots(): array
    {
        return $this->blindSpots;
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();
        if (preg_match_all('/^\s*(ssl_protocols|ssl_ciphers|protocols|curves)\s+([^;\n{]+)/mi', $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
            return;
        }

        $this->blindSpots[] = Lang::t('blind.tls_config', $file->relativePath);

        foreach ($matches[0] as [$hit, $offset]) {
            yield new Finding(
                algorithm: 'ecdh',
                purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                file: $file->relativePath,
                line: $file->lineAt($offset),
                evidence: trim($hit),
                confidence: Finding::CONFIDENCE_MEDIUM,
                detail: Lang::t('detail.tls_config'),
            );
        }
    }
}
