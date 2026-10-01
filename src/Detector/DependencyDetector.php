<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;

/**
 * Declared cryptographic dependencies.
 *
 * Everything found here is flagged as inventory rather than usage: presence in a
 * lock file is not a call site, and a protocol may even mandate a weak primitive
 * — TOTP is specified on SHA-1. Treating the two alike produced the first false
 * alarms this tool ever printed.
 */
final class DependencyDetector implements DetectorInterface
{
    private const array PACKAGES = [
        'firebase/php-jwt' => ['rsa-sign', 'detail.pkg.jwt'],
        'lcobucci/jwt' => ['rsa-sign', 'detail.pkg.jwt'],
        'web-token/jwt-framework' => ['rsa-sign', 'detail.pkg.jose'],
        'phpseclib/phpseclib' => ['rsa', 'detail.pkg.phpseclib'],
        'paragonie/halite' => ['chacha20', 'detail.pkg.halite'],
        'defuse/php-encryption' => ['aes-256', 'detail.pkg.symmetric'],
        'web-auth/webauthn-lib' => ['ecdsa', 'detail.pkg.webauthn'],
        'spomky-labs/otphp' => ['sha1', 'detail.pkg.totp'],
    ];

    public function supports(SourceFile $file): bool
    {
        return $file->name === 'composer.lock';
    }

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();

        foreach (self::PACKAGES as $package => [$algorithm, $detail]) {
            $position = strpos($content, '"'.$package.'"');
            if ($position === false) {
                continue;
            }

            yield new Finding(
                algorithm: $algorithm,
                purpose: Catalogue::get($algorithm)['purpose'] ?? Catalogue::PURPOSE_UNKNOWN,
                file: $file->relativePath,
                line: $file->lineAt($position),
                evidence: $package,
                confidence: Finding::CONFIDENCE_MEDIUM,
                detail: Lang::t($detail).' '.Lang::t('detail.declared_dependency'),
                inventory: true,
            );
        }
    }
}
