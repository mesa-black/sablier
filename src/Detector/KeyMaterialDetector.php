<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;
use Sablier\Value;

/** Keys and certificates sitting in the tree. */
final class KeyMaterialDetector implements DetectorInterface
{
    private const array PRIVATE_KEYS = [
        'BEGIN RSA PRIVATE KEY' => ['rsa', 'detail.rsa_private_key'],
        'BEGIN EC PRIVATE KEY' => ['ecdsa', 'detail.ec_private_key'],
        'BEGIN OPENSSH PRIVATE KEY' => ['ed25519', 'detail.openssh_private_key'],
        'BEGIN DSA PRIVATE KEY' => ['dh', 'detail.dsa_key'],
    ];

    private const array SSH_KEYS = [
        'ssh-rsa' => 'rsa-sign',
        'ecdsa-sha2-' => 'ecdsa',
        'ssh-ed25519' => 'ed25519',
    ];

    public function supports(SourceFile $file): bool
    {
        return $file->hasExtension('pem', 'key', 'crt', 'cer', 'pub')
            || str_contains($file->content(), '-----BEGIN');
    }

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();

        foreach (self::PRIVATE_KEYS as $marker => [$algorithm, $detail]) {
            if (str_contains($content, $marker)) {
                yield new Finding($algorithm, Catalogue::PURPOSE_AUTHENTICITY, $file->relativePath, 1, $marker,
                    Finding::CONFIDENCE_HIGH, false, Lang::t($detail));
            }
        }

        if (str_contains($content, 'BEGIN CERTIFICATE') && \function_exists('openssl_x509_parse')) {
            $parsed = @openssl_x509_parse($content);
            if (\is_array($parsed)) {
                $signature = Value::string($parsed['signatureTypeSN'] ?? null);
                yield new Finding(
                    str_contains($signature, 'ECDSA') ? 'ecdsa' : 'rsa-sign',
                    Catalogue::PURPOSE_AUTHENTICITY, $file->relativePath, 1, $signature,
                    Finding::CONFIDENCE_HIGH, false, Lang::t('detail.x509'),
                );
            }
        }

        foreach (self::SSH_KEYS as $marker => $algorithm) {
            if (str_contains($content, $marker)) {
                yield new Finding($algorithm, Catalogue::PURPOSE_AUTHENTICITY, $file->relativePath, 1, $marker,
                    Finding::CONFIDENCE_HIGH, false, Lang::t('detail.ssh_key'));
            }
        }
    }
}
