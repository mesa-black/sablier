<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\SourceFile;

/**
 * Shell scripts and pipeline files.
 *
 * This detector exists because the first real scan missed the one thing that
 * mattered: backup encryption lives in a deploy script, not in application
 * code — and backups are exactly the long-lived confidential data the whole
 * tool is about.
 */
final class ShellDetector extends PatternDetector
{
    public function supports(SourceFile $file): bool
    {
        return $file->hasExtension('sh', 'bash', 'yml', 'yaml') || $file->name === 'Dockerfile';
    }

    protected function rules(): array
    {
        return [
            ['/openssl\s+enc\b[^\n]*-(aes-?256[a-z0-9\-]*)/i', 'aes-256', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.cli_symmetric'],
            ['/openssl\s+enc\b[^\n]*-(aes-?128[a-z0-9\-]*)/i', 'aes-128', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.cli_symmetric'],
            ['/openssl\s+enc\b[^\n]*-(des3|des)/i', 'des', Catalogue::PURPOSE_CONFIDENTIALITY, ''],
            ['/openssl\s+genrsa|newkey\s+rsa:/i', 'rsa', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.rsa_keygen'],
            ['/openssl\s+ecparam|newkey\s+ec:/i', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, 'detail.ec_keygen'],
            ['/gpg\b[^\n]*--cipher-algo\s+(AES256|AES128|3DES)/i', self::CAPTURE, Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.gpg'],
            ['/ssh-keygen\b[^\n]*-t\s+rsa/i', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.ssh_keygen'],
            ['/ssh-keygen\b[^\n]*-t\s+ecdsa/i', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, 'detail.ssh_keygen'],
            ['/ssh-keygen\b[^\n]*-t\s+ed25519/i', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, 'detail.ssh_keygen'],
            ['/\bage\s+-r\b/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.age'],
        ];
    }
}
