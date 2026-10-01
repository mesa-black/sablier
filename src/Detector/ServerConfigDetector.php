<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;
use Sablier\Value;

/**
 * What the web servers and OpenSSL itself are told to do.
 *
 * Caddy, nginx, Apache and openssl.cnf all express the same handful of
 * decisions in four different vocabularies. Reading them is worth doing even
 * though the live probe is more truthful, for two reasons: the probe only
 * reaches hosts you declare, and a configuration says what was *intended* —
 * a gap between intention and handshake is itself the finding.
 */
final class ServerConfigDetector implements Detector
{
    private const array FILENAMES = [
        'Caddyfile', 'nginx.conf', 'httpd.conf', 'apache2.conf', 'ssl.conf',
        'openssl.cnf', 'openssl.conf', 'default.conf',
    ];

    private const array DIRECTORY_HINTS = ['sites-available', 'sites-enabled', 'conf.d', 'vhosts', 'caddy', 'nginx', 'apache'];

    /** Directives that name a key-exchange group, across all four dialects. */
    private const string GROUP_DIRECTIVES = '/^\s*(ssl_ecdh_curve|curves|Groups|SSLOpenSSLConfCmd\s+Curves)\s+([^;\n{]+)/mi';

    /** Directives that name protocol versions. */
    private const string PROTOCOL_DIRECTIVES = '/^\s*(ssl_protocols|SSLProtocol|protocols|MinProtocol|MaxProtocol)\s+([^;\n{]+)/mi';

    /** Directives that name a cipher list. */
    private const string CIPHER_DIRECTIVES = '/^\s*(ssl_ciphers|SSLCipherSuite|ciphers|CipherString|Ciphersuites)\s+([^;\n{]+)/mi';

    /** Caddy chooses the certificate key type itself. */
    private const string KEY_TYPE_DIRECTIVE = '/^\s*key_type\s+(\S+)/mi';

    /** @var list<string> */
    private array $blindSpots = [];

    public function supports(SourceFile $file): bool
    {
        if (\in_array($file->name, self::FILENAMES, true) || $file->hasExtension('vhost')) {
            return true;
        }

        if (!$file->hasExtension('conf', 'cnf', 'caddy')) {
            return false;
        }

        // A bare .conf could be anything; a .conf under a web-server directory
        // is worth reading.
        foreach (self::DIRECTORY_HINTS as $hint) {
            if (str_contains($file->relativePath, $hint.'/')) {
                return true;
            }
        }

        return true;
    }

    public function blindSpots(): array
    {
        return $this->blindSpots;
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();
        $found = false;

        foreach ($this->groups($file, $content) as $finding) {
            $found = true;
            yield $finding;
        }
        foreach ($this->protocols($file, $content) as $finding) {
            $found = true;
            yield $finding;
        }
        foreach ($this->ciphers($file, $content) as $finding) {
            $found = true;
            yield $finding;
        }
        foreach ($this->keyTypes($file, $content) as $finding) {
            $found = true;
            yield $finding;
        }

        if ($found) {
            $this->blindSpots[] = Lang::t('blind.tls_config', $file->relativePath);
        }
    }

    /** @return iterable<Finding> */
    private function groups(SourceFile $file, string $content): iterable
    {
        if (preg_match_all(self::GROUP_DIRECTIVES, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
            return;
        }

        foreach ($matches[0] as $index => [$hit, $offset]) {
            $offset = Value::int($offset);
            $value = strtolower($matches[2][$index][0]);
            $hybrid = str_contains($value, 'mlkem') || str_contains($value, 'kyber') || str_contains($value, 'sntrup');

            yield new Finding(
                algorithm: $hybrid ? 'ml-kem' : 'ecdh',
                purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                file: $file->relativePath,
                line: $file->lineAt($offset),
                evidence: trim($hit),
                detail: Lang::t($hybrid ? 'detail.config.hybrid_group' : 'detail.config.classical_group'),
            );
        }
    }

    /** @return iterable<Finding> */
    private function protocols(SourceFile $file, string $content): iterable
    {
        if (preg_match_all(self::PROTOCOL_DIRECTIVES, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
            return;
        }

        foreach ($matches[0] as $index => [$hit, $offset]) {
            $offset = Value::int($offset);
            $value = strtolower($matches[2][$index][0]);
            // "-TLSv1" in Apache and "!TLSv1" elsewhere switch it off, not on.
            $enabled = preg_replace('/[-!]\s*\S+/', '', $value) ?? $value;
            if (preg_match('/\b(sslv3|tlsv1(\.[01])?)\b/', $enabled) !== 1) {
                continue;
            }

            yield new Finding(
                algorithm: 'tls-obsolete',
                purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                file: $file->relativePath,
                line: $file->lineAt($offset),
                evidence: trim($hit),
                detail: Lang::t('detail.config.obsolete_protocol'),
            );
        }
    }

    /** @return iterable<Finding> */
    private function ciphers(SourceFile $file, string $content): iterable
    {
        if (preg_match_all(self::CIPHER_DIRECTIVES, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
            return;
        }

        foreach ($matches[0] as $index => [$hit, $offset]) {
            $offset = Value::int($offset);
            $value = strtolower($matches[2][$index][0]);
            foreach (['rc4' => 'rc4', '3des' => 'des', 'des-cbc' => 'des'] as $needle => $algorithm) {
                // A leading ! or - excludes the cipher instead of allowing it.
                if (preg_match('/(?<![!\-])\b'.preg_quote($needle, '/').'\b/', $value) !== 1) {
                    continue;
                }

                yield new Finding(
                    algorithm: $algorithm,
                    purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                    file: $file->relativePath,
                    line: $file->lineAt($offset),
                    evidence: trim($hit),
                    detail: Lang::t('detail.config.weak_cipher'),
                );
            }
        }
    }

    /** @return iterable<Finding> */
    private function keyTypes(SourceFile $file, string $content): iterable
    {
        if (preg_match_all(self::KEY_TYPE_DIRECTIVE, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
            return;
        }

        foreach ($matches[0] as $index => [$hit, $offset]) {
            $offset = Value::int($offset);
            $value = strtolower($matches[1][$index][0]);
            $algorithm = match (true) {
                str_contains($value, 'ed25519') => 'ed25519',
                str_contains($value, 'rsa') => 'rsa-sign',
                default => 'ecdsa',
            };

            yield new Finding(
                algorithm: $algorithm,
                purpose: Catalogue::PURPOSE_AUTHENTICITY,
                file: $file->relativePath,
                line: $file->lineAt($offset),
                evidence: trim($hit),
                detail: Lang::t('detail.config.key_type'),
            );
        }
    }
}
