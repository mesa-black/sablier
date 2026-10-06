<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;
use Sablier\Value;

/**
 * Keys and certificates sitting in the tree.
 *
 * The headers below are the legacy ones, where the format names the algorithm.
 * Modern OpenSSL does not write them: `openssl genpkey`, and `openssl req`
 * since 3.0, produce PKCS#8 — `-----BEGIN PRIVATE KEY-----`, with the algorithm
 * inside the DER rather than in the header. That is the most common private key
 * format in circulation today, and this detector walked straight past it: an
 * RSA key dropped into a repository produced nothing at all.
 *
 * Found the day the report started claiming "no private key in the versioned
 * tree" as a positive result. A detector that misses something prints a silence,
 * which is survivable; the same detector behind a sentence that says it looked
 * prints a false assurance, which is not. So PKCS#8 is read here, by asking
 * ext-openssl what the key actually is rather than guessing from the header.
 */
final class KeyMaterialDetector implements DetectorInterface
{
    private const array PRIVATE_KEYS = [
        'BEGIN RSA PRIVATE KEY' => ['rsa', 'detail.rsa_private_key'],
        'BEGIN EC PRIVATE KEY' => ['ecdsa', 'detail.ec_private_key'],
        'BEGIN OPENSSH PRIVATE KEY' => ['ed25519', 'detail.openssh_private_key'],
        'BEGIN DSA PRIVATE KEY' => ['dh', 'detail.dsa_key'],
    ];

    /**
     * What ext-openssl answers, mapped to what this tool calls it.
     *
     * Built at runtime rather than written as a constant: the curve25519
     * constants exist only on a build whose OpenSSL has them, and a fatal error
     * on an older machine would be a poor way to report a key.
     *
     * @return array<int, string>
     */
    private static function keyTypes(): array
    {
        $types = [
            \OPENSSL_KEYTYPE_RSA => 'rsa',
            \OPENSSL_KEYTYPE_EC => 'ecdsa',
            \OPENSSL_KEYTYPE_DSA => 'dh',
            \OPENSSL_KEYTYPE_DH => 'dh',
        ];
        if (\defined('OPENSSL_KEYTYPE_ED25519')) {
            $types[\OPENSSL_KEYTYPE_ED25519] = 'ed25519';
        }
        // X25519 is key agreement, not signature — so it lands under
        // confidentiality, and a private one in a repository is harvestable.
        // The purpose is read from the catalogue below rather than assumed here.
        if (\defined('OPENSSL_KEYTYPE_X25519')) {
            $types[\OPENSSL_KEYTYPE_X25519] = 'ecdh';
        }

        return $types;
    }

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

    /** Images, fonts, archives: a key in one of these is not a key in a key file. */
    private const array ASSETS = [
        'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'tif', 'tiff',
        'mp3', 'mp4', 'webm', 'wav', 'avi', 'mov',
        'woff', 'woff2', 'ttf', 'otf', 'eot',
        'zip', 'gz', 'bz2', 'xz', 'tar', 'jar', 'war', 'pdf',
    ];

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();
        // Where the key is found changes what the finding means: a .pem in a
        // config directory is housekeeping, the same bytes inside a logo are
        // not, and the report should not make the reader notice the extension
        // on their own.
        $asset = $file->hasExtension(...self::ASSETS)
            ? ' '.Lang::t('detail.asset.key', $file->extension, (int) strpos($content, '-----BEGIN'))
            : '';

        foreach (self::PRIVATE_KEYS as $marker => [$algorithm, $detail]) {
            if (str_contains($content, $marker)) {
                yield new Finding($algorithm, Catalogue::PURPOSE_AUTHENTICITY, $file->relativePath, 1, $marker,
                    Finding::CONFIDENCE_HIGH, false, Lang::t($detail).$asset);
            }
        }

        // PKCS#8, whose header names no algorithm. Asked rather than assumed:
        // the file says `BEGIN PRIVATE KEY` whether it holds RSA-4096 or
        // Ed25519, and those are not the same finding.
        if (str_contains($content, 'BEGIN PRIVATE KEY') && \function_exists('openssl_pkey_get_private')) {
            $key = @openssl_pkey_get_private($content);
            $details = $key !== false ? @openssl_pkey_get_details($key) : false;
            $type = \is_array($details) ? Value::int($details['type'] ?? null) : -1;
            $algorithm = self::keyTypes()[$type] ?? null;

            // An Ed25519 or X25519 key parses and reports a type this tool has
            // no row for; a key that does not parse at all is still a key. Both
            // are reported as something to name rather than quietly dropped.
            // The purpose follows the algorithm: a signing key is not harvestable
            // and an X25519 agreement key is, and forcing both under one heading
            // would put the serious one in the wrong section.
            $purpose = $algorithm === null
                ? Catalogue::PURPOSE_UNKNOWN
                : (Catalogue::get($algorithm)['purpose'] ?? Catalogue::PURPOSE_AUTHENTICITY);

            yield new Finding(
                $algorithm ?? 'undetermined',
                $purpose, $file->relativePath, 1, 'BEGIN PRIVATE KEY',
                $algorithm === null ? Finding::CONFIDENCE_MEDIUM : Finding::CONFIDENCE_HIGH,
                false,
                Lang::t($algorithm === null ? 'detail.pkcs8_unknown' : 'detail.pkcs8').$asset,
            );
        }

        // Encrypted PKCS#8: the algorithm cannot be read without the passphrase,
        // and the fact that it is encrypted is worth printing on its own.
        if (str_contains($content, 'BEGIN ENCRYPTED PRIVATE KEY')) {
            yield new Finding(
                'undetermined', Catalogue::PURPOSE_AUTHENTICITY, $file->relativePath, 1,
                'BEGIN ENCRYPTED PRIVATE KEY', Finding::CONFIDENCE_MEDIUM, false,
                Lang::t('detail.pkcs8_encrypted').$asset,
            );
        }

        if (str_contains($content, 'BEGIN CERTIFICATE') && \function_exists('openssl_x509_parse')) {
            $parsed = @openssl_x509_parse($content);
            if (\is_array($parsed)) {
                $signature = Value::string($parsed['signatureTypeSN'] ?? null);
                yield new Finding(
                    str_contains($signature, 'ECDSA') ? 'ecdsa' : 'rsa-sign',
                    Catalogue::PURPOSE_AUTHENTICITY, $file->relativePath, 1, $signature,
                    Finding::CONFIDENCE_HIGH, false, Lang::t('detail.x509').$asset,
                );
            }
        }

        foreach (self::SSH_KEYS as $marker => $algorithm) {
            if (str_contains($content, $marker)) {
                yield new Finding($algorithm, Catalogue::PURPOSE_AUTHENTICITY, $file->relativePath, 1, $marker,
                    Finding::CONFIDENCE_HIGH, false, Lang::t('detail.ssh_key').$asset);
            }
        }
    }
}
