<?php

declare(strict_types=1);

namespace Sablier;

/**
 * What we claim to know about each algorithm, and nothing more.
 *
 * Deliberately not a threat prediction: the tool does not guess when a
 * cryptographically relevant quantum computer arrives. It uses the regulatory
 * deadline as the planning date, which is a fact we can cite rather than a
 * number we invented.
 *
 * Only structure lives here. Labels are universal (RSA is RSA everywhere);
 * notes and replacement advice are sentences, so they live in the translations.
 */
final class Catalogue
{
    public const string PURPOSE_CONFIDENTIALITY = 'confidentiality';
    public const string PURPOSE_AUTHENTICITY = 'authenticity';
    public const string PURPOSE_INTEGRITY = 'integrity';
    public const string PURPOSE_UNKNOWN = 'unknown';

    /** @var array<string, array{label:string, purpose:string, quantum:bool, broken:bool}> */
    private const array ALGORITHMS = [
        'rsa' => ['label' => 'RSA', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => true, 'broken' => false],
        'rsa-sign' => ['label' => 'RSA', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => true, 'broken' => false],
        'ecdsa' => ['label' => 'ECDSA', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => true, 'broken' => false],
        'ecdh' => ['label' => 'ECDH / X25519', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => true, 'broken' => false],
        'ed25519' => ['label' => 'Ed25519', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => true, 'broken' => false],
        'dh' => ['label' => 'Diffie-Hellman', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => true, 'broken' => false],

        'aes-128' => ['label' => 'AES-128', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false],
        'aes-256' => ['label' => 'AES-256', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false],
        'chacha20' => ['label' => 'ChaCha20-Poly1305', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false],
        'des' => ['label' => 'DES / 3DES', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => true],
        'rc4' => ['label' => 'RC4', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => true],

        // No cryptography at all. In the catalogue because the report has to be
        // able to say it in the same sentence structure as everything else.
        'plaintext' => ['label' => 'Aucun chiffrement', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => true],

        // Not an algorithm but a protocol version; it belongs here because the
        // report speaks about it in exactly the same terms: broken today,
        // nothing to do with quantum computing.
        'tls-obsolete' => ['label' => 'TLS 1.0 / 1.1', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => true],

        'md5' => ['label' => 'MD5', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => true],
        'sha1' => ['label' => 'SHA-1', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => true],
        'sha256' => ['label' => 'SHA-256', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false],
        'sha512' => ['label' => 'SHA-512', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false],

        'bcrypt' => ['label' => 'bcrypt', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false],
        'argon2' => ['label' => 'Argon2', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false],

        'ml-kem' => ['label' => 'ML-KEM', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false],
        'ml-dsa' => ['label' => 'ML-DSA', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => false, 'broken' => false],
    ];

    /**
     * Published defects, for the algorithms that have one.
     *
     * A CVE identifies something that was found to be broken, with a date and
     * a third party anybody can go and read. The post-quantum deadline is not
     * that: it is a regulatory horizon, and filing it under the same heading
     * would turn a dated fact into an assertion of ours. So this table covers
     * exactly the "broken today" family and stops there — RSA and the elliptic
     * curves are cited through the standards in the audit report's section 4,
     * because that is what they are.
     *
     * @var array<string, list<string>>
     */
    private const array REFERENCES = [
        'md5' => ['CVE-2004-2761'],
        'sha1' => ['CVE-2005-4900'],
        'rc4' => ['CVE-2013-2566', 'CVE-2015-2808'],
        'des' => ['CVE-2016-2183'],
        'tls-obsolete' => ['CVE-2011-3389', 'CVE-2014-3566'],
    ];

    /** @return list<string> */
    public static function references(string $algorithm): array
    {
        return self::REFERENCES[$algorithm] ?? [];
    }

    /** Where a reader checks the claim for themselves. */
    public static function referenceUrl(string $reference): string
    {
        return 'https://nvd.nist.gov/vuln/detail/'.rawurlencode($reference);
    }

    /** @return array{label:string, purpose:string, quantum:bool, broken:bool, note:string, replacement:string}|null */
    public static function get(string $algorithm): ?array
    {
        $entry = self::ALGORITHMS[$algorithm] ?? null;
        if ($entry === null) {
            return null;
        }

        return $entry + [
            'note' => Lang::has("algo.$algorithm.note") ? Lang::t("algo.$algorithm.note") : '',
            'replacement' => Lang::has("algo.$algorithm.replacement") ? Lang::t("algo.$algorithm.replacement") : '',
        ];
    }

    public static function label(string $algorithm): string
    {
        return self::ALGORITHMS[$algorithm]['label'] ?? $algorithm;
    }

    /** Normalises what a scanner found (a cipher string, a constant) to a catalogue key. */
    public static function normalise(string $raw): ?string
    {
        $raw = strtolower(trim($raw));

        return match (true) {
            str_contains($raw, 'aes-128'), str_contains($raw, 'aes128') => 'aes-128',
            str_contains($raw, 'aes-192'), str_contains($raw, 'aes-256'), str_contains($raw, 'aes256') => 'aes-256',
            str_contains($raw, 'chacha') => 'chacha20',
            str_contains($raw, '3des'), str_contains($raw, 'des-') => 'des',
            str_contains($raw, 'rc4') => 'rc4',
            $raw === 'md5' => 'md5',
            $raw === 'sha1', $raw === 'sha-1' => 'sha1',
            str_starts_with($raw, 'sha256'), $raw === 'sha-256' => 'sha256',
            str_starts_with($raw, 'sha512'), str_starts_with($raw, 'sha384'), $raw === 'sha-512' => 'sha512',
            default => \array_key_exists($raw, self::ALGORITHMS) ? $raw : null,
        };
    }
}
