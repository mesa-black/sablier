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
 */
final class Catalogue
{
    public const string PURPOSE_CONFIDENTIALITY = 'confidentiality';
    public const string PURPOSE_AUTHENTICITY = 'authenticity';
    public const string PURPOSE_INTEGRITY = 'integrity';
    public const string PURPOSE_UNKNOWN = 'unknown';

    /**
     * @var array<string, array{label:string, purpose:string, quantum:bool, broken:bool, replacement:string, note:string}>
     */
    private const array ALGORITHMS = [
        // Asymmetric — the whole point of the exercise.
        'rsa' => ['label' => 'RSA', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => true, 'broken' => false,
            'replacement' => 'ML-KEM (chiffrement) ou ML-DSA (signature), en hybride pendant la transition',
            'note' => "Cassable par l'algorithme de Shor. La taille de clé n'y change rien."],
        'rsa-sign' => ['label' => 'RSA (signature)', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => true, 'broken' => false,
            'replacement' => 'ML-DSA, ou SLH-DSA pour une ancre de confiance longue durée',
            'note' => "Signature : pas de récolte possible, l'urgence dépend de la durée de vie de la clé."],
        'ecdsa' => ['label' => 'ECDSA', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => true, 'broken' => false,
            'replacement' => 'ML-DSA', 'note' => "Même exposition que RSA à Shor, sur des clés plus courtes."],
        'ecdh' => ['label' => 'ECDH / X25519', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => true, 'broken' => false,
            'replacement' => 'X25519 + ML-KEM en hybride',
            'note' => "Échange de clés : la cible principale de la récolte, puisqu'il protège le trafic."],
        'ed25519' => ['label' => 'Ed25519', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => true, 'broken' => false,
            'replacement' => 'ML-DSA', 'note' => "Excellent classiquement, vulnérable quantiquement comme toute courbe."],
        'dh' => ['label' => 'Diffie-Hellman', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => true, 'broken' => false,
            'replacement' => 'ML-KEM en hybride', 'note' => ''],

        // Symmetric — mostly fine, and saying so avoids pointless migrations.
        'aes-128' => ['label' => 'AES-128', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false,
            'replacement' => 'AES-256', 'note' => "Grover ramène la marge à 64 bits : suffisant aujourd'hui, inconfortable à long terme."],
        'aes-256' => ['label' => 'AES-256', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => "Tient face à Grover. Rien à faire."],
        'chacha20' => ['label' => 'ChaCha20-Poly1305', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => "Rien à faire."],
        'des' => ['label' => 'DES / 3DES', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => true,
            'replacement' => 'AES-256', 'note' => "Cassé classiquement. Problème d'aujourd'hui, pas de 2035."],
        'rc4' => ['label' => 'RC4', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => true,
            'replacement' => 'AES-256 ou ChaCha20', 'note' => "Cassé classiquement."],

        // Hashes.
        'md5' => ['label' => 'MD5', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => true,
            'replacement' => 'SHA-256, ou rien si l\'usage n\'est pas cryptographique',
            'note' => "Collisions triviales depuis 2004. Sans aucun rapport avec le quantique."],
        'sha1' => ['label' => 'SHA-1', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => true,
            'replacement' => 'SHA-256', 'note' => "Collisions démontrées depuis 2017."],
        'sha256' => ['label' => 'SHA-256', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => ''],
        'sha512' => ['label' => 'SHA-512', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => ''],

        // Password hashing — neither quantum nor classical concern here.
        'bcrypt' => ['label' => 'bcrypt', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => "Hachage de mot de passe : hors du périmètre post-quantique."],
        'argon2' => ['label' => 'Argon2', 'purpose' => self::PURPOSE_INTEGRITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => "Hachage de mot de passe : hors du périmètre post-quantique."],

        // Already post-quantum.
        'ml-kem' => ['label' => 'ML-KEM', 'purpose' => self::PURPOSE_CONFIDENTIALITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => "Normalisé FIPS 203."],
        'ml-dsa' => ['label' => 'ML-DSA', 'purpose' => self::PURPOSE_AUTHENTICITY, 'quantum' => false, 'broken' => false,
            'replacement' => '', 'note' => "Normalisé FIPS 204."],
    ];

    /** @return array{label:string, purpose:string, quantum:bool, broken:bool, replacement:string, note:string}|null */
    public static function get(string $algorithm): ?array
    {
        return self::ALGORITHMS[$algorithm] ?? null;
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
