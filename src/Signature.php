<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Signing a report, and being honest about what the signature is worth.
 *
 * What gets signed is not the HTML file. That file carries a rendering date and
 * a duration, so two runs of the same analysis differ byte for byte while
 * saying exactly the same thing. What is signed is a canonical digest of the
 * findings themselves: same inventory, same digest, whatever the language the
 * report was rendered in.
 *
 * PHP offers no post-quantum signature: libsodium has none, and ext-openssl
 * reads an ML-DSA key but refuses to sign with it. So for three versions this
 * tool told people to migrate their signatures before 2030 while signing its
 * own reports with Ed25519 alone, and its own report said so in the findings.
 *
 * It signs both now, when the machine can. Ed25519 always, because it works
 * everywhere PHP runs and a report nobody can verify is worth nothing; ML-DSA-65
 * in addition, through the openssl binary, from OpenSSL 3.5. That is
 * hybridation, which is what ANSSI asks for and what this tool's own references
 * say — and the one shape that adds a guarantee without removing one. A machine
 * with an older library produces a single signature and the report states it,
 * rather than carrying less than it claims.
 */
final class Signature
{
    public const string ALGORITHM = 'Ed25519';

    /**
     * A digest of what was found, independent of how it was rendered.
     *
     * Sorted by fingerprint so the order the detectors happened to run in
     * cannot change the result.
     */
    public static function digest(Analysis $analysis): string
    {
        $rows = [];
        foreach ($analysis->findings as $finding) {
            $rows[] = implode('|', [
                $finding->fingerprint(),
                $finding->algorithm,
                $finding->file,
                $finding->verdict,
                $finding->domain,
            ]);
        }
        sort($rows);

        $canonical = implode("\n", [
            'sablier/1',
            $analysis->declaration->project !== '' ? $analysis->declaration->project : basename($analysis->target),
            (string) $analysis->declaration->expiryYear,
            (string) \count($rows),
            ...$rows,
        ]);

        return hash('sha256', $canonical);
    }

    /**
     * The short form of a key pair, for a reader to check by hand.
     *
     * An ML-DSA public key is 2.7 kB of base64 and nobody pastes that into a
     * message. This is one line: it travels by whatever channel already proves
     * who is speaking, and the signature file carries the keys themselves. The
     * recipient checks that the file hashes to the line they were given, which
     * is how SSH host keys have been authenticated for thirty years.
     */
    public static function fingerprint(string $publicKeyBase64, string $pqPublicPem = ''): string
    {
        $raw = hash('sha256', $publicKeyBase64."\n".self::canonicalPem($pqPublicPem), true);

        return implode(' ', str_split(strtoupper(bin2hex(substr($raw, 0, 16))), 4));
    }

    /** Where the post-quantum half of a key pair lives, beside the other half. */
    public static function hybridKeyPath(string $keyPath): string
    {
        return $keyPath.'.ml-dsa.pem';
    }

    /** @return array{public:string, secret:string} base64 */
    public static function keypair(): array
    {
        $pair = sodium_crypto_sign_keypair();

        return [
            'public' => base64_encode(sodium_crypto_sign_publickey($pair)),
            'secret' => base64_encode(sodium_crypto_sign_secretkey($pair)),
        ];
    }

    /**
     * A detached signature, as a small readable file.
     *
     * Readable on purpose: whoever verifies it should be able to see what was
     * signed without running anything.
     *
     * @return array{algorithm:string, digest:string, signed_at:string, public_key:string, signature:string}
     */
    /**
     * @param string $previous the digest of the report this one succeeds, when there is one
     *
     * @return array{algorithm:string, digest:string, signed_at:string, public_key:string, signature:string, previous?:string, hybrid?:array{algorithm:string, public_key:string, signature:string}, ephemeral?:bool}
     */
    public static function sign(string $digest, string $secretKeyBase64, string $previous = '', string $hybridSecretPem = ''): array
    {
        $secret = base64_decode($secretKeyBase64, true);
        if ($secret === false || \strlen($secret) !== \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \RuntimeException('invalid secret key');
        }

        $signedAt = (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM);
        $payload = self::payload($digest, $signedAt, $previous);

        $block = [
            'algorithm' => self::ALGORITHM,
            'digest' => $digest,
            'signed_at' => $signedAt,
            'public_key' => base64_encode(sodium_crypto_sign_publickey_from_secretkey($secret)),
            'signature' => base64_encode(sodium_crypto_sign_detached($payload, $secret)),
        ];

        // Each report names the one before it, inside what is signed. A chain
        // of them is then an audit trail rather than a pile of files: somebody
        // who holds the last one can walk back, and a missing link shows.
        if ($previous !== '') {
            $block['previous'] = $previous;
        }

        // The same bytes, signed again by a scheme Shor does not touch. Added
        // rather than substituted: whoever cannot run ML-DSA still verifies the
        // report, and whoever can gets a signature that outlives the curve.
        $hybrid = $hybridSecretPem !== '' ? MlDsa::sign($payload, $hybridSecretPem) : null;
        if ($hybrid !== null) {
            $block['hybrid'] = [
                'algorithm' => MlDsa::ALGORITHM,
                'public_key' => MlDsa::publicFrom($hybridSecretPem),
                'signature' => $hybrid,
            ];
        }

        return $block;
    }

    /**
     * The digest of an existing signature block, for the report about to replace it.
     *
     * Reading it costs one file and makes the chain automatic: a second run
     * over the same output path succeeds the first without anybody passing a
     * flag, which is the only version of this that gets used.
     */
    public static function previousDigest(string $signaturePath): string
    {
        if (!is_file($signaturePath)) {
            return '';
        }

        $block = Value::map(json_decode((string) file_get_contents($signaturePath), true));

        return Value::string($block['digest'] ?? null);
    }

    /**
     * @param array{algorithm?:string, digest?:string, signed_at?:string, public_key?:string, signature?:string, previous?:string, hybrid?:array<string, mixed>} $block
     *
     * @return array{valid:bool, reason:string, hybrid?:string}
     */
    public static function verify(array $block, ?string $expectedDigest = null, ?string $expectedPublicKey = null, ?string $expectedPqKey = null): array
    {
        foreach (['algorithm', 'digest', 'signed_at', 'public_key', 'signature'] as $field) {
            if (!isset($block[$field]) || $block[$field] === '') {
                return ['valid' => false, 'reason' => 'verify.incomplete', 'hybrid' => 'absent'];
            }
        }

        if ($block['algorithm'] !== self::ALGORITHM) {
            return ['valid' => false, 'reason' => 'verify.algorithm'];
        }

        // A signature that verifies against a key nobody vouched for proves
        // nothing: the expected key comes from the versioned declaration.
        if ($expectedPublicKey !== null && $expectedPublicKey !== '' && !hash_equals($expectedPublicKey, $block['public_key'])) {
            return ['valid' => false, 'reason' => 'verify.wrong_key'];
        }

        if ($expectedDigest !== null && !hash_equals($expectedDigest, $block['digest'])) {
            return ['valid' => false, 'reason' => 'verify.changed'];
        }

        $key = base64_decode($block['public_key'], true);
        $signature = base64_decode($block['signature'], true);
        // Both lengths are checked, not just the key's: sodium throws on a
        // signature of the wrong size, and a malformed file must come back as
        // a verdict rather than as a stack trace.
        if ($key === false || $signature === false
            || \strlen($key) !== \SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || \strlen($signature) !== \SODIUM_CRYPTO_SIGN_BYTES) {
            return ['valid' => false, 'reason' => 'verify.malformed'];
        }

        $payload = self::payload($block['digest'], $block['signed_at'], $block['previous'] ?? '');
        $ok = sodium_crypto_sign_verify_detached($signature, $payload, $key);
        if (!$ok) {
            return ['valid' => false, 'reason' => 'verify.invalid', 'hybrid' => 'absent'];
        }

        // The second half, when the file carries one. Three answers rather than
        // two: an old OpenSSL means "cannot tell", and collapsing that into
        // "invalid" would turn a missing library into a forgery accusation.
        $hybrid = Value::map($block['hybrid'] ?? null);
        if ($hybrid === []) {
            return ['valid' => true, 'reason' => 'verify.valid', 'hybrid' => 'absent'];
        }

        // The second key is checked against the declaration too. Skipping that
        // would leave it asserted by the very file it signs, which is worth
        // nothing to anybody who can already forge the Ed25519 half — and that
        // is the only reader this signature was added for.
        $pqKey = Value::string($hybrid['public_key'] ?? null);
        if ($expectedPqKey !== null && $expectedPqKey !== ''
            && !hash_equals(self::canonicalPem($expectedPqKey), self::canonicalPem($pqKey))) {
            return ['valid' => false, 'reason' => 'verify.wrong_key_pq', 'hybrid' => 'invalid'];
        }

        $held = MlDsa::verify($payload, Value::string($hybrid['signature'] ?? null), $pqKey);

        return match ($held) {
            true => ['valid' => true, 'reason' => 'verify.valid.hybrid', 'hybrid' => 'valid'],
            false => ['valid' => false, 'reason' => 'verify.invalid.hybrid', 'hybrid' => 'invalid'],
            default => ['valid' => true, 'reason' => 'verify.valid.unchecked', 'hybrid' => 'unavailable'],
        };
    }

    /**
     * What the signature actually covers.
     *
     * The previous digest is appended rather than inserted, so a block without
     * one produces the same bytes as before this existed: signatures made by
     * older versions still verify.
     */
    /** A PEM compared on its content, not on how its lines were wrapped. */
    public static function canonicalPem(string $pem): string
    {
        return (string) preg_replace('/\s+/', '', $pem);
    }

    private static function payload(string $digest, string $signedAt, string $previous = ''): string
    {
        return "sablier-report/1\n".$digest."\n".$signedAt.($previous !== '' ? "\n".$previous : '');
    }
}
