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
 * The uncomfortable part, stated in the report rather than buried here: PHP
 * offers no post-quantum signature at all. RSA and ECDSA come with ext-openssl,
 * Ed25519 with ext-sodium, and all three fall to Shor — so the choice was never
 * "Ed25519 or nothing" but "Ed25519 or equally exposed". Ed25519 is the
 * soundest of the three: modern, compact, no parameter to get wrong. It stays
 * quantum-vulnerable, which this tool's own catalogue says. That is defensible
 * for a report
 * whose authenticity matters for months — a signature cannot be harvested, and
 * breaking the curve in 2035 does not forge a 2026 signature anyone still
 * cares about. It is not defensible for a report you must still prove genuine
 * after the expiry year. Sablier says which of the two you are in and lets you
 * decide; pretending the question does not exist would be exactly the silence
 * this project was built to end.
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
     * @return array{algorithm:string, digest:string, signed_at:string, public_key:string, signature:string, previous?:string}
     */
    public static function sign(string $digest, string $secretKeyBase64, string $previous = ''): array
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
     * @param array{algorithm?:string, digest?:string, signed_at?:string, public_key?:string, signature?:string, previous?:string} $block
     *
     * @return array{valid:bool, reason:string}
     */
    public static function verify(array $block, ?string $expectedDigest = null, ?string $expectedPublicKey = null): array
    {
        foreach (['algorithm', 'digest', 'signed_at', 'public_key', 'signature'] as $field) {
            if (!isset($block[$field]) || $block[$field] === '') {
                return ['valid' => false, 'reason' => 'verify.incomplete'];
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

        $ok = sodium_crypto_sign_verify_detached(
            $signature,
            self::payload($block['digest'], $block['signed_at'], $block['previous'] ?? ''),
            $key,
        );

        return ['valid' => $ok, 'reason' => $ok ? 'verify.valid' : 'verify.invalid'];
    }

    /**
     * What the signature actually covers.
     *
     * The previous digest is appended rather than inserted, so a block without
     * one produces the same bytes as before this existed: signatures made by
     * older versions still verify.
     */
    private static function payload(string $digest, string $signedAt, string $previous = ''): string
    {
        return "sablier-report/1\n".$digest."\n".$signedAt.($previous !== '' ? "\n".$previous : '');
    }
}
