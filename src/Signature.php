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
 * The uncomfortable part, stated in the report rather than buried here: the
 * only signature algorithm PHP ships is Ed25519, which this tool's own
 * catalogue classifies as quantum-vulnerable. That is defensible for a report
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
    public static function sign(string $digest, string $secretKeyBase64): array
    {
        $secret = base64_decode($secretKeyBase64, true);
        if ($secret === false || \strlen($secret) !== \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \RuntimeException('invalid secret key');
        }

        $signedAt = (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM);
        $payload = self::payload($digest, $signedAt);

        return [
            'algorithm' => self::ALGORITHM,
            'digest' => $digest,
            'signed_at' => $signedAt,
            'public_key' => base64_encode(sodium_crypto_sign_publickey_from_secretkey($secret)),
            'signature' => base64_encode(sodium_crypto_sign_detached($payload, $secret)),
        ];
    }

    /**
     * @param array{algorithm?:string, digest?:string, signed_at?:string, public_key?:string, signature?:string} $block
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
        if ($key === false || $signature === false || \strlen($key) !== \SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return ['valid' => false, 'reason' => 'verify.malformed'];
        }

        $ok = sodium_crypto_sign_verify_detached($signature, self::payload($block['digest'], $block['signed_at']), $key);

        return ['valid' => $ok, 'reason' => $ok ? 'verify.valid' : 'verify.invalid'];
    }

    private static function payload(string $digest, string $signedAt): string
    {
        return "sablier-report/1\n".$digest."\n".$signedAt;
    }
}
