<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The post-quantum signature, borrowed from the openssl binary.
 *
 * This tool tells people to migrate their signatures before 2030, and its own
 * reports were signed with Ed25519 alone. The reason was not laziness: PHP
 * cannot do it. libsodium exposes no post-quantum signature at all, and
 * ext-openssl reads an ML-DSA key but refuses to sign with it — its API takes a
 * digest, and ML-DSA is a pure scheme with nothing to pre-hash. `openssl_sign`
 * answers `invalid digest` and stops there.
 *
 * The binary can, from OpenSSL 3.5. So the signature is made by the same tool
 * the probe already borrows, and three rules keep that honest:
 *
 * - **in addition, never instead.** Ed25519 works everywhere PHP runs; ML-DSA
 *   needs a recent OpenSSL. Replacing one with the other would make reports
 *   unverifiable for whoever has the older library, which is most people. This
 *   is also the position ANSSI takes and this tool cites: hybridation.
 * - **borrowed, never implemented.** A hand-written lattice signature in a tool
 *   whose whole credit rests on not inventing cryptography would be the worst
 *   thing this project could ship.
 * - **said out loud when absent.** On a machine without it the report states
 *   that it carries one signature and why, rather than quietly carrying less
 *   than it claims.
 */
final class MlDsa
{
    /** 65 is the middle parameter set: category 3, and what CNSA 2.0 asks of new systems. */
    public const string ALGORITHM = 'ML-DSA-65';

    private static ?bool $available = null;

    /**
     * Whether this machine can sign at all.
     *
     * Asked once: the answer cannot change inside a run, and it costs a process
     * each time it is asked.
     */
    public static function available(): bool
    {
        if (self::$available !== null) {
            return self::$available;
        }

        $binary = self::binary();
        if ($binary === null) {
            return self::$available = false;
        }

        $list = (string) @shell_exec(escapeshellarg($binary).' list -signature-algorithms 2>/dev/null');

        return self::$available = str_contains(strtolower($list), strtolower(self::ALGORITHM));
    }

    /**
     * A key pair, as PEM.
     *
     * @return array{public:string, secret:string}|null
     */
    public static function keypair(): ?array
    {
        $binary = self::binary();
        if ($binary === null || !self::available()) {
            return null;
        }

        $secret = self::temporary();
        $public = self::temporary();
        @shell_exec(\sprintf(
            '%s genpkey -algorithm %s -out %s 2>/dev/null',
            escapeshellarg($binary), escapeshellarg(self::ALGORITHM), escapeshellarg($secret),
        ));
        @shell_exec(\sprintf(
            '%s pkey -in %s -pubout -out %s 2>/dev/null',
            escapeshellarg($binary), escapeshellarg($secret), escapeshellarg($public),
        ));

        $pair = ['secret' => (string) @file_get_contents($secret), 'public' => (string) @file_get_contents($public)];
        self::shred($secret, $public);

        return str_contains($pair['secret'], 'PRIVATE KEY') && str_contains($pair['public'], 'PUBLIC KEY')
            ? $pair
            : null;
    }

    /** The public half of a secret PEM, which is what a verifier needs. */
    public static function publicFrom(string $secretPem): string
    {
        $binary = self::binary();
        if ($binary === null || !self::available()) {
            return '';
        }

        $key = self::temporary();
        $public = self::temporary();
        file_put_contents($key, $secretPem);
        chmod($key, 0o600);
        @shell_exec(\sprintf(
            '%s pkey -in %s -pubout -out %s 2>/dev/null',
            escapeshellarg($binary), escapeshellarg($key), escapeshellarg($public),
        ));

        $pem = (string) @file_get_contents($public);
        self::shred($key, $public);

        return $pem;
    }

    /** The detached signature, base64, or null when this machine cannot make one. */
    public static function sign(string $payload, string $secretPem): ?string
    {
        $binary = self::binary();
        if ($binary === null || !self::available() || !str_contains($secretPem, 'PRIVATE KEY')) {
            return null;
        }

        $key = self::temporary();
        $message = self::temporary();
        $signature = self::temporary();
        file_put_contents($key, $secretPem);
        chmod($key, 0o600);
        file_put_contents($message, $payload);

        // -rawin: ML-DSA signs the message itself. There is no digest to pass,
        // which is exactly why PHP's own API cannot express this call.
        @shell_exec(\sprintf(
            '%s pkeyutl -sign -rawin -inkey %s -in %s -out %s 2>/dev/null',
            escapeshellarg($binary), escapeshellarg($key), escapeshellarg($message), escapeshellarg($signature),
        ));

        $bytes = (string) @file_get_contents($signature);
        self::shred($key, $message, $signature);

        return $bytes === '' ? null : base64_encode($bytes);
    }

    /**
     * Whether a signature holds.
     *
     * Three answers, not two: it held, it did not, or this machine cannot tell.
     * Collapsing the third into "invalid" would turn an old OpenSSL into a
     * forgery accusation.
     */
    public static function verify(string $payload, string $signatureBase64, string $publicPem): ?bool
    {
        $binary = self::binary();
        $bytes = base64_decode($signatureBase64, true);
        if ($binary === null || !self::available() || $bytes === false || !str_contains($publicPem, 'PUBLIC KEY')) {
            return null;
        }

        $key = self::temporary();
        $message = self::temporary();
        $signature = self::temporary();
        file_put_contents($key, $publicPem);
        file_put_contents($message, $payload);
        file_put_contents($signature, $bytes);

        $output = (string) @shell_exec(\sprintf(
            '%s pkeyutl -verify -rawin -pubin -inkey %s -in %s -sigfile %s 2>&1',
            escapeshellarg($binary), escapeshellarg($key), escapeshellarg($message), escapeshellarg($signature),
        ));
        self::shred($key, $message, $signature);

        return str_contains(strtolower($output), 'verified successfully');
    }

    private static function binary(): ?string
    {
        $path = trim((string) @shell_exec('command -v openssl 2>/dev/null'));

        return $path !== '' ? $path : null;
    }

    private static function temporary(): string
    {
        return sys_get_temp_dir().'/sablier-mldsa-'.bin2hex(random_bytes(6));
    }

    /** A private key written to disk leaves with the function that wrote it. */
    private static function shred(string ...$paths): void
    {
        foreach ($paths as $path) {
            if (is_file($path)) {
                @file_put_contents($path, str_repeat("\0", max(1, (int) @filesize($path))));
                @unlink($path);
            }
        }
    }
}
