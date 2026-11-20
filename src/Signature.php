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
                // The declared name, which is the team's and the same in every
                // language — but the label of an *undeclared* domain is
                // translated, and putting it here made the digest depend on the
                // language the report was rendered in. Three renderings of one
                // inventory then produced three digests, while the seal printed
                // underneath them claimed the opposite. Found by publishing the
                // same report in three languages and reading the three values.
                $finding->domainDeclared ? $finding->domain : '-',
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
        $raw = self::keysHash($publicKeyBase64, $pqPublicPem);

        return implode(' ', str_split(strtoupper(bin2hex(substr($raw, 0, 16))), 4));
    }

    /**
     * The hash the fingerprint shortens, whole: 32 raw bytes.
     *
     * The fingerprint keeps half of it because a line read aloud has to stay
     * short. The sky of the keys (see {@see Sky}) is drawn from all of it, so
     * the drawing and the fingerprint are two views of one value and cannot
     * disagree about which keys they describe.
     */
    public static function keysHash(string $publicKeyBase64, string $pqPublicPem = ''): string
    {
        return hash('sha256', $publicKeyBase64."\n".self::canonicalPem($pqPublicPem), true);
    }

    /**
     * That hash, whole, as one line: `SHA256:` and 43 characters of base64.
     *
     * The fingerprint is half the hash, which is enough to compare two keys
     * and not enough to draw their sky. This line is all of it, in the
     * notation OpenSSH prints and Stellar reads, so that anybody can paste it
     * into another implementation and see whether the sky this tool drew is
     * the one the keys have. A drawing only this program could produce would
     * be a drawing nobody could check.
     */
    public static function fullFingerprint(string $publicKeyBase64, string $pqPublicPem = ''): string
    {
        return 'SHA256:'.rtrim(base64_encode(self::keysHash($publicKeyBase64, $pqPublicPem)), '=');
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
        $sealed = self::seal(self::payload($digest, $signedAt, $previous), $secret, $hybridSecretPem);

        $block = [
            'algorithm' => self::ALGORITHM,
            'digest' => $digest,
            'signed_at' => $signedAt,
            'public_key' => $sealed['public_key'],
            'signature' => $sealed['signature'],
        ];

        // Each report names the one before it, inside what is signed. A chain
        // of them is then an audit trail rather than a pile of files: somebody
        // who holds the last one can walk back, and a missing link shows.
        if ($previous !== '') {
            $block['previous'] = $previous;
        }

        if (isset($sealed['hybrid'])) {
            $block['hybrid'] = $sealed['hybrid'];
        }

        return $block;
    }

    /**
     * The page itself, signed as the file it is.
     *
     * The findings signature cannot cover the page that displays it: a file
     * that prints its own signature would have to contain it before it was
     * computed. A signature written *beside* the page has no such problem, so
     * once every byte of the page is on disk, its SHA-256 is signed with the
     * same key and the same two schemes, and filed as `<page>.page.sig`.
     *
     * The payload starts with its own label, `sablier-page/2`, so a page
     * signature can never be passed off as a findings signature or the other
     * way round, and it carries the findings digest the page displays: a page
     * signature presented beside another analysis's `.sig` says so.
     *
     * Since 0.13.2 it also carries the page's size in bytes, signed with the
     * rest, so `verify` can say how big the signed page was — a figure a
     * reader can compare with the file in hand, where a hash is not. The
     * label moved to `/2` for it; `/1` files, without a size, still verify.
     *
     * @return array{covers:string, algorithm:string, file:string, sha256:string, size:int, digest:string, signed_at:string, public_key:string, signature:string, hybrid?:array{algorithm:string, public_key:string, signature:string}}
     */
    public static function signPage(string $pagePath, string $digest, string $secretKeyBase64, string $hybridSecretPem = ''): array
    {
        $secret = base64_decode($secretKeyBase64, true);
        if ($secret === false || \strlen($secret) !== \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \RuntimeException('invalid secret key');
        }

        $file = basename($pagePath);
        $sha256 = self::pageHash($pagePath);
        $size = self::pageSize($pagePath);
        $signedAt = (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM);
        $sealed = self::seal(self::pagePayload($file, $sha256, $digest, $signedAt, $size), $secret, $hybridSecretPem);

        $block = [
            'covers' => 'page',
            'algorithm' => self::ALGORITHM,
            'file' => $file,
            'sha256' => $sha256,
            'size' => $size,
            'digest' => $digest,
            'signed_at' => $signedAt,
            'public_key' => $sealed['public_key'],
            'signature' => $sealed['signature'],
        ];
        if (isset($sealed['hybrid'])) {
            $block['hybrid'] = $sealed['hybrid'];
        }

        return $block;
    }

    /** Where the signature of a page is filed: beside it, under its name. */
    public static function pagePath(string $pagePath): string
    {
        return $pagePath.'.page.sig';
    }

    /** The SHA-256 of a file as it is on disk, every byte of it. */
    public static function pageHash(string $pagePath): string
    {
        $hash = is_file($pagePath) ? hash_file('sha256', $pagePath) : false;

        return \is_string($hash) ? $hash : '';
    }

    /** The size of a file in bytes, as `verify` prints it; -1 when there is no file. */
    public static function pageSize(string $pagePath): int
    {
        $size = is_file($pagePath) ? filesize($pagePath) : false;

        return $size === false ? -1 : $size;
    }

    /**
     * A page against its signature.
     *
     * The signature is checked first and the page second, because they fail
     * for different reasons and the reader acts differently on each: a
     * signature that does not hold means the `.page.sig` file itself was
     * altered; a signature that holds over another hash means the page was.
     *
     * @param array<mixed> $block
     *
     * @return array{valid:bool, reason:string, hybrid:string}
     */
    public static function verifyPage(array $block, string $pagePath, ?string $expectedPublicKey = null, ?string $expectedPqKey = null): array
    {
        foreach (['algorithm', 'file', 'sha256', 'signed_at', 'public_key', 'signature'] as $field) {
            if (Value::string($block[$field] ?? null) === '') {
                return ['valid' => false, 'reason' => 'verify.incomplete', 'hybrid' => 'absent'];
            }
        }
        if (Value::string($block['covers'] ?? null) !== 'page') {
            return ['valid' => false, 'reason' => 'verify.page.not_page', 'hybrid' => 'unchecked'];
        }

        // The size decides the label: present, the payload is `/2` and the
        // size is in it; absent, it is a `/1` file from 0.13.1. Neither can be
        // turned into the other — adding or removing the field changes the
        // bytes the signature is checked over, and the check fails.
        $size = \array_key_exists('size', $block) ? $block['size'] : null;
        if ($size !== null && (!\is_int($size) || $size < 0)) {
            return ['valid' => false, 'reason' => 'verify.malformed', 'hybrid' => 'unchecked'];
        }
        $checked = self::check(
            self::pagePayload(
                Value::string($block['file'] ?? null),
                Value::string($block['sha256'] ?? null),
                Value::string($block['digest'] ?? null),
                Value::string($block['signed_at'] ?? null),
                $size,
            ),
            $block,
            $expectedPublicKey,
            $expectedPqKey,
        );
        if (!$checked['valid']) {
            return $checked;
        }

        if (!is_file($pagePath)) {
            return ['valid' => false, 'reason' => 'verify.page.missing', 'hybrid' => $checked['hybrid']];
        }
        if (!hash_equals(Value::string($block['sha256'] ?? null), self::pageHash($pagePath))
            || ($size !== null && $size !== self::pageSize($pagePath))) {
            return ['valid' => false, 'reason' => 'verify.page.modified', 'hybrid' => $checked['hybrid']];
        }

        return ['valid' => true, 'reason' => 'verify.page.valid', 'hybrid' => $checked['hybrid']];
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
     * The second half reports one of five states, and `unchecked` is not
     * `unavailable`: when the Ed25519 half already failed there is nothing to
     * learn from the other, and saying "this machine cannot verify ML-DSA" on a
     * machine that can sends the reader to install an OpenSSL they already have
     * instead of looking at the key that did not match.
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

        // The algorithm and the key are judged before the digest, as they
        // always were: a file signed by somebody else is that, first, whatever
        // it claims to cover. check() asks both again, which costs nothing.
        if ($expectedDigest !== null && !hash_equals($expectedDigest, $block['digest'])) {
            $first = self::check('', $block, $expectedPublicKey, null);
            if (\in_array($first['reason'], ['verify.algorithm', 'verify.wrong_key'], true)) {
                return $first;
            }

            return ['valid' => false, 'reason' => 'verify.changed', 'hybrid' => 'unchecked'];
        }

        return self::check(self::payload($block['digest'], $block['signed_at'], $block['previous'] ?? ''), $block, $expectedPublicKey, $expectedPqKey);
    }

    /**
     * Both halves of a signature over a payload, against the keys a reader expects.
     *
     * @param array<mixed> $block
     *
     * @return array{valid:bool, reason:string, hybrid:string}
     */
    private static function check(string $payload, array $block, ?string $expectedPublicKey, ?string $expectedPqKey): array
    {
        if (Value::string($block['algorithm'] ?? null) !== self::ALGORITHM) {
            return ['valid' => false, 'reason' => 'verify.algorithm', 'hybrid' => 'unchecked'];
        }

        // A signature that verifies against a key nobody vouched for proves
        // nothing: the expected key comes from the versioned declaration.
        $publicKey = Value::string($block['public_key'] ?? null);
        if ($expectedPublicKey !== null && $expectedPublicKey !== '' && !hash_equals($expectedPublicKey, $publicKey)) {
            return ['valid' => false, 'reason' => 'verify.wrong_key', 'hybrid' => 'unchecked'];
        }

        $key = base64_decode($publicKey, true);
        $signature = base64_decode(Value::string($block['signature'] ?? null), true);
        // Both lengths are checked, not just the key's: sodium throws on a
        // signature of the wrong size, and a malformed file must come back as
        // a verdict rather than as a stack trace.
        if ($key === false || $signature === false
            || \strlen($key) !== \SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || \strlen($signature) !== \SODIUM_CRYPTO_SIGN_BYTES) {
            return ['valid' => false, 'reason' => 'verify.malformed', 'hybrid' => 'unchecked'];
        }

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
     * One payload, signed by Ed25519 and, when the key has its other half, by ML-DSA-65.
     *
     * @param non-empty-string $secret
     * @return array{public_key:string, signature:string, hybrid?:array{algorithm:string, public_key:string, signature:string}}
     */
    private static function seal(string $payload, string $secret, string $hybridSecretPem): array
    {
        $sealed = [
            'public_key' => base64_encode(sodium_crypto_sign_publickey_from_secretkey($secret)),
            'signature' => base64_encode(sodium_crypto_sign_detached($payload, $secret)),
        ];

        // The same bytes, signed again by a scheme Shor does not touch. Added
        // rather than substituted: whoever cannot run ML-DSA still verifies the
        // report, and whoever can gets a signature that outlives the curve.
        $hybrid = $hybridSecretPem !== '' ? MlDsa::sign($payload, $hybridSecretPem) : null;
        if ($hybrid !== null) {
            $sealed['hybrid'] = [
                'algorithm' => MlDsa::ALGORITHM,
                'public_key' => MlDsa::publicFrom($hybridSecretPem),
                'signature' => $hybrid,
            ];
        }

        return $sealed;
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

    private static function pagePayload(string $file, string $sha256, string $digest, string $signedAt, ?int $size = null): string
    {
        // The size after the hash it describes; `/1` is byte for byte what
        // 0.13.1 signed, so its files keep verifying.
        return $size === null
            ? "sablier-page/1\n".$file."\n".$sha256."\n".$digest."\n".$signedAt
            : "sablier-page/2\n".$file."\n".$sha256."\n".$size."\n".$digest."\n".$signedAt;
    }
}
