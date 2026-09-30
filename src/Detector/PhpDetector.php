<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\SourceFile;

/** Cryptography called from PHP source. */
final class PhpDetector extends PatternDetector
{
    /** Hints that a hash call is an identifier, not a security control. */
    private const string NON_CRYPTO_HINT = '/cache|etag|identif|slug|fingerprint|gravatar|colou?r|filename|checksum_of_name|dedup/i';

    private const array HASHES = ['md5', 'sha1', 'sha256', 'sha512'];

    public function supports(SourceFile $file): bool
    {
        return $file->hasExtension('php');
    }

    protected function rules(): array
    {
        return [
            // Symmetric encryption with a literal cipher…
            ['/openssl_(?:en|de)crypt\s*\(\s*[^,]+,\s*[\'"]([a-z0-9\-]+)[\'"]/i', self::CAPTURE, Catalogue::PURPOSE_CONFIDENTIALITY, ''],
            // …and with the cipher coming from somewhere else.
            ['/openssl_(?:en|de)crypt\s*\(\s*[^,]+,\s*[\$A-Z]/', null, Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.cipher_from_variable'],
            ['/OPENSSL_KEYTYPE_RSA/', 'rsa', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.rsa_keygen'],
            ['/OPENSSL_KEYTYPE_EC/', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, 'detail.ec_keygen'],
            ['/openssl_sign\s*\(/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.openssl_sign'],
            ['/openssl_verify\s*\(/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.openssl_verify'],
            ['/sodium_crypto_box\w*\s*\(/', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.sodium_box'],
            ['/sodium_crypto_kx\w*\s*\(/', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.sodium_kx'],
            ['/sodium_crypto_sign\w*\s*\(/', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, 'detail.sodium_sign'],
            ['/sodium_crypto_secretbox\w*\s*\(/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.sodium_secretbox'],
            ['/sodium_crypto_aead_\w+\s*\(/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, ''],
            ['/\bhash(?:_hmac)?\s*\(\s*[\'"]([a-z0-9\-]+)[\'"]/i', self::CAPTURE, Catalogue::PURPOSE_INTEGRITY, ''],
            ['/\bmd5\s*\(/', 'md5', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/\bsha1\s*\(/', 'sha1', Catalogue::PURPOSE_INTEGRITY, ''],
            // Listed so the report can say "leave this alone".
            ['/PASSWORD_BCRYPT|PASSWORD_DEFAULT/', 'bcrypt', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/PASSWORD_ARGON2\w*/', 'argon2', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/[\'"](RS(?:256|384|512))[\'"]/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            ['/[\'"](PS(?:256|384|512))[\'"]/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            ['/[\'"](ES(?:256|384|512))[\'"]/', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            ['/[\'"]EdDSA[\'"]/', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            ['/\bmcrypt_\w+\s*\(/', 'des', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.mcrypt'],
        ];
    }

    protected function finding(SourceFile $file, int $offset, ?string $algorithm, string $purpose, string $detail): ?Finding
    {
        $finding = parent::finding($file, $offset, $algorithm, $purpose, $detail);
        if ($finding === null || !\in_array($algorithm, self::HASHES, true)) {
            return $finding;
        }

        // A digest used as an identifier, or one living in test code, is not a
        // security control. Saying so is what keeps three real findings from
        // drowning under forty false ones.
        $lineText = $file->lineTextAt($offset);
        $isNoise = preg_match(self::NON_CRYPTO_HINT, $lineText) === 1 || $file->isTestCode();

        return $isNoise
            ? new Finding($finding->algorithm, $finding->purpose, $finding->file, $finding->line,
                $finding->evidence, $finding->confidence, true, $finding->detail)
            : $finding;
    }
}
