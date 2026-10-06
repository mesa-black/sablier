<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;
use Sablier\Value;

/**
 * Cryptography chosen in a PHP framework's configuration array.
 *
 * Laravel, CakePHP and Laminas all put the decision in the same kind of file —
 * a PHP array under config/ — with three different vocabularies. One detector
 * rather than three, because the file kind is identical; only the keys differ.
 *
 * This is where a framework's default becomes a project's choice, and it is
 * routinely the only place a cipher is named in a whole codebase: application
 * code calls `encrypt()` and never sees an algorithm.
 */
final class FrameworkConfigDetector implements DetectorInterface
{
    private const array FILENAMES = [
        'app.php', 'app_local.php', 'database.php', 'session.php',
        'hashing.php', 'mail.php', 'module.config.php', 'global.php', 'local.php',
        // Laravel with tymon/jwt-auth, and Laravel's object storage.
        'jwt.php', 'filesystems.php', 'broadcasting.php',
    ];

    public function supports(SourceFile $file): bool
    {
        // `Config/` with a capital as well as `config/`: CodeIgniter puts its
        // encryption settings in `app/Config/Encryption.php`, and the lowercase
        // test walked past the whole framework.
        return $file->hasExtension('php')
            && (\in_array($file->name, self::FILENAMES, true)
                || str_contains($file->relativePath, 'config/')
                || str_contains($file->relativePath, 'Config/'));
    }

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();

        $rules = [
            // Laravel: the application cipher, and CakePHP's Security engine.
            ['/[\'"]cipher[\'"]\s*=>\s*[\'"]([a-z0-9\-]+)[\'"]/i', 'capture', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.cipher'],
            // Laminas\Crypt block cipher.
            ['/[\'"]algo[\'"]\s*=>\s*[\'"](aes|blowfish|des)[\'"]/i', 'crypt', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.cipher'],
            // Laravel hashing driver — listed so the report can say "leave it alone".
            ['/[\'"]driver[\'"]\s*=>\s*[\'"](bcrypt|argon2?i?d?)[\'"]/i', 'hash', Catalogue::PURPOSE_INTEGRITY, 'detail.framework.hashing'],
            // Mail transport encryption, all three frameworks.
            ['/[\'"]encryption[\'"]\s*=>\s*[\'"](tls|ssl)[\'"]/i', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.mail_tls'],
            ['/[\'"]encryption[\'"]\s*=>\s*(null|false)/i', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.mail_plain'],
            // Database transport.
            ['/PDO::MYSQL_ATTR_SSL_(?:CA|CERT|KEY)/', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.db_tls'],
            ['/[\'"]ssl_ca[\'"]\s*=>/i', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.db_tls'],
            // Laravel session payloads.
            ['/[\'"]encrypt[\'"]\s*=>\s*false/i', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.session_plain'],
            // Laravel with tymon/jwt-auth: the signature behind every API token,
            // written once in config/jwt.php and never thought about again.
            ['/[\'"]algo[\'"]\s*=>\s*[\'"]((?:HS|RS|PS|ES)(?:256|384|512)|EdDSA)[\'"]/i', 'jose', Catalogue::PURPOSE_AUTHENTICITY, 'detail.framework.jwt_algo'],
            // Laravel's Postgres connections say it in a word.
            ['/[\'"]sslmode[\'"]\s*=>\s*[\'"](require|verify-ca|verify-full|prefer)[\'"]/i', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.db_tls'],
            ['/[\'"]sslmode[\'"]\s*=>\s*[\'"](disable|allow)[\'"]/i', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.db_plain'],
            // Laravel filesystems: what the object store is told to do with the
            // bytes once they arrive.
            ['/[\'"]ServerSideEncryption[\'"]\s*=>\s*[\'"](AES256|aws:kms)[\'"]/i', 'aes-256', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.object_sse'],
            // Laravel broadcasting: Pusher over plain HTTP.
            ['/[\'"]useTLS[\'"]\s*=>\s*false/i', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.broadcast_plain'],
            // CodeIgniter 4, app/Config/Encryption.php — a property rather than
            // an array key, which is why the pattern is shaped differently.
            ['/\$cipher\s*=\s*[\'"]([A-Za-z0-9\-]+)[\'"]/', 'capture', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.cipher'],
            ['/\$digest\s*=\s*[\'"](SHA256|SHA512|SHA1|MD5)[\'"]/i', 'capture', Catalogue::PURPOSE_INTEGRITY, 'detail.framework.digest'],
            // Yii2 signs its cookies with HMAC-SHA256, keyed by this one value.
            ['/[\'"]cookieValidationKey[\'"]\s*=>/i', 'hmac-sha256', Catalogue::PURPOSE_INTEGRITY, 'detail.framework.cookie_signed'],
            // Laravel Passport signs its OAuth2 tokens with an RSA key pair, and
            // config/passport.php is where the two halves are named.
            ['/[\'"](?:private_key|public_key)[\'"]\s*=>\s*env\(\s*[\'"]PASSPORT_/i', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.framework.passport'],
            // Redis over TLS, which Laravel spells in the connection scheme.
            ['/[\'"]scheme[\'"]\s*=>\s*[\'"]tls[\'"]/i', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.cache_tls'],
            // Pusher's older spelling of the same thing.
            ['/[\'"]encrypted[\'"]\s*=>\s*true/i', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.framework.broadcast_tls'],
        ];

        foreach ($rules as [$pattern, $kind, $purpose, $detail]) {
            if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }

            foreach ($matches[0] as $index => [$hit, $offset]) {
                $offset = Value::int($offset);
                // The first group, or an empty string: a rule whose pattern has
                // no group, or a group that did not take part, must not reach
                // strtolower() as a missing offset.
                $captured = $matches[1][$index][0] ?? '';
                $algorithm = match ($kind) {
                    'capture' => Catalogue::normalise($captured),
                    // RS256 is a public-key signature and HS256 is a shared
                    // secret: the report is useless if it prints the JOSE name
                    // and leaves the reader to know which is which.
                    'jose' => Catalogue::fromJose($captured),
                    'crypt' => match (strtolower($captured)) {
                        'aes' => 'aes-256', 'des' => 'des', default => null,
                    },
                    'hash' => str_starts_with(strtolower($captured), 'argon') ? 'argon2' : 'bcrypt',
                    default => $kind,
                };

                if ($algorithm === null) {
                    continue;
                }

                yield new Finding(
                    algorithm: $algorithm,
                    purpose: $purpose,
                    file: $file->relativePath,
                    line: $file->lineAt($offset),
                    evidence: trim($hit),
                    detail: Lang::t($detail),
                );
            }
        }
    }
}
