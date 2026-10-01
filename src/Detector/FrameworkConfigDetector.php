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
    ];

    public function supports(SourceFile $file): bool
    {
        return $file->hasExtension('php')
            && (\in_array($file->name, self::FILENAMES, true) || str_contains($file->relativePath, 'config/'));
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
