<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Finds cryptography by reading files, and says how sure it is.
 *
 * The rule that shapes everything here: never guess. An algorithm passed as a
 * variable is reported as undetermined with its location, not resolved by
 * inference — a wrong inventory is worse than an incomplete one, because nobody
 * checks an inventory twice.
 */
final class Scanner
{
    /**
     * Matched on every path segment, not just the prefix: the first real scan
     * counted an entire project twice because a git worktree sat inside it, and
     * a nested vendor/ was read in full.
     */
    private const array SKIP_DIRS = ['.git', '.kilo', '.idea', '.vscode', '.svn', 'vendor', 'node_modules', 'var', 'build'];
    private const int MAX_BYTES = 2_000_000;

    /** Hints that a hash call is an identifier, not a security control. */
    private const string NON_CRYPTO_HINT = '/cache|etag|identif|slug|fingerprint|gravatar|colou?r|filename|checksum_of_name|dedup/i';

    /** Test code: real, but it protects nothing. Reporting it as a breach is how a tool loses its reader. */
    private const string TEST_PATH = '#(^|/)(tests?|spec|fixtures?)/#i';

    /** @var list<Finding> */
    private array $findings = [];

    /** @var list<string> */
    private array $blindSpots = [];

    private int $filesRead = 0;

    /** @return array{findings: list<Finding>, files: int, blind: list<string>} */
    public function scan(string $root): array
    {
        $root = rtrim(realpath($root) ?: $root, '/');
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                function (\SplFileInfo $file) use ($root): bool {
                    $rel = ltrim(str_replace($root, '', $file->getPathname()), '/');

                    return array_intersect(explode('/', $rel), self::SKIP_DIRS) === [];
                },
            ),
        );

        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile() || $file->getSize() > self::MAX_BYTES) {
                continue;
            }
            $rel = ltrim(str_replace($root, '', $file->getPathname()), '/');
            $this->inspect($file->getPathname(), $rel, $file->getExtension(), $file->getFilename());
        }

        return ['findings' => $this->findings, 'files' => $this->filesRead, 'blind' => $this->blindSpots];
    }

    private function inspect(string $path, string $rel, string $ext, string $name): void
    {
        $content = (string) file_get_contents($path);
        ++$this->filesRead;

        match (true) {
            $ext === 'php' => $this->php($content, $rel),
            $name === 'composer.lock' => $this->composerLock($content, $rel),
            \in_array($ext, ['pem', 'key', 'crt', 'cer', 'pub'], true),
                str_contains($content, '-----BEGIN') => $this->keyMaterial($content, $rel),
            $name === 'Caddyfile' || \in_array($ext, ['conf', 'cnf'], true) => $this->tlsConfig($content, $rel),
            \in_array($ext, ['sh', 'bash', 'yml', 'yaml'], true), $name === 'Dockerfile' => $this->shell($content, $rel),
            default => null,
        };
    }

    /** @param list<array{0:string,1:int}> $matches */
    private function lineOf(string $content, int $offset): int
    {
        return substr_count($content, "\n", 0, $offset) + 1;
    }

    private function php(string $content, string $rel): void
    {
        // Rules are (pattern, algorithm|null, purpose, detail). A null algorithm
        // means "we can see cryptography here but not which one" — reported as
        // undetermined rather than resolved.
        $rules = [
            // Symmetric encryption with a literal cipher.
            ['/openssl_(?:en|de)crypt\s*\(\s*[^,]+,\s*[\'"]([a-z0-9\-]+)[\'"]/i', 'capture', Catalogue::PURPOSE_CONFIDENTIALITY, ''],
            // …and with the cipher coming from somewhere else.
            ['/openssl_(?:en|de)crypt\s*\(\s*[^,]+,\s*[\$A-Z]/', null, Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.cipher_from_variable')],
            // Key generation.
            ['/OPENSSL_KEYTYPE_RSA/', 'rsa', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.rsa_keygen')],
            ['/OPENSSL_KEYTYPE_EC/', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.ec_keygen')],
            // Signatures.
            ['/openssl_sign\s*\(/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.openssl_sign')],
            ['/openssl_verify\s*\(/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.openssl_verify')],
            // libsodium.
            ['/sodium_crypto_box\w*\s*\(/', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.sodium_box')],
            ['/sodium_crypto_kx\w*\s*\(/', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.sodium_kx')],
            ['/sodium_crypto_sign\w*\s*\(/', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.sodium_sign')],
            ['/sodium_crypto_secretbox\w*\s*\(/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.sodium_secretbox')],
            ['/sodium_crypto_aead_\w+\s*\(/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, ''],
            // Hashes.
            ['/\bhash(?:_hmac)?\s*\(\s*[\'"]([a-z0-9\-]+)[\'"]/i', 'capture', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/\bmd5\s*\(/', 'md5', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/\bsha1\s*\(/', 'sha1', Catalogue::PURPOSE_INTEGRITY, ''],
            // Passwords — listed so the report can say "leave this alone".
            ['/PASSWORD_BCRYPT|PASSWORD_DEFAULT/', 'bcrypt', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/PASSWORD_ARGON2\w*/', 'argon2', Catalogue::PURPOSE_INTEGRITY, ''],
            // JWT / JOSE algorithms as literals.
            ['/[\'"](RS(?:256|384|512))[\'"]/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.jwt')],
            ['/[\'"](PS(?:256|384|512))[\'"]/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.jwt')],
            ['/[\'"](ES(?:256|384|512))[\'"]/', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.jwt')],
            ['/[\'"]EdDSA[\'"]/', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.jwt')],
            // Dead libraries.
            ['/\bmcrypt_\w+\s*\(/', 'des', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.mcrypt')],
        ];

        foreach ($rules as [$pattern, $algorithm, $purpose, $detail]) {
            if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }
            foreach ($matches[0] as $i => [$hit, $offset]) {
                $line = $this->lineOf($content, $offset);
                $lineText = $this->lineText($content, $offset);

                $resolved = $algorithm;
                if ($algorithm === 'capture') {
                    $resolved = Catalogue::normalise($matches[1][$i][0] ?? '');
                    if ($resolved === null) {
                        continue; // An algorithm we do not know: not our place to judge it.
                    }
                }

                $this->findings[] = new Finding(
                    algorithm: $resolved ?? 'undetermined',
                    purpose: $purpose,
                    file: $rel,
                    line: $line,
                    evidence: trim($lineText),
                    confidence: $resolved === null ? Finding::CONFIDENCE_MEDIUM : Finding::CONFIDENCE_HIGH,
                    likelyNonCrypto: \in_array($resolved, ['md5', 'sha1', 'sha256', 'sha512'], true)
                        && (preg_match(self::NON_CRYPTO_HINT, $lineText) === 1
                            || preg_match(self::TEST_PATH, $rel) === 1),
                    detail: $detail,
                );
            }
        }
    }

    private function lineText(string $content, int $offset): string
    {
        $start = strrpos(substr($content, 0, $offset), "\n");
        $start = $start === false ? 0 : $start + 1;
        $end = strpos($content, "\n", $offset);

        return substr($content, $start, ($end === false ? \strlen($content) : $end) - $start);
    }

    /**
     * Shell and pipeline files. This detector exists because the first real scan
     * missed the one thing that mattered: backup encryption lives in a deploy
     * script, not in application code — and backups are exactly the long-lived
     * confidential data the whole tool is about.
     */
    private function shell(string $content, string $rel): void
    {
        $rules = [
            ['/openssl\s+enc\b[^\n]*-(aes-?256[a-z0-9\-]*)/i', 'aes-256', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.cli_symmetric')],
            ['/openssl\s+enc\b[^\n]*-(aes-?128[a-z0-9\-]*)/i', 'aes-128', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.cli_symmetric')],
            ['/openssl\s+enc\b[^\n]*-(des3|des)/i', 'des', Catalogue::PURPOSE_CONFIDENTIALITY, ''],
            ['/openssl\s+genrsa|newkey\s+rsa:/i', 'rsa', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.rsa_keygen')],
            ['/openssl\s+ecparam|newkey\s+ec:/i', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.ec_keygen')],
            ['/gpg\b[^\n]*--cipher-algo\s+(AES256|AES128|3DES)/i', 'capture', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.gpg')],
            ['/ssh-keygen\b[^\n]*-t\s+(rsa|ed25519|ecdsa)/i', 'capture-ssh', Catalogue::PURPOSE_AUTHENTICITY, Lang::t('detail.ssh_keygen')],
            ['/\bage\s+-r\b/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, Lang::t('detail.age')],
        ];

        foreach ($rules as [$pattern, $algorithm, $purpose, $detail]) {
            if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }
            foreach ($matches[0] as $i => [$hit, $offset]) {
                $resolved = $algorithm;
                if ($algorithm === 'capture') {
                    $resolved = Catalogue::normalise($matches[1][$i][0] ?? '');
                } elseif ($algorithm === 'capture-ssh') {
                    $resolved = match (strtolower($matches[1][$i][0] ?? '')) {
                        'rsa' => 'rsa-sign', 'ecdsa' => 'ecdsa', default => 'ed25519',
                    };
                }
                if ($resolved === null) {
                    continue;
                }
                $this->findings[] = new Finding($resolved, $purpose, $rel, $this->lineOf($content, $offset), trim($this->lineText($content, $offset)), Finding::CONFIDENCE_HIGH, false, $detail);
            }
        }
    }

    private function keyMaterial(string $content, string $rel): void
    {
        $map = [
            'BEGIN RSA PRIVATE KEY' => ['rsa', Lang::t('detail.rsa_private_key')],
            'BEGIN EC PRIVATE KEY' => ['ecdsa', Lang::t('detail.ec_private_key')],
            'BEGIN OPENSSH PRIVATE KEY' => ['ed25519', Lang::t('detail.openssh_private_key')],
            'BEGIN DSA PRIVATE KEY' => ['dh', Lang::t('detail.dsa_key')],
        ];
        foreach ($map as $marker => [$algorithm, $detail]) {
            if (str_contains($content, $marker)) {
                $this->findings[] = new Finding($algorithm, Catalogue::PURPOSE_AUTHENTICITY, $rel, 1, $marker, Finding::CONFIDENCE_HIGH, false, $detail);
            }
        }

        if (str_contains($content, 'BEGIN CERTIFICATE') && \function_exists('openssl_x509_parse')) {
            $parsed = @openssl_x509_parse($content);
            if (\is_array($parsed)) {
                $sig = (string) ($parsed['signatureTypeSN'] ?? '');
                $algorithm = str_contains($sig, 'ECDSA') ? 'ecdsa' : 'rsa-sign';
                $this->findings[] = new Finding($algorithm, Catalogue::PURPOSE_AUTHENTICITY, $rel, 1, $sig, Finding::CONFIDENCE_HIGH, false, Lang::t('detail.x509'));
            }
        }

        foreach (['ssh-rsa' => 'rsa-sign', 'ecdsa-sha2-' => 'ecdsa', 'ssh-ed25519' => 'ed25519'] as $marker => $algorithm) {
            if (str_contains($content, $marker)) {
                $this->findings[] = new Finding($algorithm, Catalogue::PURPOSE_AUTHENTICITY, $rel, 1, $marker, Finding::CONFIDENCE_HIGH, false, Lang::t('detail.ssh_key'));
            }
        }
    }

    private function tlsConfig(string $content, string $rel): void
    {
        if (preg_match_all('/^\s*(ssl_protocols|ssl_ciphers|protocols|curves)\s+([^;\n{]+)/mi', $content, $m, \PREG_OFFSET_CAPTURE) === 0) {
            return;
        }
        foreach ($m[0] as $i => [$hit, $offset]) {
            $this->findings[] = new Finding(
                algorithm: 'ecdh',
                purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                file: $rel,
                line: $this->lineOf($content, $offset),
                evidence: trim($hit),
                confidence: Finding::CONFIDENCE_MEDIUM,
                detail: Lang::t('detail.tls_config'),
            );
        }
        $this->blindSpots[] = Lang::t('blind.tls_config', $rel);
    }

    private function composerLock(string $content, string $rel): void
    {
        $known = [
            'firebase/php-jwt' => ['rsa-sign', 'detail.pkg.jwt'],
            'lcobucci/jwt' => ['rsa-sign', 'detail.pkg.jwt'],
            'web-token/jwt-framework' => ['rsa-sign', 'detail.pkg.jose'],
            'phpseclib/phpseclib' => ['rsa', 'detail.pkg.phpseclib'],
            'paragonie/halite' => ['chacha20', 'detail.pkg.halite'],
            'defuse/php-encryption' => ['aes-256', 'detail.pkg.symmetric'],
            'web-auth/webauthn-lib' => ['ecdsa', 'detail.pkg.webauthn'],
            'spomky-labs/otphp' => ['sha1', 'detail.pkg.totp'],
        ];
        foreach ($known as $package => [$algorithm, $detail]) {
            $pos = strpos($content, '"'.$package.'"');
            if ($pos === false) {
                continue;
            }
            $this->findings[] = new Finding(
                algorithm: $algorithm,
                purpose: Catalogue::get($algorithm)['purpose'] ?? Catalogue::PURPOSE_UNKNOWN,
                file: $rel,
                line: $this->lineOf($content, $pos),
                evidence: $package,
                confidence: Finding::CONFIDENCE_MEDIUM,
                detail: Lang::t($detail).' '.Lang::t('detail.declared_dependency'),
                inventory: true,
            );
        }
    }
}
