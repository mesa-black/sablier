<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;

/** Cryptography called from PHP source. */
final class PhpDetector extends PatternDetector
{
    /**
     * Hints that a hash call is an identifier, not a security control.
     *
     * Read against the line and against the name of the enclosing function,
     * because the line is usually `return md5(` and says nothing. The list grew
     * from a measurement rather than from imagination: twenty public
     * repositories, eighty-nine findings called broken, eighty-two of them
     * identifiers, filenames, cache keys or object hash codes.
     */
    private const string NON_CRYPTO_HINT = '/cache|etag|identif|slug|gravatar|colou?r|filename|checksum_of_name|dedup|fingerprint'
        .'|hashcode|hash_code|uniquename|unique_name|classname|class_name|mockname|testdouble|mock|tmp[-_]|tmpfile|contenthash|content_hash|lock|mutex|reusable|recaller|timing|dynamic|\bname\b'
        .'|getname|indexedfile|filenameparts|calculatehash|is_really_writable|_get_lock|checksum/i';

    /**
     * …except where the word that would have cleared it is the subject itself.
     *
     * An SSH key fingerprint or a certificate fingerprint in MD5 *is* a
     * security control, and two of the seven real findings in that measurement
     * were exactly that. So "fingerprint" alone no longer buys silence.
     */
    private const string STILL_SECURITY = '/certificate|public_?key|host_?key|private_?key|signing_?key|key_?pair'
        .'|signature|csrf|xss|password|secret|nonce'
        // A bare "token" is as often a profiling marker as a credential, so it
        // has to say which: $token in a logger rescued a digest of a serialised
        // array back into the red.
        .'|access_?token|auth_?token|api_?token|session_?token|refresh_?token|bearer|credential/i';

    /**
     * What a digest is computed over, when that settles the question.
     *
     * `$key = md5($trendType . serialize($values))` is a cache key; `md5($dn)`
     * over a certificate is not. The argument names the subject, and on twenty
     * public repositories the subject was a document, a path or a version far
     * more often than a secret.
     */
    private const string IDENTITY_SUBJECT = '/md5\s*\(\s*\$?(this->)?\w*(content|data|reference|version|path|url|record|image|file|name|lines?)'
        .'|hash\s*\(\s*[\'"]\w+[\'"]\s*,\s*\$?(this->)?\w*(content|reference|version|path|url|file|name|json)'
        // A digest of a serialised structure identifies that structure. It is
        // an array key, a cache entry or a lock name, never a secret: you
        // cannot keep confidential something you just serialised to hash it.
        .'|(md5|sha1)\s*\(\s*(serialize|json_encode|var_export|print_r)\s*\('
        .'|\w*_?path\s*\(|define\s*\(\s*[\'"][A-Z_]*HASH/i';

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
            // RSA used directly, which is how most PHP code encrypts for a
            // recipient. Found missing when a fixture written to test something
            // else produced no finding at all.
            ['/openssl_(?:public_encrypt|private_decrypt)\s*\(/', 'rsa', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.openssl_rsa'],
            ['/openssl_(?:private_encrypt|public_decrypt)\s*\(/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.openssl_rsa_sign'],
            ['/openssl_sign\s*\(/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.openssl_sign'],
            ['/openssl_verify\s*\(/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.openssl_verify'],
            ['/sodium_crypto_box\w*\s*\(/', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.sodium_box'],
            ['/sodium_crypto_kx\w*\s*\(/', 'ecdh', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.sodium_kx'],
            ['/sodium_crypto_sign\w*\s*\(/', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, 'detail.sodium_sign'],
            ['/sodium_crypto_secretbox\w*\s*\(/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.sodium_secretbox'],
            ['/sodium_crypto_aead_\w+\s*\(/', 'chacha20', Catalogue::PURPOSE_CONFIDENTIALITY, ''],
            // A keyed digest and a bare one are two different primitives, so
            // they are two different rules: one pattern matching both produced
            // the finding twice, once correctly and once as broken.
            ['/\bhash_hmac\s*\(\s*[\'"]([a-z0-9\-]+)[\'"]/i', self::CAPTURE_HMAC, Catalogue::PURPOSE_INTEGRITY, 'detail.hmac_legacy'],
            ['/\bhash\s*\(\s*[\'"]([a-z0-9\-]+)[\'"]/i', self::CAPTURE, Catalogue::PURPOSE_INTEGRITY, ''],
            // A hand-rolled HMAC is still an HMAC: the inner and outer pads are
            // the construction, written out because the function was not there.
            ['/\b(?:md5|sha1)\s*\(\s*\$?\w*(?:k_)?[io]pad/i', 'hmac-md5', Catalogue::PURPOSE_INTEGRITY, 'detail.hmac_legacy'],
            ['/\bmd5\s*\(/', 'md5', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/\bsha1\s*\(/', 'sha1', Catalogue::PURPOSE_INTEGRITY, ''],
            // Listed so the report can say "leave this alone".
            ['/PASSWORD_BCRYPT|PASSWORD_DEFAULT/', 'bcrypt', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/PASSWORD_ARGON2\w*/', 'argon2', Catalogue::PURPOSE_INTEGRITY, ''],
            ['/[\'"](RS(?:256|384|512))[\'"]/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            ['/[\'"](PS(?:256|384|512))[\'"]/', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            ['/[\'"](ES(?:256|384|512))[\'"]/', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            ['/[\'"]EdDSA[\'"]/', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, 'detail.jwt'],
            // mcrypt with the cipher spelled out, and mcrypt without it. The
            // extension is dead either way, but naming DES when the code says
            // `mcrypt_module_open($cipher)` is inventing a fact: that call runs
            // whatever the caller asked for, AES included. Twenty-eight of the
            // eighty-two false positives measured on public code were this one
            // rule claiming DES about an API that only mentions mcrypt.
            ['/\bmcrypt_\w+\s*\(\s*(?:MCRYPT_)?[\'\"]?(3?des|rijndael[\w-]*|blowfish|cast[\w-]*|rc[24])[\'\"]?/i', self::CAPTURE, Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.mcrypt'],
            ['/\bmcrypt_(?:module_open|encrypt|decrypt|generic\w*|enc_\w+)\s*\(/', null, Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.mcrypt'],
        ];
    }

    /**
     * A table of algorithms a protocol requires, rather than a use of one.
     *
     * `'hmac-sha1', 'hmac-sha1-etm@openssh.com' => [new Hash('sha1'), 20]` is an
     * SSH client saying what the specification obliges it to understand. The
     * key names the algorithm, which is what separates it from a configuration
     * line like `'algorithm' => 'RS256'`, where the key names a setting and the
     * value is somebody's choice.
     */
    private const string CAPABILITY_ARM = '/^\s*(?:default|[\'"][\w.@+-]*(?:hmac|sha|md5|rsa|ecdsa|ecdh|dsa|aes|3?des|rc[24]|curve|ed25519|x25519|nistp|ssh-)[\w.@+-]*[\'"])'
        .'(?:\s*,\s*[\'"][\w.@+-]+[\'"])*\s*=>'
        // An arm wrapped over two lines puts the key above and the arrow below,
        // and a line that opens with `=>` is never anything else.
        .'|^\s*=>/i';

    protected function finding(SourceFile $file, int $offset, ?string $algorithm, string $purpose, string $detail): ?Finding
    {
        $finding = parent::finding($file, $offset, $algorithm, $purpose, $detail);
        if ($finding === null) {
            return null;
        }

        // Presence in a table is not a call site — the same rule the lock files
        // already get, and the reason their broken entries are reported as
        // something to confirm rather than something to fix tonight.
        if (preg_match(self::CAPABILITY_ARM, $file->lineTextAt($offset)) === 1) {
            return new Finding(
                $finding->algorithm, $finding->purpose, $finding->file, $finding->line,
                $finding->evidence, $finding->confidence, $finding->likelyNonCrypto,
                Lang::t('detail.capability_table'), inventory: true,
            );
        }

        if (!\in_array($algorithm, self::HASHES, true)) {
            return $finding;
        }

        // A digest used as an identifier, or one living in test code, is not a
        // security control. Saying so is what keeps three real findings from
        // drowning under forty false ones.
        $line = $file->lineTextAt($offset);
        $function = $file->functionAt($offset);
        $context = $line.' '.$function;

        // Inside an HMAC, a bare digest is half of a construction the collision
        // attacks do not reach. PHPMailer writes one by hand, and both of its
        // inner calls were reported as broken on their own.
        if ($function === 'hmac' || preg_match('/[io]pad/i', $line) === 1) {
            return null;
        }

        $isNoise = $file->isTestCode()
            || ((preg_match(self::NON_CRYPTO_HINT, $context) === 1
                || preg_match(self::IDENTITY_SUBJECT, $line) === 1
                // A digest assigned to something called a key, an id or a name
                // is a lookup, unless the line says otherwise. Key derivation
                // names its subject — a password, a secret — and is rescued by
                // the list below.
                || preg_match('/\$(cache_?)?(key|id|name|hash)\b\s*=/i', $line) === 1)
                && preg_match(self::STILL_SECURITY, $context) !== 1);

        return $isNoise
            ? new Finding($finding->algorithm, $finding->purpose, $finding->file, $finding->line,
                $finding->evidence, $finding->confidence, true, $finding->detail)
            : $finding;
    }
}
