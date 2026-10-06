<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;
use Sablier\Value;

/**
 * Cryptography declared in a framework's YAML, which until now nothing read.
 *
 * Every other configuration detector here reads PHP, because Laravel, CakePHP
 * and Laminas put their configuration in PHP arrays. Symfony does not: its
 * password hashers, its login flows and the signature algorithms behind its
 * tokens live in `config/packages/*.yaml`, and a tool that only opens `.php`
 * files walks past the whole security configuration of the most widely deployed
 * PHP framework in Europe.
 *
 * What makes this worth a detector of its own rather than a few more patterns:
 * these are **declared algorithms**, not call sites. Nobody writes `RS256` in a
 * controller; they write it once in a firewall and every login uses it for the
 * next five years. That is the clearest possible input for this tool, and the
 * hardest to find by reading code.
 *
 * Three rules keep it from inventing findings.
 *
 * - **The value decides, not the key.** `algorithm:` appears in a dozen
 *   unrelated places in a Symfony configuration, so a pattern matches only when
 *   the value is a hasher or a JOSE algorithm this tool recognises. A key with
 *   an unknown value produces nothing rather than a guess.
 * - **A value that comes from the environment is a question, not an answer.**
 *   `algorithm: '%env(JWT_ALGO)%'` says the algorithm is decided outside the
 *   repository — which is exactly the case this tool exists to surface, so it is
 *   reported as undetermined and lands in "to declare".
 * - **It stays in its lane.** `verify_peer: false` under `http_client` is a real
 *   defect and is deliberately not reported here: it is a problem of today's
 *   authentication, not of when a cipher stops holding, and a tool that starts
 *   reporting every security smell loses the right to be believed about 2035.
 *
 * It reads the text rather than parsing YAML, for the same reason the rest of
 * this tool reads text: no dependency, and a file that does not parse is still
 * read. The cost is in `blindSpots()`, not hidden.
 */
final class FrameworkYamlDetector implements DetectorInterface
{
    /**
     * Symfony's password hashers, and what each one actually computes.
     *
     * `auto` and `native` resolve at runtime to argon2id when libsodium is there
     * and bcrypt otherwise. They are recorded rather than skipped — an inventory
     * that says nothing about how a project stores its passwords has a hole
     * where its most-asked question should be — but at medium confidence, which
     * is this tool's word for "read from something other than a literal". Both
     * outcomes are CLEAR, so the entry cannot mislead whichever way it resolves.
     */
    private const array HASHERS = [
        'auto' => 'argon2',
        'native' => 'argon2',
        'bcrypt' => 'bcrypt',
        'argon2i' => 'argon2',
        'argon2id' => 'argon2',
        'sodium' => 'argon2',
        'pbkdf2' => 'sha512',
        'plaintext' => 'plaintext',
        'md5' => 'md5',
        'sha1' => 'sha1',
        'sha256' => 'sha256',
        'sha512' => 'sha512',
    ];

    public function supports(SourceFile $file): bool
    {
        // Under a configuration directory, which is where a framework puts the
        // files this reads. A docker-compose at the root of a repository is
        // somebody else's business, and the shell detector already has it.
        return $file->hasExtension('yaml', 'yml')
            && (str_contains($file->relativePath, 'config/') || str_contains($file->relativePath, 'Config/'));
    }

    public function blindSpots(): array
    {
        return [Lang::t('blind.yaml')];
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();

        yield from $this->hashers($file, $content);
        yield from $this->joseAlgorithms($file, $content);
        yield from $this->oidcLogin($file, $content);
        yield from $this->databaseTransport($file, $content);
    }

    /**
     * How passwords are stored, which is the one line of a Symfony
     * configuration a reader of the report always wants to see.
     *
     * @return iterable<Finding>
     */
    private function hashers(SourceFile $file, string $content): iterable
    {
        // Two patterns, because all three shapes in the documentation and in the
        // wild have to be read: the explicit key on its own line, the same key
        // inside an inline mapping with a cost beside it, and the shorthand
        // where the user class points straight at a hasher name. The first
        // version read only the first shape and found nothing in the real
        // application it was tried on — which uses the shorthand.
        //
        // The class-name character set needs a doubled backslash to survive
        // PHP's single quotes and reach PCRE as one: with a single one, the
        // character class ended at an escaped bracket and matched nothing at
        // all, silently.
        $patterns = ['/\balgorithm:[ \t]*[\'"]?([A-Za-z0-9_]+)[\'"]?/'];

        // The shorthand — `App\Entity\User: bcrypt` — is read only in a file
        // that declares hashers at all, and only when the key is shaped like a
        // class name. Without both guards it matched `cookie_secure: auto` in a
        // real application's framework.yaml and reported a password hasher that
        // does not exist: `auto` is an ordinary YAML value, and a pattern whose
        // only context is its value will eventually meet that value elsewhere.
        if (preg_match('/^\s*(?:password_hashers|encoders):/m', $content) === 1) {
            $patterns[] = '/^[ \t]*(?:[A-Za-z0-9_]+\\\\[A-Za-z0-9_\\\\]+|[A-Z][A-Za-z0-9_]*):[ \t]*[\'"]?([A-Za-z0-9_]+)[\'"]?[ \t]*$/m';
        }

        $matches = [[], []];
        foreach ($patterns as $pattern) {
            if (preg_match_all($pattern, $content, $found, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }
            $matches[0] = [...$matches[0], ...$found[0]];
            $matches[1] = [...$matches[1], ...$found[1]];
        }
        if ($matches[1] === []) {
            return;
        }

        // The shorthand and the explicit key can both match one line; the
        // finding is the same fact either way, so it is emitted once.
        $seen = [];
        foreach ($matches[1] as $index => [$value, $_]) {
            $named = strtolower(Value::string($value));
            $algorithm = self::HASHERS[$named] ?? null;
            if ($algorithm === null) {
                continue;
            }

            $offset = Value::int($matches[0][$index][1]);
            $line = $file->lineAt($offset);
            if (isset($seen[$line])) {
                continue;
            }
            $seen[$line] = true;

            yield new Finding(
                algorithm: $algorithm,
                purpose: $algorithm === 'plaintext' ? Catalogue::PURPOSE_CONFIDENTIALITY : Catalogue::PURPOSE_INTEGRITY,
                file: $file->relativePath,
                line: $line,
                evidence: trim(Value::string($matches[0][$index][0])),
                confidence: \in_array($named, ['auto', 'native'], true)
                    ? Finding::CONFIDENCE_MEDIUM
                    : Finding::CONFIDENCE_HIGH,
                detail: Lang::t(match (true) {
                    $algorithm === 'plaintext' => 'detail.yaml.hasher_plain',
                    \in_array($named, ['auto', 'native'], true) => 'detail.yaml.hasher_auto',
                    default => 'detail.yaml.hasher',
                }),
            );
        }
    }

    /**
     * The signature algorithms behind tokens: OIDC token handlers, LexikJWT, and
     * anything else that names a JOSE algorithm in a configuration key.
     *
     * Both shapes are read — `algorithms: ['RS256', 'ES256']` on one line, and a
     * block list underneath — because the first is what the documentation shows
     * and the second is what people write.
     *
     * @return iterable<Finding>
     */
    private function joseAlgorithms(SourceFile $file, string $content): iterable
    {
        $pattern = '/^(?<indent>[ \t]*)(?<key>[a-z_]*algorithms?):(?<inline>[^\n]*)\n(?<block>(?:[ \t]*[-#][^\n]*\n)*)/mi';
        if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE | \PREG_SET_ORDER) === 0) {
            return;
        }

        foreach ($matches as $match) {
            $value = Value::string($match['inline'][0]).' '.Value::string($match['block'][0] ?? '');
            $offset = Value::int($match[0][1]);
            $line = $file->lineAt($offset);
            $evidence = trim(Value::string($match['key'][0]).':'.Value::string($match['inline'][0]));

            // An algorithm decided outside the repository is the finding, not a
            // gap in this detector: the report asks for it to be declared.
            if (preg_match('/%env\(|\$\{|%[a-z_.]+%/i', $value) === 1) {
                yield new Finding(
                    algorithm: 'undetermined',
                    purpose: Catalogue::PURPOSE_UNKNOWN,
                    file: $file->relativePath,
                    line: $line,
                    evidence: $evidence,
                    confidence: Finding::CONFIDENCE_MEDIUM,
                    detail: Lang::t('detail.yaml.algorithm_from_env'),
                );

                continue;
            }

            $seen = [];
            foreach (self::joseTokens($value) as $token) {
                $algorithm = Catalogue::fromJose($token);
                if ($algorithm === null || isset($seen[$algorithm])) {
                    continue;
                }
                $seen[$algorithm] = true;

                yield new Finding(
                    algorithm: $algorithm,
                    purpose: Catalogue::get($algorithm)['purpose'] ?? Catalogue::PURPOSE_UNKNOWN,
                    file: $file->relativePath,
                    line: $line,
                    // The JOSE name, which is what the file says and what the
                    // person who wrote it will search for.
                    evidence: $token,
                    detail: Lang::t('detail.yaml.jose'),
                );
            }
        }
    }

    /**
     * A login delegated to an identity provider.
     *
     * The firewall names the provider, never the signature: the algorithm comes
     * from the provider's published keys, so it is not in this repository and
     * cannot be. That is the thesis of this tool stated by somebody else's
     * configuration format — the whole login path rests on a signature nobody
     * here chose — so it is reported as undetermined and asks to be declared.
     *
     * @return iterable<Finding>
     */
    private function oidcLogin(SourceFile $file, string $content): iterable
    {
        if (preg_match('/^\s*oidc_login:\s*$/m', $content, $m, \PREG_OFFSET_CAPTURE) !== 1) {
            return;
        }

        yield new Finding(
            algorithm: 'undetermined',
            purpose: Catalogue::PURPOSE_AUTHENTICITY,
            file: $file->relativePath,
            line: $file->lineAt(Value::int($m[0][1])),
            evidence: 'oidc_login',
            confidence: Finding::CONFIDENCE_MEDIUM,
            detail: Lang::t('detail.yaml.oidc_login'),
        );
    }

    /**
     * Whether the database connection is encrypted, said in the connection
     * string rather than in code.
     *
     * @return iterable<Finding>
     */
    private function databaseTransport(SourceFile $file, string $content): iterable
    {
        $rules = [
            ['/sslmode=(disable|allow)/i', 'plaintext', 'detail.yaml.db_plain'],
            ['/sslmode=(require|verify-ca|verify-full|prefer)/i', 'ecdh', 'detail.yaml.db_tls'],
            ['/MYSQL_ATTR_SSL_(?:CA|CERT|KEY)|ssl_ca:/i', 'ecdh', 'detail.yaml.db_tls'],
        ];

        foreach ($rules as [$pattern, $algorithm, $detail]) {
            if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }

            foreach ($matches[0] as [$hit, $offset]) {
                yield new Finding(
                    algorithm: $algorithm,
                    purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                    file: $file->relativePath,
                    line: $file->lineAt(Value::int($offset)),
                    evidence: trim(Value::string($hit)),
                    detail: Lang::t($detail),
                );
            }
        }
    }

    /**
     * The JOSE names inside a scalar or a list.
     *
     * @return list<string>
     */
    private static function joseTokens(string $value): array
    {
        if (preg_match_all('/\b(HS|RS|PS|ES)(256|384|512)\b|\bEdDSA\b/i', $value, $found) === 0) {
            return [];
        }

        return array_values(array_unique($found[0]));
    }
}
