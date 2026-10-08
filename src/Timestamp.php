<?php

declare(strict_types=1);

namespace Sablier;

/**
 * A date somebody else attests, because ours is worth nothing.
 *
 * Every signature in this tool proves two things and not a third: which key
 * signed, and which findings it signed. The `signed_at` field is covered by the
 * signature, so it cannot be edited afterwards — but it comes from the clock of
 * the machine that signed, which is ours. Backdating a report is therefore
 * trivial, and the chain of `previous` digests does not help: the same key holds
 * every link, so the whole chain can be rebuilt in order and will verify
 * perfectly. Our seals answer *who* and *what*. Nothing in them answers *when*.
 *
 * A timestamping authority answers it in one request: it is handed a digest,
 * never the document, and returns a signed token saying that this digest was
 * presented to it at this instant. It has no stake in our conclusions, which is
 * the entire point.
 *
 * Three decisions shape what is here.
 *
 * - **The digest is what gets attested**, not the signature and not the file.
 *   It is printed in the report, so anybody holding the document can rebuild
 *   the query by hand — `openssl ts -verify -digest <the printed value>` takes
 *   a hex digest directly, with no file to canonicalise and no field order to
 *   agree on. It also survives an ephemeral key: the key is destroyed, the
 *   attested date is not.
 * - **The token is a file of its own**, raw DER beside the `.sig`, because the
 *   stock `openssl ts` command reads exactly that. A reader verifies the date
 *   without this tool, which is the same reason the signature is a readable
 *   JSON file rather than something only we can open.
 * - **No default authority.** Who attests your dates is a decision, like the
 *   regime and the lifetimes — and a default would quietly make that choice for
 *   every user, in a jurisdiction they did not pick. `--timestamp=<url>` takes
 *   the URL or does nothing.
 *
 * The limit, said here rather than discovered later: a timestamping authority
 * signs with RSA or ECDSA, which this tool's own catalogue classes as quantum
 * vulnerable. A token is evidence for a dispute in the next few years, not for
 * 2040. Keeping it past that means re-attesting it while the scheme still holds,
 * and the report says so next to the date.
 */
final class Timestamp
{
    /**
     * How many authorities a document can carry.
     *
     * Not a technical limit — nothing in RFC 3161 caps it — but a bound on the
     * discovery loop, and a statement that corroboration is a handful of
     * independent jurisdictions rather than a collection.
     */
    private const SLOTS = 8;

    /** Long enough for a loaded authority, short enough that a build does not hang on one. */
    private const int TIMEOUT = 20;

    /** Where a token is filed, beside the signature it dates. */
    /**
     * Where the token of the nth authority is written.
     *
     * One slot per authority, in the order they were named, and the first keeps
     * the plain `.tsr` name: it is the one every command in the documentation
     * and in the report itself points at, and the one a reader who corroborates
     * nothing still finds. The slot is stable across runs, which is what makes
     * the keep-the-earliest rule work per authority — an authority that was
     * unreachable on one run does not push the others down a slot and lose
     * their antecedence.
     */
    public static function path(string $reportPath, int $slot = 0): string
    {
        return $reportPath.($slot === 0 ? '' : '.'.($slot + 1)).'.tsr';
    }

    /**
     * Every token sitting beside a report, in slot order.
     *
     * Discovery rather than a flag, for the reason the chain is discovered too:
     * an artefact that has to be asked for is an artefact nobody checks. A
     * reader who was handed three tokens and knows to look for one would verify
     * one third of what they hold.
     *
     * @return list<string>
     */
    public static function paths(string $reportPath): array
    {
        $found = [];
        for ($slot = 0; $slot < self::SLOTS; ++$slot) {
            $path = self::path($reportPath, $slot);
            if (is_file($path)) {
                $found[] = $path;
            }
        }

        return $found;
    }

    /**
     * Ask an authority to attest a digest.
     *
     * @return array{token:string}|array{error:string, detail:string}
     */
    public static function request(string $digestHex, string $url): array
    {
        $binary = self::binary();
        if ($binary === null) {
            return ['error' => 'timestamp.no_openssl', 'detail' => ''];
        }
        if (preg_match('/^[0-9a-f]{64}$/i', $digestHex) !== 1) {
            return ['error' => 'timestamp.bad_digest', 'detail' => $digestHex];
        }
        if (preg_match('#^https?://#i', $url) !== 1) {
            return ['error' => 'timestamp.bad_url', 'detail' => $url];
        }

        // -cert asks the authority to put its certificate inside the token.
        // Without it the token is unverifiable by anybody who does not already
        // hold that certificate, which defeats the purpose of a file a third
        // party is meant to check on their own.
        $queryPath = self::temporary();
        @shell_exec(\sprintf(
            '%s ts -query -digest %s -sha256 -cert -out %s 2>/dev/null',
            escapeshellarg($binary), escapeshellarg(strtolower($digestHex)), escapeshellarg($queryPath),
        ));
        $query = (string) @file_get_contents($queryPath);
        @unlink($queryPath);
        if ($query === '') {
            return ['error' => 'timestamp.query_failed', 'detail' => ''];
        }

        $response = @file_get_contents($url, false, stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/timestamp-query\r\nContent-Length: ".\strlen($query)."\r\n",
                'content' => $query,
                'timeout' => self::TIMEOUT,
                // The body of a refusal says why; an exception would throw it away.
                'ignore_errors' => true,
            ],
        ]));
        if ($response === false || $response === '') {
            return ['error' => 'timestamp.unreachable', 'detail' => $url];
        }

        // A reply is granted or refused, and a refused one is still a valid DER
        // structure — so the status is read rather than the length.
        $read = self::read($response);
        if ($read === null) {
            return ['error' => 'timestamp.refused', 'detail' => $url];
        }

        return ['token' => $response];
    }

    /**
     * What a token says, before anybody decides whether to believe it.
     *
     * Reading and verifying are separate on purpose: a report must be able to
     * print the attested date on a machine that cannot check the chain, and
     * printing it with the words "not verified here" beats printing nothing.
     *
     * @return array{time:string, authority:string, algorithm:string, serial:string, imprint:string}|null
     */
    public static function read(string $token): ?array
    {
        $binary = self::binary();
        if ($binary === null || $token === '') {
            return null;
        }

        $path = self::temporary();
        file_put_contents($path, $token);
        $text = (string) @shell_exec(\sprintf(
            '%s ts -reply -in %s -text 2>/dev/null',
            escapeshellarg($binary), escapeshellarg($path),
        ));
        @unlink($path);

        if (preg_match('/^Time stamp:\s*(.+)$/m', $text, $time) !== 1) {
            return null;
        }

        preg_match('/^Serial number:\s*(.+)$/m', $text, $serial);
        $signer = self::signer($token);

        return [
            'time' => trim($time[1]),
            // Read off the certificate that signed, not off the token's own TSA
            // field: that field is optional and a major authority leaves it
            // empty, so a report built on it says "unspecified" about a
            // certificate that names its holder on the next line.
            'authority' => $signer['organisation'],
            // The scheme the attestation itself rests on, because this tool
            // spends every other page saying that schemes expire. A token signed
            // with RSA-4096 is evidence for a dispute in the next few years, and
            // the report prints that rather than implying a date holds forever.
            'algorithm' => $signer['algorithm'],
            'serial' => trim($serial[1] ?? ''),
            // The digest the token actually covers, lifted out of the hex dump
            // openssl prints. Needed because a chain that cannot be built stops
            // `ts -verify` before it ever compares the imprint: without this,
            // "the chain is unverified" and "this token is about another
            // document" came back as the same answer.
            'imprint' => self::imprint($text),
        ];
    }

    /**
     * The certificates in a `pkcs7 -print_certs` dump, each with its own PEM.
     *
     * @return list<array{subject:string, issuer:string, pem:string}>
     */
    private static function certificates(string $pems): array
    {
        // `[^\n]*` and `[\s\S]*?` rather than `.` with /s: a dot that matches
        // newlines made the first subject swallow the whole dump, so the parse
        // returned one certificate instead of two and the "leaf" was whichever
        // one survived. Caught by comparing the algorithm this prints against
        // the certificates in the token, which disagreed.
        $pattern = '/^subject=(?<subject>[^\n]*)\n\s*issuer=(?<issuer>[^\n]*)\n\s*(?<pem>-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)/m';
        if (preg_match_all($pattern, $pems, $matches, \PREG_SET_ORDER) === 0) {
            return [];
        }

        return array_map(static fn (array $m): array => [
            'subject' => trim($m['subject']),
            'issuer' => trim($m['issuer']),
            'pem' => $m['pem'],
        ], $matches);
    }

    /**
     * A token's date written the way every other date in these documents is.
     *
     * The zone is kept and named: an authority answers in UTC, the reader is
     * somewhere else, and silently converting an attested instant to a local
     * clock would make two copies of the same document disagree.
     */
    public static function readable(string $time): string
    {
        try {
            return (new \DateTimeImmutable($time))->setTimezone(new \DateTimeZone('UTC'))->format('d/m/Y H:i').' UTC';
        } catch (\Exception) {
            return $time;
        }
    }

    /** The message imprint out of openssl's hex dump. */
    private static function imprint(string $replyText): string
    {
        if (preg_match('/^Message data:\n((?:\s+[0-9a-f]{4} - .+\n)+)/mi', $replyText, $m) !== 1) {
            return '';
        }

        $hex = '';
        foreach (explode("\n", trim($m[1])) as $line) {
            // Each line is "    0000 - aa bb cc dd-ee …   ascii". The offset and
            // the ASCII column both have to go before the bytes are readable.
            if (preg_match('/^\s*[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]){1,16})/i', $line, $bytes) === 1) {
                $hex .= strtolower((string) preg_replace('/[^0-9a-f]/i', '', $bytes[1]));
            }
        }

        return $hex;
    }

    /**
     * Who signed the token, and with what.
     *
     * A timestamp token is a CMS structure carrying the responder's certificate,
     * which is the only self-contained statement of who vouched.
     *
     * @return array{organisation:string, algorithm:string}
     */
    private static function signer(string $token): array
    {
        $binary = self::binary();
        if ($binary === null) {
            return ['organisation' => '', 'algorithm' => ''];
        }

        $reply = self::temporary();
        $inner = self::temporary();
        file_put_contents($reply, $token);
        @shell_exec(\sprintf(
            '%s ts -reply -in %s -token_out -out %s 2>/dev/null',
            escapeshellarg($binary), escapeshellarg($reply), escapeshellarg($inner),
        ));
        $pems = (string) @shell_exec(\sprintf(
            '%s pkcs7 -inform DER -in %s -print_certs 2>/dev/null',
            escapeshellarg($binary), escapeshellarg($inner),
        ));

        // The leaf, not simply the first one printed. A CMS structure carries
        // the responder's certificate *and* the intermediates that chain it, in
        // whatever order they were put there — and the first one happened to be
        // the responder for every authority tested, which is a coincidence to
        // rely on rather than a rule. The leaf is the certificate that issued
        // none of the others.
        $certificates = self::certificates($pems);
        $issuers = array_column($certificates, 'issuer');
        $leaf = null;
        foreach ($certificates as $certificate) {
            if (!\in_array($certificate['subject'], $issuers, true)) {
                $leaf = $certificate;
                break;
            }
        }
        $leaf ??= $certificates[0] ?? null;

        $organisation = '';
        if ($leaf !== null && preg_match('/\bO\s*=\s*([^,\n]+)/', $leaf['subject'], $m) === 1) {
            $organisation = trim($m[1]);
        }

        $algorithm = '';
        if ($leaf !== null) {
            $certPath = self::temporary();
            file_put_contents($certPath, $leaf['pem']."\n");
            $text = (string) @shell_exec(\sprintf(
                '%s x509 -in %s -noout -text 2>/dev/null',
                escapeshellarg($binary), escapeshellarg($certPath),
            ));
            @unlink($certPath);
            preg_match('/Public Key Algorithm:\s*(\S+)/', $text, $kind);
            preg_match('/Public-Key:\s*\((\d+) bit\)/', $text, $bits);
            $algorithm = match (strtolower($kind[1] ?? '')) {
                'rsaencryption' => 'RSA',
                'id-ecpublickey' => 'ECDSA',
                default => $kind[1] ?? '',
            };
            if ($algorithm !== '' && isset($bits[1])) {
                $algorithm .= '-'.$bits[1];
            }
        }

        @unlink($reply);
        @unlink($inner);

        return ['organisation' => $organisation, 'algorithm' => $algorithm];
    }

    /**
     * Whether the token holds, for this digest, against a trust store.
     *
     * Four states, because collapsing them lies. `valid`: the authority's
     * signature holds and it attests this digest. `invalid`: it does not —
     * either the token covers something else or it was tampered with. `untrusted`:
     * the token is well formed and this machine cannot build a chain to a root
     * it trusts, which is what a self-signed authority or a missing intermediate
     * looks like, and is not a forgery. `unchecked`: there is no openssl, or no
     * trust store to check against.
     *
     * The distinction matters most for an old token: a responder certificate
     * expires long before the date it attested stops being interesting, and
     * reporting that as `invalid` would retire a perfectly good attestation.
     *
     * @return array{state:string, detail:string}
     */
    public static function verify(string $token, string $digestHex, string $caFile = ''): array
    {
        $binary = self::binary();
        if ($binary === null || $token === '') {
            return ['state' => 'unchecked', 'detail' => ''];
        }

        // Before any question of trust: does this token even talk about this
        // document? A hash comparison needs no certificate, and answering it
        // first means an honest "the chain is unverified" can never cover a
        // token that attests something else entirely.
        $read = self::read($token);
        if ($read === null) {
            return ['state' => 'invalid', 'detail' => ''];
        }
        if ($read['imprint'] !== '' && !hash_equals($read['imprint'], strtolower($digestHex))) {
            return ['state' => 'invalid', 'detail' => 'imprint'];
        }

        $trust = $caFile !== '' ? ['-CAfile', $caFile] : self::systemTrust();
        if ($trust === []) {
            return ['state' => 'unchecked', 'detail' => ''];
        }
        if ($trust[0] === '-CAfile' && !is_file($trust[1])) {
            return ['state' => 'unchecked', 'detail' => $trust[1]];
        }

        $path = self::temporary();
        file_put_contents($path, $token);
        $output = (string) @shell_exec(\sprintf(
            '%s ts -verify -digest %s -in %s %s %s 2>&1',
            escapeshellarg($binary), escapeshellarg(strtolower($digestHex)), escapeshellarg($path),
            $trust[0], escapeshellarg($trust[1]),
        ));
        @unlink($path);

        if (str_contains($output, 'Verification: OK')) {
            return ['state' => 'valid', 'detail' => ''];
        }

        // openssl's own words, trimmed to the first line that explains
        // something. A reader who is told only "failed" cannot tell a missing
        // intermediate certificate from a token that does not match.
        if (preg_match('/Verify error:\s*(.+)/', $output, $why) === 1) {
            $reason = trim($why[1]);
            $trust = ['self-signed', 'self signed', 'local issuer', 'has expired', 'not yet valid', 'unable to verify'];
            foreach ($trust as $needle) {
                if (str_contains(strtolower($reason), $needle)) {
                    return ['state' => 'untrusted', 'detail' => $reason];
                }
            }

            return ['state' => 'invalid', 'detail' => $reason];
        }

        $detail = '';
        foreach (explode("\n", $output) as $line) {
            $line = trim($line);
            // "Using configuration from …" is printed on every run, success
            // included: taking the first line reported that as the reason a
            // token failed, which is the kind of plausible noise somebody acts
            // on for an hour.
            if ($line !== '' && !str_starts_with($line, 'Using configuration')
                && !str_starts_with($line, 'Verification:') && !str_contains($line, 'ts: ')) {
                $detail = $line;
                break;
            }
        }

        return ['state' => 'invalid', 'detail' => $detail];
    }

    /**
     * The trust store openssl itself was built with.
     *
     * Not a bundle shipped in this repository: a list of root certificates
     * vendored by a tool like this one would go stale and nobody would notice,
     * and the machine already has one that its own updates keep current.
     *
     * @return array{0:string, 1:string}|array{}
     */
    private static function systemTrust(): array
    {
        $binary = self::binary();
        if ($binary === null) {
            return [];
        }

        $dir = trim((string) @shell_exec(escapeshellarg($binary).' version -d 2>/dev/null'));
        if (preg_match('/"(.+)"/', $dir, $m) !== 1) {
            return [];
        }

        // The bundle before the directory: `-CApath` needs the hashed symlinks
        // `c_rehash` creates, and a package manager that ships the directory
        // without them makes every token look forged. Measured on this laptop:
        // -CApath FAILED, -CAfile OK, same certificates.
        if (is_file($m[1].'/cert.pem')) {
            return ['-CAfile', $m[1].'/cert.pem'];
        }

        return is_dir($m[1].'/certs') ? ['-CApath', $m[1].'/certs'] : [];
    }

    private static function binary(): ?string
    {
        $path = trim((string) @shell_exec('command -v openssl 2>/dev/null'));

        return $path !== '' ? $path : null;
    }

    private static function temporary(): string
    {
        return sys_get_temp_dir().'/sablier-ts-'.bin2hex(random_bytes(6));
    }
}
