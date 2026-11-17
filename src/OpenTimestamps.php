<?php

declare(strict_types=1);

namespace Sablier;

use Sablier\Ots\BlockHeader;
use Sablier\Ots\Calendar;
use Sablier\Ots\FormatError;
use Sablier\Ots\Node;
use Sablier\Ots\Proof;

/**
 * A date nobody has to be believed about.
 *
 * The RFC 3161 tokens in Timestamp answer *when* with somebody's word: an
 * authority signs that it saw a digest at an instant, and the reader trusts
 * that authority, its clock, and the RSA or ECDSA key it signs with — which
 * this tool's own catalogue classes as quantum vulnerable. Decided on
 * 2026-11-17 (docs/scoping.md, item 2) to add a second kind of evidence that
 * asks for none of that.
 *
 * An OpenTimestamps proof is a path of hash operations from the signed findings
 * digest to the merkle root of a Bitcoin block. Checking it means recomputing
 * those hashes and comparing the result with 32 bytes of a block header that
 * thousands of independent machines hold. No signature, no certificate, no
 * authority: the official client checks it with `ots verify -d <digest>`, and
 * this tool checks it in `sablier verify`, by arithmetic in both cases.
 *
 * Four decisions shape what is here.
 *
 * - **What is anchored is the digest Timestamp attests**, the one printed in the
 *   report, so both kinds of evidence talk about the same thing and a reader
 *   checks either without this tool.
 * - **One file, every calendar in it.** Each calendar's answer is a branch under
 *   the same root, as the official client writes it, so `<report>.ots` is the
 *   file a reader passes to `ots` and there is no slot numbering to learn.
 * - **A default exists, unlike for --timestamp.** `--anchor=opentimestamps`
 *   uses the public calendars the official client uses. An RFC 3161 authority
 *   *is* the evidence, so choosing one is choosing whom to believe, and this
 *   tool will not make that choice for anybody. A calendar is not the
 *   evidence: it aggregates digests and pays for a Bitcoin transaction, and
 *   the proof it hands back verifies without it, against the chain. It cannot
 *   lie about a date — a wrong path does not reach a real block — and at worst
 *   it fails to anchor, which is loud and costs nothing but the attempt.
 * - **The oldest anchoring is kept.** As with the tokens: the claim worth making
 *   is that these findings existed *no later than* some block, so a proof that
 *   already covers this digest is upgraded in place, never replaced.
 *
 * The limits, said here rather than discovered later. It proves *when*, no
 * later than the block, and nothing about *who*: that remains the signature's
 * job. It is not immediate: a calendar puts its digests in a transaction every
 * few hours, and until that transaction is in a block the proof is pending
 * and only says which calendars to ask. And against a quantum computer, the
 * proof itself is SHA-256 (sometimes RIPEMD-160) and nothing else, which
 * Grover's algorithm weakens without breaking; whether the Bitcoin chain keeps
 * its consensus through that transition is outside what the proof can say.
 */
final class OpenTimestamps
{
    /** The word `--anchor` accepts for "the public calendars". */
    public const string KEYWORD = 'opentimestamps';

    /**
     * The calendars the official client submits to when given none, read from
     * otsclient/cmds.py on 2026-11-17. They are aggregators run by three
     * different operators; each forwards to its calendar, which is what the
     * pending attestation names and what an upgrade asks.
     */
    public const array CALENDARS = [
        'https://a.pool.opentimestamps.org',
        'https://b.pool.opentimestamps.org',
        'https://a.pool.eternitywall.com',
        'https://ots.btc.catallaxy.com',
    ];

    /**
     * Which calendars a pending attestation may send this tool to, from
     * python-opentimestamps calendar.py (DEFAULT_CALENDAR_WHITELIST).
     *
     * A pending attestation is a URL written by whoever produced the file, and
     * `verify` reads files that came from anywhere. Following any URL in it
     * would let a proof make this machine fetch an address of its author's
     * choosing — so only these, and the calendars named on the command line.
     */
    private const array TRUSTED = ['*.calendar.opentimestamps.org', '*.calendar.eternitywall.com', '*.calendar.catallaxy.com'];

    /** Beside the report, like the `.sig` and the `.tsr`: the name every `ots` command in the report uses. */
    public static function path(string $reportPath): string
    {
        return $reportPath.'.ots';
    }

    /**
     * The calendars to submit to, with the keyword expanded.
     *
     * @param list<string> $asked
     *
     * @return list<string>
     */
    public static function calendars(array $asked): array
    {
        $out = [];
        foreach ($asked as $calendar) {
            foreach ($calendar === self::KEYWORD ? self::CALENDARS : [$calendar] as $url) {
                $url = rtrim($url, '/');
                if (!\in_array($url, $out, true)) {
                    $out[] = $url;
                }
            }
        }

        return $out;
    }

    /**
     * Submit a digest to every calendar and merge what comes back.
     *
     * What the calendars receive is not the digest itself but the hash of the
     * digest followed by sixteen random bytes, as the official client does.
     * The digest is printed in a report that may be public; sent bare, it would
     * let a calendar's logs tie that report to the address that submitted it.
     * The nonce is in the proof, so nothing is lost for the reader.
     *
     * @param list<string> $calendars
     *
     * @return array{proof:?Proof, reached:list<string>, errors:list<array{error:string, detail:string}>}
     */
    public static function stamp(string $digestHex, array $calendars): array
    {
        $digest = preg_match('/^[0-9a-f]{64}$/i', $digestHex) === 1 ? (string) hex2bin($digestHex) : '';
        if ($digest === '') {
            return ['proof' => null, 'reached' => [], 'errors' => [['error' => 'anchor.bad_digest', 'detail' => $digestHex]]];
        }

        $nonce = random_bytes(16);
        $tip = hash('sha256', $digest.$nonce, true);
        $branches = new Node();
        $reached = [];
        $errors = [];
        foreach ($calendars as $calendar) {
            if (preg_match('#^https?://[^/?\#@\s]+(/[^?\#\s]*)?$#i', $calendar) !== 1) {
                $errors[] = ['error' => 'anchor.bad_url', 'detail' => $calendar];
                continue;
            }
            $answer = Calendar::submit($calendar, $tip);
            if (isset($answer['node'])) {
                $branches->merge($answer['node']);
                $reached[] = $calendar;
            } else {
                // Loud, and the other calendars are still asked: one operator's
                // bad day is the reason there are several.
                $errors[] = $answer;
            }
        }
        if ($reached === []) {
            return ['proof' => null, 'reached' => [], 'errors' => $errors];
        }

        $hashed = new Node();
        $hashed->ops[] = ['op' => Node::SHA256, 'arg' => '', 'node' => $branches];
        $root = new Node();
        $root->ops[] = ['op' => Node::APPEND, 'arg' => $nonce, 'node' => $hashed];

        return ['proof' => new Proof($digest, $root), 'reached' => $reached, 'errors' => $errors];
    }

    /**
     * Read a proof from disk, or say why not.
     *
     * @return array{proof:Proof}|array{error:string, detail:string}
     */
    public static function load(string $path): array
    {
        try {
            $proof = Proof::parse((string) file_get_contents($path));
            // Walked once here so a proof whose operations cannot be applied is
            // refused when it is read, not halfway through a verification.
            $proof->attestations();
        } catch (FormatError $e) {
            return ['error' => 'anchor.unreadable', 'detail' => $path.': '.$e->getMessage()];
        }

        return ['proof' => $proof];
    }

    /**
     * Ask the calendars whether the pending branches have reached a block.
     *
     * What a calendar returns is grafted under the attestation it completes;
     * the pending attestation stays beside it, as the official client leaves
     * it. `changed` is true only when a Bitcoin attestation was added, so that
     * a proof is rewritten when it became checkable and at no other time.
     *
     * @param list<string> $named calendars named on the command line, trusted on top of the defaults
     *
     * @return array{changed:bool, errors:list<array{error:string, detail:string}>}
     */
    public static function upgrade(Proof $proof, array $named = []): array
    {
        $before = self::bitcoin($proof);
        $errors = [];
        $asked = [];
        foreach ($proof->attestations() as $attestation) {
            if ($attestation['tag'] !== Node::PENDING || $attestation['message'] === null) {
                continue;
            }
            $uri = Node::uri($attestation['payload']);
            $key = $uri.'|'.$attestation['message'];
            if (isset($asked[$key])) {
                continue;
            }
            $asked[$key] = true;
            if (!self::trusted($uri, $named)) {
                $errors[] = ['error' => 'anchor.untrusted', 'detail' => $uri];
                continue;
            }

            $answer = Calendar::upgrade($uri, $attestation['message']);
            if (isset($answer['node'])) {
                $attestation['node']->merge($answer['node']);
            } elseif (isset($answer['error'])) {
                $errors[] = $answer;
            }
        }

        return ['changed' => self::bitcoin($proof) > $before, 'errors' => $errors];
    }

    private static function bitcoin(Proof $proof): int
    {
        return \count(array_filter($proof->attestations(), static fn (array $a): bool => $a['tag'] === Node::BITCOIN));
    }

    /**
     * What a proof establishes, attestation by attestation.
     *
     * Each Bitcoin attestation is checked against a header: one the reader
     * supplied (matched by its merkle root, so no height has to be typed),
     * otherwise one fetched, when the network is allowed. Five states, because
     * collapsing them lies: `valid`, `invalid` (the header does not carry this
     * commitment, does not carry the work, or the two sources disagree),
     * `unchecked` (no header could be had, which is not a forgery), and, for the
     * proof as a whole, the pending calendars and the branches this machine
     * cannot compute.
     *
     * @param list<string> $headers raw 80-byte headers supplied by hand
     *
     * @return array{anchors:list<array{height:int, state:string, reason:string, detail:string, time:int, source:string}>, pending:list<string>, unsupported:int, unused:int}
     */
    public static function check(Proof $proof, array $headers = [], bool $network = true): array
    {
        $anchors = [];
        $pending = [];
        $unsupported = 0;
        $fetched = [];
        $used = [];
        foreach ($proof->attestations() as $attestation) {
            if ($attestation['message'] === null) {
                ++$unsupported;
                continue;
            }
            if ($attestation['tag'] === Node::PENDING) {
                $host = (string) parse_url(Node::uri($attestation['payload']), \PHP_URL_HOST);
                if (!\in_array($host, $pending, true)) {
                    $pending[] = $host;
                }
                continue;
            }
            if ($attestation['tag'] !== Node::BITCOIN) {
                continue;
            }

            $height = Node::height($attestation['payload']);
            $commitment = $attestation['message'];
            $header = null;
            $source = '';
            foreach ($headers as $index => $candidate) {
                if (substr($candidate, 36, 32) === $commitment) {
                    $header = $candidate;
                    $source = '--block-header';
                    $used[$index] = true;
                }
            }
            if ($header === null && $network) {
                $got = $fetched[$height] ??= BlockHeader::fetch($height);
                if (!isset($got['header'], $got['source'])) {
                    $error = $got['error'];
                    $anchors[] = [
                        'height' => $height,
                        // Two explorers that disagree is a finding; one that
                        // does not answer is a gap.
                        'state' => $error === 'anchor.header.disagree' ? 'invalid' : 'unchecked',
                        'reason' => $error,
                        'detail' => $got['detail'],
                        'time' => 0,
                        'source' => '',
                    ];
                    continue;
                }
                $header = $got['header'];
                $source = $got['source'];
            }
            if ($header === null) {
                $anchors[] = ['height' => $height, 'state' => 'unchecked', 'reason' => 'anchor.offline', 'detail' => '', 'time' => 0, 'source' => ''];
                continue;
            }

            $verdict = BlockHeader::check($header, $commitment, $height);
            $anchors[] = [
                'height' => $height,
                'state' => $verdict['ok'] ? 'valid' : 'invalid',
                'reason' => $verdict['reason'],
                'detail' => '',
                'time' => $verdict['time'],
                'source' => $source,
            ];
        }

        usort($anchors, static fn (array $a, array $b): int => $a['height'] <=> $b['height']);

        // A header the reader typed in that no attestation uses is not noise:
        // either it is from another block, or this proof is not about the
        // digest it claims — and with a tampered digest, that is the only
        // trace an offline check leaves, since nothing else can be matched.
        return ['anchors' => $anchors, 'pending' => $pending, 'unsupported' => $unsupported, 'unused' => \count($headers) - \count($used)];
    }

    /**
     * The one line a report prints: the earliest block that checked, or the
     * earliest one claimed, or the calendars still working on it.
     *
     * @param array{anchors:list<array{height:int, state:string, reason:string, detail:string, time:int, source:string}>, pending:list<string>, unsupported:int, unused:int} $check
     *
     * @return array{state:string, height:int, time:int, calendars:list<string>}
     */
    public static function summary(array $check): array
    {
        foreach (['valid', 'invalid', 'unchecked'] as $state) {
            foreach ($check['anchors'] as $anchor) {
                if ($anchor['state'] === $state) {
                    return ['state' => $state === 'valid' ? 'anchored' : $state, 'height' => $anchor['height'], 'time' => $anchor['time'], 'calendars' => $check['pending']];
                }
            }
        }

        return ['state' => 'pending', 'height' => 0, 'time' => 0, 'calendars' => $check['pending']];
    }

    /** A block time in the format every other date of these documents uses. */
    public static function readable(int $time): string
    {
        return gmdate('d/m/Y H:i', $time).' UTC';
    }

    /**
     * Whether a calendar URL may be contacted: https, a known operator's host
     * or one named on the command line, and nothing a URL could hide behind.
     *
     * @param list<string> $named
     */
    private static function trusted(string $uri, array $named): bool
    {
        $parts = parse_url($uri);
        if (!\is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || !isset($parts['host'])
            || isset($parts['port']) || isset($parts['user']) || !\in_array($parts['path'] ?? '', ['', '/'], true)) {
            foreach ($named as $calendar) {
                if (rtrim($calendar, '/') === rtrim($uri, '/')) {
                    return true;
                }
            }

            return false;
        }
        foreach (self::TRUSTED as $pattern) {
            if (fnmatch($pattern, strtolower($parts['host']))) {
                return true;
            }
        }
        foreach ($named as $calendar) {
            if (parse_url($calendar, \PHP_URL_HOST) === $parts['host']) {
                return true;
            }
        }

        return false;
    }
}
