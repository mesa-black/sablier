<?php

declare(strict_types=1);

namespace Sablier\Ots;

use Sablier\Value;

/**
 * The 80 bytes that end an OpenTimestamps proof, and why we do not believe
 * whoever hands them to us.
 *
 * A Bitcoin attestation says "the message reached here is the merkle root of
 * the block at height N". Checking it needs that block's header, and a header
 * comes from somewhere: a node of one's own, an explorer on the web, or a
 * reader who copied it by hand. None of those is trusted. What is trusted is
 * arithmetic:
 *
 * - **The merkle root.** Bytes 36 to 68 of the header must be the message the
 *   proof computed, byte for byte, in the order the header stores them — the
 *   reverse of what explorers print (BitcoinBlockHeaderAttestation
 *   .verify_against_blockheader compares against hashMerkleRoot as stored).
 * - **The work.** The double SHA-256 of the header, read as a little-endian
 *   number, must be at or below the target its own `nBits` field encodes.
 *   Anybody can write a header; only mining makes one whose hash is that small.
 * - **How much work.** A header can encode a trivial target and satisfy it in a
 *   second. So the target must also be at or below a floor taken from real
 *   blocks of the main chain, listed below with their dates. A source that lies
 *   about the header would have to mine a block at close to the difficulty of
 *   that era — for any proof this tool makes, the difficulty of November 2026.
 *
 * The limit, said here rather than found later: the work check proves a block
 * was mined, not that it is in the chain everybody follows. Agreement between
 * two explorers run by different companies, or a node of one's own, covers
 * that half; the work check is what makes a lie expensive rather than free.
 * And the floor is an era's difficulty, so a proof claiming a very old height
 * is only as costly to forge as a block of that year was to mine.
 */
final class BlockHeader
{
    public const int LENGTH = 80;

    /**
     * Retarget blocks of the main chain, about one a year, read on 2026-11-17
     * from blockstream.info and mempool.space, which agreed on every one.
     * Height, nBits, date of the block.
     *
     * The last line is the floor every proof this tool produces is held to: it
     * was the latest retarget when the feature was written, and every anchor
     * made from here on sits above it.
     */
    private const array CHECKPOINTS = [
        [354816, 0x181713dd, '2015-05-03'],
        [407232, 0x1806274b, '2016-04-14'],
        [459648, 0x1802335a, '2017-03-30'],
        [512064, 0x175589a3, '2018-03-05'],
        [564480, 0x172e5b50, '2019-02-24'],
        [616896, 0x17121ad4, '2020-02-11'],
        [669312, 0x170d21b9, '2021-02-06'],
        [721728, 0x170a8bb4, '2022-02-04'],
        [774144, 0x17072720, '2023-01-29'],
        [826560, 0x1704005a, '2024-01-20'],
        [878976, 0x17028c61, '2025-01-12'],
        [931392, 0x1701ebf2, '2026-01-08'],
        [975744, 0x17021673, '2026-11-14'],
    ];

    /**
     * How far below a checkpoint the difficulty may fall and still be believed.
     *
     * Four, because that is the most one retarget can lower it, and because the
     * largest real fall from any of these checkpoints to a later block was
     * under half (July 2021, after mining left China: about -45% from the May
     * peak). Generous on purpose: refusing a real block would be a false alarm
     * on a sound proof, which is worse than a margin on a forgery that would
     * still cost a quarter of a block at that era's difficulty.
     */
    private const int SLACK = 4;

    /** Six confirmations: the depth past which a block is not expected to be replaced. */
    private const int SETTLED = 6;

    /** How far a header's time may sit outside the dates its height allows. */
    private const int MARGIN = 2 * 86400;

    /** Two explorers run by different companies. One alone would be one point of trust. */
    public const array EXPLORERS = ['https://blockstream.info/api', 'https://mempool.space/api'];

    /**
     * Whether a header proves what the attestation claims.
     *
     * @return array{ok:bool, reason:string, time:int}
     */
    public static function check(string $header, string $commitment, int $height): array
    {
        if (\strlen($header) !== self::LENGTH) {
            return ['ok' => false, 'reason' => 'anchor.header.length', 'time' => 0];
        }
        $time = self::uint32($header, 68);
        if (!hash_equals(substr($header, 36, 32), $commitment)) {
            return ['ok' => false, 'reason' => 'anchor.header.merkle', 'time' => $time];
        }
        $reason = self::work($header, $height);

        return ['ok' => $reason === '', 'reason' => $reason, 'time' => $time];
    }

    /**
     * Whether a header carries the work of a real block of the era it claims,
     * whatever it commits to. Empty when it does, the reason when it does not.
     *
     * Two claims in a header could pick the floor, and both are the forger's
     * to write: the height (in the attestation) and the time (in the header).
     * The first version took the floor from the height alone, and a review
     * showed what that buys: claim height 354816, write a 2026 time, mine at
     * 2015 difficulty for about a hundred dollars of hash, and the report said
     * "anchored in 2026". So the floor is the stricter of the two — the
     * checkpoint for the height and the latest checkpoint at or before the
     * time — and a time outside the window its height allows is refused
     * outright. What is left is the honest limit: a proof that claims an old
     * height *and* an old time is only as costly to forge as a block of that
     * era, and it then claims an old date, which is what it would cost.
     */
    public static function work(string $header, int $height): string
    {
        if (\strlen($header) !== self::LENGTH) {
            return 'anchor.header.length';
        }
        $time = self::uint32($header, 68);
        $byHeight = null;
        $byTime = null;
        $window = [null, null];
        foreach (self::CHECKPOINTS as $index => [$at, $floorBits, $date]) {
            $since = (int) strtotime($date.' 00:00:00 UTC');
            if ($height >= $at) {
                $byHeight = self::target($floorBits, self::SLACK);
                $next = self::CHECKPOINTS[$index + 1][2] ?? null;
                $window = [$since, $next === null ? null : (int) strtotime($next.' 00:00:00 UTC')];
            }
            if ($time >= $since) {
                $byTime = self::target($floorBits, self::SLACK);
            }
        }
        if ($byHeight === null) {
            return 'anchor.header.too_old';
        }

        // A block's time drifts from the true one by hours, never by days, and
        // the checkpoints are dated to the day: two days of margin each side.
        if ($time < $window[0] - self::MARGIN || ($window[1] !== null && $time > $window[1] + self::MARGIN)) {
            return 'anchor.header.time';
        }

        // The work after the dates: a header whose time its height cannot
        // have is refused for that, whatever it cost to mine.
        $bits = self::uint32($header, 72);
        $target = self::target($bits);
        if ($target === null || strcmp(self::hash($header), $target) > 0) {
            return 'anchor.header.work';
        }

        $floor = $byTime !== null && strcmp($byTime, $byHeight) < 0 ? $byTime : $byHeight;
        if (strcmp($target, $floor) > 0) {
            return 'anchor.header.floor';
        }

        return '';
    }

    /**
     * The header at a height, from wherever this machine is allowed to ask.
     *
     * A node of one's own first, when SABLIER_BITCOIN_RPC names one: it is the
     * only source that checked the whole chain itself. Otherwise both
     * explorers, and they must agree.
     *
     * When they do not, what the disagreement means depends on the headers.
     * Decided on 2026-11-17, after review: near the tip, two honest explorers
     * can briefly follow different branches — a reorganisation in progress,
     * not a lie — and a header without the work of its era is a source that
     * is broken or lying cheaply, which says something about that source and
     * nothing about the proof. Both are a gap (`anchor.header.unsettled`, not
     * checked). Only two headers that each carry real work, at a height buried
     * under six blocks or more, are a contradiction no honest pair produces:
     * one of them serves another chain at real cost, and the anchoring cannot
     * be established from these sources (`anchor.header.disagree`, invalid).
     *
     * @return array{header:string, source:string}|array{error:string, detail:string}
     */
    public static function fetch(int $height): array
    {
        $rpc = trim((string) getenv('SABLIER_BITCOIN_RPC'));
        if ($rpc !== '') {
            return self::rpc($rpc, $height);
        }

        $answers = [];
        foreach (self::EXPLORERS as $explorer) {
            $answer = self::explorer($explorer, $height);
            if (isset($answer['error'])) {
                return $answer;
            }
            $answers[parse_url($explorer, \PHP_URL_HOST)] = $answer['header'];
        }
        if (\count(array_unique($answers)) !== 1) {
            $mined = true;
            foreach ($answers as $header) {
                $mined = $mined && self::work($header, $height) === '';
            }
            $tip = self::tip(self::EXPLORERS[0]);
            $settled = $tip !== null && $tip - $height >= self::SETTLED;

            return ['error' => $mined && $settled ? 'anchor.header.disagree' : 'anchor.header.unsettled', 'detail' => (string) $height];
        }

        return ['header' => (string) reset($answers), 'source' => implode(' + ', array_keys($answers))];
    }

    /** The height of the chain's tip according to one explorer, null when it does not say. */
    private static function tip(string $base): ?int
    {
        $answer = Http::request('GET', $base.'/blocks/tip/height', '', ['User-Agent: sablier']);
        if ($answer === null || $answer['status'] !== 200 || preg_match('/^\d+$/', trim($answer['body'])) !== 1) {
            return null;
        }

        return (int) trim($answer['body']);
    }

    /** The hex a reader pastes, back to bytes; null when it is not a header. */
    public static function fromHex(string $hex): ?string
    {
        $hex = strtolower(trim($hex));

        return preg_match('/^[0-9a-f]{160}$/', $hex) === 1 ? (string) hex2bin($hex) : null;
    }

    /**
     * The double SHA-256 of a header as a big-endian number, ready for strcmp.
     *
     * Bitcoin reads the hash as little-endian; reversing it once makes the byte
     * comparison and the numeric one the same thing.
     */
    private static function hash(string $header): string
    {
        return strrev(hash('sha256', hash('sha256', $header, true), true));
    }

    /**
     * The 256-bit target `nBits` encodes, big-endian, times a small factor.
     *
     * Three bytes of mantissa and one of exponent: target = mantissa × 256^(exponent − 3).
     * Null for an encoding consensus refuses (the sign bit set, or a target
     * that does not fit in 256 bits), which this tool refuses too rather than
     * interpret.
     */
    private static function target(int $bits, int $factor = 1): ?string
    {
        $exponent = $bits >> 24;
        $mantissa = $bits & 0x007fffff;
        if (($bits & 0x00800000) !== 0 || $mantissa === 0) {
            return null;
        }

        $value = $mantissa * $factor;
        if ($exponent < 3) {
            $value >>= 8 * (3 - $exponent);
            $shift = 0;
        } else {
            $shift = $exponent - 3;
        }
        $bytes = ltrim(pack('J', $value), "\x00").str_repeat("\x00", $shift);
        if (\strlen($bytes) > 32) {
            return null;
        }

        return str_pad($bytes, 32, "\x00", \STR_PAD_LEFT);
    }

    private static function uint32(string $bytes, int $offset): int
    {
        $value = unpack('V', substr($bytes, $offset, 4));

        return \is_array($value) ? Value::int($value[1] ?? null) : 0;
    }

    /**
     * Esplora's API, which both explorers serve: height to hash, hash to header.
     *
     * The header's own hash is recomputed and compared with the hash the
     * explorer gave for that height: an explorer that answered the height with
     * one block and the header with another is not an explorer to believe.
     *
     * @return array{header:string}|array{error:string, detail:string}
     */
    private static function explorer(string $base, int $height): array
    {
        $host = (string) parse_url($base, \PHP_URL_HOST);
        $hash = Http::request('GET', $base.'/block-height/'.$height, '', ['User-Agent: sablier']);
        if ($hash === null || $hash['status'] !== 200 || preg_match('/^[0-9a-f]{64}$/', trim($hash['body'])) !== 1) {
            return ['error' => 'anchor.header.unreachable', 'detail' => $host];
        }
        $hash = trim($hash['body']);

        $hex = Http::request('GET', $base.'/block/'.$hash.'/header', '', ['User-Agent: sablier']);
        $header = $hex !== null && $hex['status'] === 200 ? self::fromHex($hex['body']) : null;
        if ($header === null) {
            return ['error' => 'anchor.header.unreachable', 'detail' => $host];
        }
        if (bin2hex(self::hash($header)) !== $hash) {
            return ['error' => 'anchor.header.inconsistent', 'detail' => $host];
        }

        return ['header' => $header];
    }

    /**
     * A Bitcoin Core node, through its JSON-RPC: getblockhash, then
     * getblockheader with verbose off, which returns the 80 bytes in hex.
     *
     * Credentials ride in the URL (http://user:password@host:8332), the form
     * every Bitcoin tool accepts; they are moved into a header here so they do
     * not depend on how a given PHP build treats userinfo, and never printed.
     *
     * @return array{header:string, source:string}|array{error:string, detail:string}
     */
    private static function rpc(string $url, int $height): array
    {
        $parts = parse_url($url);
        if (!\is_array($parts) || !isset($parts['host'])) {
            return ['error' => 'anchor.header.rpc', 'detail' => 'SABLIER_BITCOIN_RPC'];
        }
        $endpoint = ($parts['scheme'] ?? 'http').'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '').($parts['path'] ?? '/');
        $headers = ['Content-Type: application/json'];
        if (isset($parts['user'])) {
            $headers[] = 'Authorization: Basic '.base64_encode(urldecode($parts['user']).':'.urldecode($parts['pass'] ?? ''));
        }

        $call = static function (string $method, array $params) use ($endpoint, $headers): ?string {
            $answer = Http::request('POST', $endpoint, (string) json_encode(['jsonrpc' => '1.0', 'id' => 'sablier', 'method' => $method, 'params' => $params]), $headers, 100000);
            if ($answer === null || $answer['status'] !== 200) {
                return null;
            }
            $decoded = Value::map(json_decode($answer['body'], true));
            $result = $decoded['result'] ?? null;

            return \is_string($result) ? $result : null;
        };

        $host = $parts['host'];
        $hash = $call('getblockhash', [$height]);
        if ($hash === null || preg_match('/^[0-9a-f]{64}$/', $hash) !== 1) {
            return ['error' => 'anchor.header.rpc', 'detail' => $host];
        }
        $header = self::fromHex((string) $call('getblockheader', [$hash, false]));
        if ($header === null || bin2hex(self::hash($header)) !== $hash) {
            return ['error' => 'anchor.header.rpc', 'detail' => $host];
        }

        return ['header' => $header, 'source' => $host];
    }
}
