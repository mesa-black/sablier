<?php

declare(strict_types=1);

namespace Sablier\Ots;

use Sablier\Version;

/**
 * A remote OpenTimestamps calendar: two requests, both public.
 *
 * Submitting POSTs the 32 raw bytes of the digest to `<calendar>/digest` and
 * gets back a short tree — a few appends and hashes ending in a pending
 * attestation that names the calendar. The calendar aggregates every digest it
 * receives into one merkle tree and puts that tree's root in a Bitcoin
 * transaction, typically within a few hours.
 *
 * Upgrading GETs `<calendar>/timestamp/<hex commitment>`, where the commitment
 * is the message reached at the pending attestation. 404 means the transaction
 * is not confirmed yet; 200 returns the rest of the path, down to the block.
 *
 * Neither request carries anything but a hash. The calendar never sees the
 * findings, the report or who asked, beyond an IP address.
 */
final class Calendar
{
    private const string ACCEPT = 'application/vnd.opentimestamps.v1';

    /**
     * @return array{node:Node}|array{error:string, detail:string}
     */
    public static function submit(string $calendar, string $digest): array
    {
        $answer = Http::request('POST', rtrim($calendar, '/').'/digest', $digest, [
            'Accept: '.self::ACCEPT,
            'User-Agent: sablier/'.Version::NUMBER,
            'Content-Type: application/octet-stream',
        ]);
        if ($answer === null) {
            return ['error' => 'anchor.unreachable', 'detail' => $calendar];
        }
        if ($answer['status'] !== 200) {
            return ['error' => 'anchor.refused', 'detail' => $calendar.' (HTTP '.$answer['status'].')'];
        }

        return self::tree($answer['body'], $digest, $calendar);
    }

    /**
     * @return array{node:Node}|array{pending:true}|array{error:string, detail:string}
     */
    public static function upgrade(string $calendar, string $commitment): array
    {
        $answer = Http::request('GET', rtrim($calendar, '/').'/timestamp/'.bin2hex($commitment), '', [
            'Accept: '.self::ACCEPT,
            'User-Agent: sablier/'.Version::NUMBER,
        ]);
        if ($answer === null) {
            return ['error' => 'anchor.unreachable', 'detail' => $calendar];
        }
        if ($answer['status'] === 404) {
            return ['pending' => true];
        }
        if ($answer['status'] !== 200) {
            return ['error' => 'anchor.refused', 'detail' => $calendar.' (HTTP '.$answer['status'].')'];
        }

        return self::tree($answer['body'], $commitment, $calendar);
    }

    /**
     * What a calendar answered, parsed and walked before anything is kept.
     *
     * Walked, not only parsed: an answer whose operations cannot be applied to
     * the message it continues would make the whole file unreadable the next
     * time, so it is refused here, at the door, with the calendar named.
     *
     * @return array{node:Node}|array{error:string, detail:string}
     */
    private static function tree(string $body, string $message, string $calendar): array
    {
        try {
            $reader = new Bytes($body);
            $node = Node::parse($reader);
            $reader->end();
            $node->walk($message);
        } catch (FormatError $e) {
            return ['error' => 'anchor.malformed', 'detail' => $calendar.': '.$e->getMessage()];
        }

        return ['node' => $node];
    }
}
