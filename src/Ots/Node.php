<?php

declare(strict_types=1);

namespace Sablier\Ots;

/**
 * One message in an OpenTimestamps proof, and everything that hangs off it.
 *
 * A proof is a tree. Each node stands for a message — the digest at the root,
 * then whatever the operations below it produce — and carries two kinds of
 * children: attestations, which say "this exact message was recorded
 * somewhere", and operations, each leading to the node of its result. Walking
 * from the root down to a Bitcoin attestation recomputes, one hash at a time,
 * the merkle root of a block: that walk *is* the verification, and it needs
 * nothing but the hash functions.
 *
 * The node does not store its message. The reference implementation computes
 * results while parsing; this one parses the structure first and computes on
 * the walk, so that a branch through an operation PHP cannot run (Keccak-256,
 * which is not SHA3-256 and is not in ext-hash) refuses that branch instead of
 * refusing the whole file — the other branches, and the bytes of this one,
 * survive a round trip untouched.
 *
 * Serialisation sorts attestations and operations the way the reference does
 * (core/timestamp.py, Timestamp.serialize), so a proof this tool merges or
 * upgrades comes out byte for byte as the official client would write it, and
 * a proof it only reads comes out exactly as it came in.
 */
final class Node
{
    public const int SHA1 = 0x02;
    public const int RIPEMD160 = 0x03;
    public const int SHA256 = 0x08;
    public const int KECCAK256 = 0x67;
    public const int APPEND = 0xf0;
    public const int PREPEND = 0xf1;
    public const int REVERSE = 0xf2;
    public const int HEXLIFY = 0xf3;

    /** Recorded in a calendar, to be completed later: the payload is the calendar's URI. */
    public const string PENDING = "\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e";
    /** The message is the merkle root of the Bitcoin block at the height in the payload. */
    public const string BITCOIN = "\x05\x88\x96\x0d\x73\xd7\x19\x01";

    /** The reference's limits (core/op.py, core/notary.py), kept so a proof it accepts is one we accept. */
    public const int MAX_MESSAGE = 4096;
    private const int MAX_PAYLOAD = 8192;
    private const int MAX_URI = 1000;
    private const int MAX_DEPTH = 256;
    private const int MAX_HEIGHT = 4294967295;

    /**
     * How many operations and attestations a whole proof may hold.
     *
     * The reference has no such limit, and a review showed why one is needed
     * here: 65,536 forks of 4 KB messages fit in under a megabyte and exhausted
     * PHP's memory on the walk, so a file handed to `verify` could stop it with
     * a fatal error instead of a refusal. A real proof merged from four
     * calendars and upgraded holds a few hundred elements; 2,048 leaves ample
     * room and caps the walk at about 8 MB of messages.
     */
    public const int MAX_ELEMENTS = 2048;

    /** What the reference allows in a pending URI: no query, no fragment, no credentials, no percent. */
    private const string URI_CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:';

    private const array UNARY = [self::SHA1, self::RIPEMD160, self::SHA256, self::KECCAK256, self::REVERSE, self::HEXLIFY];
    private const array BINARY = [self::APPEND, self::PREPEND];

    /** @var list<array{tag:string, payload:string}> */
    public array $attestations = [];

    /** @var list<array{op:int, arg:string, node:Node}> */
    public array $ops = [];

    /**
     * The operations and attestations already here, keyed, so a duplicate is
     * found in one lookup. Scanning the siblings instead made a node with
     * forty thousand branches take a minute to parse.
     *
     * @var array<string, true>
     */
    private array $seen = [];

    public static function parse(Bytes $bytes, int $depth = 0): self
    {
        if ($depth >= self::MAX_DEPTH) {
            throw new FormatError('proof nested deeper than '.self::MAX_DEPTH);
        }

        // 0xff announces "another branch follows this one"; the last branch of
        // a node is the one without it.
        $node = new self();
        $tag = $bytes->byte();
        while ($tag === 0xff) {
            $node->element($bytes, $bytes->byte(), $depth);
            $tag = $bytes->byte();
        }
        $node->element($bytes, $tag, $depth);

        return $node;
    }

    private function element(Bytes $bytes, int $tag, int $depth): void
    {
        if ($tag === 0x00) {
            $kind = $bytes->read(8);
            $payload = $bytes->varbytes(self::MAX_PAYLOAD);
            // Known attestations are checked as the reference checks them; an
            // unknown one is kept as it came, so that a notary this tool has
            // never heard of survives a rewrite.
            if ($kind === self::PENDING) {
                self::uri($payload);
            } elseif ($kind === self::BITCOIN) {
                self::height($payload);
            }
            $bytes->count(self::MAX_ELEMENTS);
            // Collapsed, as the reference's set collapses them: the same
            // attestation twice on one message says nothing the first did not.
            $this->addAttestation(['tag' => $kind, 'payload' => $payload]);

            return;
        }

        if (\in_array($tag, self::UNARY, true)) {
            $arg = '';
        } elseif (\in_array($tag, self::BINARY, true)) {
            $arg = $bytes->varbytes(self::MAX_MESSAGE, 1);
        } else {
            throw new FormatError(\sprintf('unknown operation 0x%02x', $tag));
        }

        $bytes->count(self::MAX_ELEMENTS);
        if (isset($this->seen[self::opKey($tag, $arg)])) {
            throw new FormatError(\sprintf('operation 0x%02x repeated', $tag));
        }
        $this->seen[self::opKey($tag, $arg)] = true;

        $this->ops[] = ['op' => $tag, 'arg' => $arg, 'node' => self::parse($bytes, $depth + 1)];
    }

    /** @param array{tag:string, payload:string} $attestation */
    private function addAttestation(array $attestation): void
    {
        $key = 'a:'.$attestation['tag'].$attestation['payload'];
        if (!isset($this->seen[$key])) {
            $this->seen[$key] = true;
            $this->attestations[] = $attestation;
        }
    }

    private static function opKey(int $op, string $arg): string
    {
        return 'o:'.$op.':'.$arg;
    }

    public function serialise(): string
    {
        $attestations = $this->attestations;
        usort($attestations, self::compareAttestations(...));
        $ops = $this->ops;
        // strcmp rather than <=> on the arguments: two byte strings that both
        // happen to look like numbers would be compared as numbers.
        usort($ops, static fn (array $a, array $b): int => ($a['op'] <=> $b['op']) ?: strcmp($a['arg'], $b['arg']));

        if ($attestations === [] && $ops === []) {
            throw new FormatError('an empty node cannot be written');
        }

        $out = '';
        $last = array_pop($attestations);
        foreach ($attestations as $attestation) {
            $out .= "\xff\x00".self::attestation($attestation);
        }
        if ($ops === []) {
            return $out."\x00".self::attestation($last ?? throw new FormatError('unreachable'));
        }
        if ($last !== null) {
            $out .= "\xff\x00".self::attestation($last);
        }

        $final = array_pop($ops);
        foreach ($ops as $op) {
            $out .= "\xff".self::operation($op['op'], $op['arg']).$op['node']->serialise();
        }

        return $out.self::operation($final['op'], $final['arg']).$final['node']->serialise();
    }

    /**
     * Fold another tree for the same message into this one.
     *
     * Used twice: to put the answers of several calendars under one digest — a
     * fork at the root, each branch its own calendar — and to graft what a
     * calendar returns on upgrade under the pending attestation it completes.
     * Pending attestations are kept beside the Bitcoin one, as the official
     * client keeps them: they cost a few bytes and say where to ask again.
     */
    public function merge(self $other): void
    {
        foreach ($other->attestations as $attestation) {
            $this->addAttestation($attestation);
        }
        $index = [];
        foreach ($this->ops as $ours) {
            $index[self::opKey($ours['op'], $ours['arg'])] = $ours['node'];
        }
        foreach ($other->ops as $theirs) {
            $key = self::opKey($theirs['op'], $theirs['arg']);
            if (isset($index[$key])) {
                $index[$key]->merge($theirs['node']);
                continue;
            }
            $this->seen[$key] = true;
            $index[$key] = $theirs['node'];
            $this->ops[] = $theirs;
        }
    }

    /**
     * Every attestation under this node, with the message it attests.
     *
     * The message is null below an operation this machine cannot compute: the
     * attestation is still listed, so that a reader is told a branch was not
     * checked rather than left to assume there was none.
     *
     * @return list<array{message:?string, tag:string, payload:string, node:Node}>
     */
    public function walk(?string $message): array
    {
        $found = [];
        $this->collect($message, $found);

        return $found;
    }

    /**
     * The walk itself, appending to one list rather than copying a merged one
     * at every level, which made a wide proof quadratic.
     *
     * @param list<array{message:?string, tag:string, payload:string, node:Node}> $found
     */
    private function collect(?string $message, array &$found): void
    {
        foreach ($this->attestations as $attestation) {
            $found[] = ['message' => $message, 'tag' => $attestation['tag'], 'payload' => $attestation['payload'], 'node' => $this];
        }
        foreach ($this->ops as $op) {
            $op['node']->collect($message === null ? null : self::apply($op['op'], $op['arg'], $message), $found);
        }
    }

    /**
     * One edge of the tree. Null for Keccak-256 only: PHP has SHA3-256, which
     * pads differently and gives another answer, and computing the wrong hash
     * would turn "not checked" into "does not match".
     */
    public static function apply(int $op, string $arg, string $message): ?string
    {
        $limit = $op === self::HEXLIFY ? intdiv(self::MAX_MESSAGE, 2) : self::MAX_MESSAGE;
        if ($message === '' || \strlen($message) > $limit) {
            throw new FormatError(\sprintf('message of %d byte(s) refused by operation 0x%02x', \strlen($message), $op));
        }

        $result = match ($op) {
            self::SHA1 => hash('sha1', $message, true),
            self::RIPEMD160 => hash('ripemd160', $message, true),
            self::SHA256 => hash('sha256', $message, true),
            self::KECCAK256 => null,
            self::APPEND => $message.$arg,
            self::PREPEND => $arg.$message,
            self::REVERSE => strrev($message),
            self::HEXLIFY => bin2hex($message),
            default => throw new FormatError(\sprintf('unknown operation 0x%02x', $op)),
        };
        if ($result !== null && \strlen($result) > self::MAX_MESSAGE) {
            throw new FormatError('operation result longer than '.self::MAX_MESSAGE.' bytes');
        }

        return $result;
    }

    /** The calendar a pending attestation points at. */
    public static function uri(string $payload): string
    {
        $bytes = new Bytes($payload);
        $uri = $bytes->varbytes(self::MAX_URI);
        $bytes->end();
        if (\strlen($uri) !== strspn($uri, self::URI_CHARACTERS)) {
            throw new FormatError('pending attestation with a URI outside the allowed characters');
        }

        return $uri;
    }

    /** The block height a Bitcoin attestation names. */
    public static function height(string $payload): int
    {
        $bytes = new Bytes($payload);
        $height = $bytes->varuint();
        $bytes->end();
        if ($height > self::MAX_HEIGHT) {
            throw new FormatError('block height out of range');
        }

        return $height;
    }

    public static function pending(string $uri): self
    {
        $node = new self();
        $node->addAttestation(['tag' => self::PENDING, 'payload' => Bytes::varbytesOf($uri)]);

        return $node;
    }

    private static function operation(int $op, string $arg): string
    {
        return \chr($op).(\in_array($op, self::BINARY, true) ? Bytes::varbytesOf($arg) : '');
    }

    /** @param array{tag:string, payload:string} $attestation */
    private static function attestation(array $attestation): string
    {
        return $attestation['tag'].Bytes::varbytesOf($attestation['payload']);
    }

    /**
     * The reference's order: by tag, then by URI for pending ones, by height
     * for Bitcoin ones, by raw payload for the rest.
     *
     * @param array{tag:string, payload:string} $a
     * @param array{tag:string, payload:string} $b
     */
    private static function compareAttestations(array $a, array $b): int
    {
        if ($a['tag'] !== $b['tag']) {
            return strcmp($a['tag'], $b['tag']);
        }

        return match ($a['tag']) {
            self::PENDING => strcmp(self::uri($a['payload']), self::uri($b['payload'])),
            self::BITCOIN => self::height($a['payload']) <=> self::height($b['payload']),
            default => strcmp($a['payload'], $b['payload']),
        };
    }
}
