<?php

declare(strict_types=1);

namespace Sablier\Ots;

/**
 * A detached OpenTimestamps proof: the `.ots` file the official client reads.
 *
 * Header magic, a major version, the operation that hashed the original file,
 * that digest, then the tree (core/timestamp.py, DetachedTimestampFile). The
 * "file" here is never a file: it is the signed findings digest, so the hash
 * operation is SHA-256 and the digest is the one printed in the report —
 * which is exactly what `ots verify -d <digest>` expects.
 */
final class Proof
{
    public const string MAGIC = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
    private const int VERSION = 1;

    /** The hash operations a detached file may name, with their digest length. */
    private const array DIGEST_LENGTH = [Node::SHA1 => 20, Node::RIPEMD160 => 20, Node::SHA256 => 32];

    public function __construct(
        /** The raw digest the tree starts from, not its hex. */
        public readonly string $digest,
        public readonly Node $root,
        public readonly int $hashOp = Node::SHA256,
    ) {
        if (\strlen($digest) !== (self::DIGEST_LENGTH[$hashOp] ?? -1)) {
            throw new FormatError('digest length does not match its hash operation');
        }
    }

    /**
     * The largest file read at all. Real proofs are a few kilobytes — the
     * nine examples of the official client are all under 2 KB, and one merged
     * from four calendars and upgraded stays under 10 KB. Refused before a
     * single byte is parsed, so a hostile file costs a stat, not a walk.
     */
    public const int MAX_BYTES = 65536;

    public static function parse(string $bytes): self
    {
        if (\strlen($bytes) > self::MAX_BYTES) {
            throw new FormatError(\sprintf('%d bytes, more than any real proof (%d at most)', \strlen($bytes), self::MAX_BYTES));
        }
        $reader = new Bytes($bytes);
        if ($reader->read(\strlen(self::MAGIC)) !== self::MAGIC) {
            throw new FormatError('not an OpenTimestamps proof');
        }
        $version = $reader->byte();
        if ($version !== self::VERSION) {
            throw new FormatError(\sprintf('proof format version %d', $version));
        }
        $op = $reader->byte();
        if (!isset(self::DIGEST_LENGTH[$op])) {
            throw new FormatError(\sprintf('file hash operation 0x%02x', $op));
        }
        $digest = $reader->read(self::DIGEST_LENGTH[$op]);
        $root = Node::parse($reader);
        $reader->end();

        return new self($digest, $root, $op);
    }

    public function serialise(): string
    {
        return self::MAGIC.\chr(self::VERSION).\chr($this->hashOp).$this->digest.$this->root->serialise();
    }

    public function hex(): string
    {
        return bin2hex($this->digest);
    }

    /**
     * Every attestation in the proof, with the message it attests.
     *
     * @return list<array{message:?string, tag:string, payload:string, node:Node}>
     */
    public function attestations(): array
    {
        return $this->root->walk($this->digest);
    }
}
