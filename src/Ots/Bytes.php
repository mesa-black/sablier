<?php

declare(strict_types=1);

namespace Sablier\Ots;

/**
 * A cursor over bytes somebody else wrote, and the two encodings the format uses.
 *
 * Everything an OpenTimestamps proof contains is read through here, because a
 * proof is untrusted input twice over: it arrives beside a report that may have
 * travelled anywhere, and half of it was written by a calendar server we do not
 * run. Every read is bounded and every overrun throws, so a truncated or hostile
 * file is a refusal with a reason rather than a warning and a wrong answer.
 *
 * The encodings are the reference implementation's (python-opentimestamps,
 * core/serialize.py): a varuint is little-endian base 128, seven bits per byte,
 * the high bit saying another byte follows, nine bytes at most; varbytes is a
 * varuint length followed by that many bytes.
 */
final class Bytes
{
    /** Nine bytes of seven bits: 63 bits, which is what fits in a PHP integer. */
    private const int MAX_VARUINT_BYTES = 9;

    private int $offset = 0;

    public function __construct(private readonly string $bytes)
    {
    }

    public function byte(): int
    {
        return \ord($this->read(1));
    }

    public function read(int $length): string
    {
        if ($length < 0 || $this->offset + $length > \strlen($this->bytes)) {
            throw new FormatError(\sprintf('truncated: %d byte(s) wanted at offset %d, %d left', $length, $this->offset, \strlen($this->bytes) - $this->offset));
        }
        $chunk = substr($this->bytes, $this->offset, $length);
        $this->offset += $length;

        return $chunk;
    }

    public function varuint(): int
    {
        $value = 0;
        for ($i = 0; $i < self::MAX_VARUINT_BYTES; ++$i) {
            $byte = $this->byte();
            $value |= ($byte & 0x7f) << (7 * $i);
            if (($byte & 0x80) === 0) {
                return $value;
            }
        }

        throw new FormatError('varuint longer than nine bytes');
    }

    public function varbytes(int $max, int $min = 0): string
    {
        $length = $this->varuint();
        if ($length > $max || $length < $min) {
            throw new FormatError(\sprintf('length %d outside %d..%d', $length, $min, $max));
        }

        return $this->read($length);
    }

    /** Trailing bytes are an error, as in the reference: a proof says exactly what it says. */
    public function end(): void
    {
        if ($this->offset !== \strlen($this->bytes)) {
            throw new FormatError(\sprintf('%d trailing byte(s)', \strlen($this->bytes) - $this->offset));
        }
    }

    public static function varuintOf(int $value): string
    {
        if ($value < 0) {
            throw new FormatError('negative varuint');
        }
        $out = '';
        do {
            $byte = $value & 0x7f;
            $value >>= 7;
            $out .= \chr($value !== 0 ? $byte | 0x80 : $byte);
        } while ($value !== 0);

        return $out;
    }

    public static function varbytesOf(string $bytes): string
    {
        return self::varuintOf(\strlen($bytes)).$bytes;
    }
}
