<?php

declare(strict_types=1);

namespace Sablier;

/**
 * A pair of keys, drawn as a constellation.
 *
 * The fingerprint of the keys is what ties a signed report to its author, and
 * it is thirty-two characters nobody reads twice. A drawing is something a
 * reader recognises without reading: the same keys always give the same sky,
 * and other keys an unrelated one. Somebody who receives a report every
 * quarter sees, before anything else, whether it comes from the usual hand.
 *
 * What it is not: a proof. A page draws its own sky, so a forged page draws
 * the forger's, or copies the picture outright. The sky is derived from the
 * same hash as the fingerprint and establishes nothing the fingerprint does
 * not; it carries fewer bits to the eye, and its name about 33. It is a way to
 * notice a change, and the fingerprint received by another channel stays the
 * check. The report says so beside the drawing.
 *
 * The mapping is Stellar's, version 1 (https://github.com/mesa-black/stellar),
 * reimplemented here rather than called, because this tool has no dependency
 * and its report loads nothing. `tests/fixtures/stellar-v1.json` is Stellar's
 * own list of reference constellations, and the test suite refuses a port
 * that draws one of them differently: a sky that depended on which program
 * drew it would be worse than none.
 *
 * PHP has no SHAKE256 with a chosen output length, so the sponge is written
 * out below. It is the plain Keccak-f[1600] of FIPS 202 on 64-bit integers.
 */
final class Sky
{
    private const int GRID = 64;
    private const int FIELD_GRID = 256;
    private const int MIN_DISTANCE_SQUARED = 81;

    private const string CONSONANTS = 'bdfghjklmnprstvz';
    private const string VOWELS = 'aeiou';
    private const array NOUN_ENDINGS = ['a', 'us', 'um', 'is', 'ix', 'or', 'ax', 'ia'];
    private const array EPITHET_ENDINGS = ['alis', 'aris', 'ensis', 'inus', 'ianus', 'osus', 'atus', 'icus'];

    /** Glow and core colours of the five spectral classes, hot blue to cool red. */
    private const array CLASS_COLOURS = ['#8fb4ff', '#f4f6ff', '#ffe08a', '#ffb070', '#ff7b6b'];
    /** Core radius per magnitude, brightest first, in viewBox units. */
    private const array RADII = [11.0, 8.0, 5.5];

    /** SHAKE256 absorbs and squeezes 136 bytes at a time. */
    private const int RATE = 136;

    /** Rotation offsets of the rho step, in the order the pi step visits the lanes. */
    private const array ROTATIONS = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
    private const array LANES = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
    /**
     * Round constants, as two 32-bit halves: a literal above 2^63 would be
     * read as a float.
     */
    private const array ROUNDS = [
        [0x00000000, 0x00000001], [0x00000000, 0x00008082], [0x80000000, 0x0000808A], [0x80000000, 0x80008000],
        [0x00000000, 0x0000808B], [0x00000000, 0x80000001], [0x80000000, 0x80008081], [0x80000000, 0x00008009],
        [0x00000000, 0x0000008A], [0x00000000, 0x00000088], [0x00000000, 0x80008009], [0x00000000, 0x8000000A],
        [0x00000000, 0x8000808B], [0x80000000, 0x0000008B], [0x80000000, 0x00008089], [0x80000000, 0x00008003],
        [0x80000000, 0x00008002], [0x80000000, 0x00000080], [0x00000000, 0x0000800A], [0x80000000, 0x8000000A],
        [0x80000000, 0x80008081], [0x80000000, 0x00008080], [0x00000000, 0x80000001], [0x80000000, 0x80008008],
    ];

    public readonly string $name;
    /** @var list<array{x:int, y:int, magnitude:int, class:int}> */
    public readonly array $stars;
    /** @var list<array{0:int, 1:int}> pairs of star indices, the lower first */
    public readonly array $edges;
    /** @var list<array{x:int, y:int, brightness:int}> */
    public readonly array $field;

    /** @var array<int, int> the 25 lanes of the sponge */
    private array $state;
    private string $squeezed = '';

    /** @param string $digest the 32 raw bytes of a SHA-256 */
    public function __construct(string $digest)
    {
        if (\strlen($digest) !== 32) {
            throw new \InvalidArgumentException('A sky is drawn from the 32 bytes of a SHA-256.');
        }
        $this->state = array_fill(0, 25, 0);
        $this->absorb("stellar/v1\0".$digest);

        // The order of the draws below is the mapping: name, count, stars,
        // tree, loops, background.
        $this->name = $this->drawName();

        $count = 7 + $this->draw(6);
        $stars = [];
        while (\count($stars) < $count) {
            $x = $this->draw(self::GRID);
            $y = $this->draw(self::GRID);
            foreach ($stars as $star) {
                if (($star['x'] - $x) ** 2 + ($star['y'] - $y) ** 2 < self::MIN_DISTANCE_SQUARED) {
                    continue 2;
                }
            }
            $stars[] = ['x' => $x, 'y' => $y, 'magnitude' => $this->draw(3), 'class' => $this->draw(5)];
        }

        // Each star joins one of the two nearest stars placed before it.
        $edges = [];
        $joined = [];
        $link = static function (int $a, int $b) use (&$edges, &$joined): void {
            $joined[$a][$b] = $joined[$b][$a] = true;
            $edges[] = [min($a, $b), max($a, $b)];
        };
        for ($i = 1; $i < $count; ++$i) {
            $near = self::nearest($stars, $i, range(0, $i - 1));
            $link($near[\count($near) > 1 ? $this->draw(2) : 0], $i);
        }
        // Up to two more edges close loops.
        for ($extra = $this->draw(3); $extra > 0; --$extra) {
            $a = $this->draw($count);
            $free = array_values(array_filter(
                range(0, $count - 1),
                static fn (int $j): bool => $j !== $a && !isset($joined[$a][$j]),
            ));
            if ($free !== []) {
                $link($a, self::nearest($stars, $a, $free)[0]);
            }
        }

        $field = [];
        for ($n = 40 + $this->draw(24); $n > 0; --$n) {
            $field[] = [
                'x' => $this->draw(self::FIELD_GRID),
                'y' => $this->draw(self::FIELD_GRID),
                'brightness' => $this->draw(3),
            ];
        }

        $this->stars = $stars;
        $this->edges = $edges;
        $this->field = $field;
        $this->state = [];
        $this->squeezed = '';
    }

    /**
     * The drawing, as a standalone SVG element.
     *
     * It is always night in it, whatever the theme of the page around: the
     * colours are part of what a reader recognises. The identifiers carry a
     * prefix, since the element is inlined in a page that has its own.
     *
     * @param string $caption printed under the name; the fingerprint, usually
     */
    public function svg(string $caption = ''): string
    {
        $out = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000" role="img" aria-label="'
            .htmlspecialchars($this->name).'">'
            .'<defs><radialGradient id="sky-night" cx="50%" cy="42%" r="75%">'
            .'<stop offset="0" stop-color="#16204a"/><stop offset="1" stop-color="#05060f"/></radialGradient>';
        foreach (self::CLASS_COLOURS as $class => $colour) {
            $out .= '<radialGradient id="sky-glow'.$class.'"><stop offset="0" stop-color="'.$colour
                .'" stop-opacity=".55"/><stop offset="1" stop-color="'.$colour.'" stop-opacity="0"/></radialGradient>';
        }
        $out .= '</defs><rect width="1000" height="1000" rx="4" fill="url(#sky-night)"/><g fill="#cfd8ff">';
        foreach ($this->field as $star) {
            $out .= \sprintf(
                '<circle cx="%.1F" cy="%.1F" r="%.1F" opacity="%.2F"/>',
                ($star['x'] + 0.5) / self::FIELD_GRID * 1000,
                ($star['y'] + 0.5) / self::FIELD_GRID * 1000,
                0.9 + 0.45 * $star['brightness'],
                0.25 + 0.17 * $star['brightness'],
            );
        }
        $out .= '</g><g stroke="#dfe6ff" stroke-opacity=".5" stroke-width="2.2" stroke-linecap="round">';
        foreach ($this->edges as [$a, $b]) {
            $out .= \sprintf('<line x1="%.1F" y1="%.1F" x2="%.1F" y2="%.1F"/>', ...self::place($this->stars[$a]), ...self::place($this->stars[$b]));
        }
        $out .= '</g>';
        foreach ($this->stars as $star) {
            [$x, $y] = self::place($star);
            $r = self::RADII[$star['magnitude']];
            $colour = self::CLASS_COLOURS[$star['class']];
            $out .= \sprintf('<circle cx="%.1F" cy="%.1F" r="%.1F" fill="url(#sky-glow%d)"/>', $x, $y, $r * 4, $star['class']);
            if ($star['magnitude'] === 0) {
                // Diffraction spikes single out the brightest stars.
                $out .= \sprintf(
                    '<path d="M%.1F %.1FH%.1FM%.1F %.1FV%.1F" stroke="%s" stroke-opacity=".7" stroke-width="1.6" stroke-linecap="round"/>',
                    $x - $r * 3.2, $y, $x + $r * 3.2, $x, $y - $r * 3.2, $y + $r * 3.2, $colour,
                );
            }
            $out .= \sprintf('<circle cx="%.1F" cy="%.1F" r="%.1F" fill="%s"/>', $x, $y, $r, $colour)
                .\sprintf('<circle cx="%.1F" cy="%.1F" r="%.1F" fill="#fff"/>', $x, $y, $r * 0.45);
        }
        $out .= '<text x="500" y="935" text-anchor="middle" font-family="ui-sans-serif, system-ui, sans-serif" font-size="34" letter-spacing="10" fill="#e8ecff">'
            .htmlspecialchars(strtoupper($this->name)).'</text>';
        if ($caption !== '') {
            $out .= '<text x="500" y="972" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="17" fill="#e8ecff" fill-opacity=".6">'
                .htmlspecialchars($caption).'</text>';
        }

        return $out.'</svg>';
    }

    /**
     * Where a star sits in the viewBox, which keeps room for the caption.
     *
     * @param array{x:int, y:int, magnitude:int, class:int} $star
     *
     * @return array{0:float, 1:float}
     */
    private static function place(array $star): array
    {
        return [110 + ($star['x'] + 0.5) / self::GRID * 780, 70 + ($star['y'] + 0.5) / self::GRID * 780];
    }

    /**
     * The candidates, nearest to star $i first; at equal distance, the lower
     * index first. The tie-break is part of the mapping.
     *
     * @param list<array{x:int, y:int, magnitude:int, class:int}> $stars
     * @param list<int>                                            $candidates
     *
     * @return list<int>
     */
    private static function nearest(array $stars, int $i, array $candidates): array
    {
        $distance = static fn (int $j): int => ($stars[$i]['x'] - $stars[$j]['x']) ** 2 + ($stars[$i]['y'] - $stars[$j]['y']) ** 2;
        usort($candidates, static fn (int $a, int $b): int => [$distance($a), $a] <=> [$distance($b), $b]);

        return $candidates;
    }

    /** An invented name with a Latin sound: a noun and an epithet. */
    private function drawName(): string
    {
        $consonant = fn (): string => self::CONSONANTS[$this->draw(16)];
        $vowel = fn (): string => self::VOWELS[$this->draw(5)];

        $noun = $consonant().$vowel().$consonant().$vowel().$consonant().self::NOUN_ENDINGS[$this->draw(8)];
        $epithet = $consonant().$vowel().$consonant().self::EPITHET_ENDINGS[$this->draw(8)];

        return ucfirst($noun).' '.ucfirst($epithet);
    }

    /**
     * A uniform integer in [0, $n), for $n up to 65536: two bytes read
     * big-endian, drawn again when they would bias the result.
     */
    private function draw(int $n): int
    {
        $limit = 65536 - 65536 % $n;
        do {
            if (\strlen($this->squeezed) < 2) {
                $this->squeeze();
            }
            $value = (\ord($this->squeezed[0]) << 8) | \ord($this->squeezed[1]);
            $this->squeezed = substr($this->squeezed, 2);
        } while ($value >= $limit);

        return $value % $n;
    }

    /** Absorbs the whole message and pads it as SHAKE does (0x1F … 0x80). */
    private function absorb(string $message): void
    {
        $message .= "\x1F";
        $message = str_pad($message, (int) (ceil(\strlen($message) / self::RATE) * self::RATE), "\0");
        $message[\strlen($message) - 1] = $message[\strlen($message) - 1] | "\x80";

        foreach (str_split($message, self::RATE) as $block) {
            /** @var array<int, int> $lanes */
            $lanes = unpack('P17', $block);
            foreach ($lanes as $i => $lane) {
                $this->state[$i - 1] ^= $lane;
            }
            $this->permute();
        }
    }

    /** Appends one block of output. The block is a multiple of two bytes, so draws never straddle a call. */
    private function squeeze(): void
    {
        $this->squeezed .= pack('P17', ...\array_slice($this->state, 0, 17));
        $this->permute();
    }

    /** Keccak-f[1600]: twenty-four rounds of theta, rho, pi, chi and iota. */
    private function permute(): void
    {
        $s = $this->state;
        foreach (self::ROUNDS as [$high, $low]) {
            $c = [];
            for ($x = 0; $x < 5; ++$x) {
                $c[$x] = $s[$x] ^ $s[$x + 5] ^ $s[$x + 10] ^ $s[$x + 15] ^ $s[$x + 20];
            }
            for ($x = 0; $x < 5; ++$x) {
                $d = $c[($x + 4) % 5] ^ self::rotate($c[($x + 1) % 5], 1);
                for ($y = 0; $y < 25; $y += 5) {
                    $s[$x + $y] ^= $d;
                }
            }

            $carried = $s[1];
            foreach (self::LANES as $i => $lane) {
                $next = $s[$lane];
                $s[$lane] = self::rotate($carried, self::ROTATIONS[$i]);
                $carried = $next;
            }

            for ($y = 0; $y < 25; $y += 5) {
                $row = \array_slice($s, $y, 5);
                for ($x = 0; $x < 5; ++$x) {
                    $s[$y + $x] = $row[$x] ^ (~$row[($x + 1) % 5] & $row[($x + 2) % 5]);
                }
            }

            $s[0] ^= ($high << 32) | $low;
        }
        $this->state = $s;
    }

    /**
     * A 64-bit rotation to the left. PHP's right shift carries the sign, so
     * the bits that come round are masked.
     */
    private static function rotate(int $lane, int $by): int
    {
        return ($lane << $by) | (($lane >> (64 - $by)) & ((1 << $by) - 1));
    }
}
