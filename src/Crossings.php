<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The date each domain crosses the line.
 *
 * The chart shows a bar against a mark and asks the reader to do the
 * subtraction. The subtraction has one answer, and it is a date: data encrypted
 * in year Y stays sensitive until Y + lifetime, so the first year whose data
 * outlives the expiry is `expiry − lifetime + 1`. Before that year the domain
 * is fine; from it, everything encrypted is already lost by the time the
 * algorithm goes.
 *
 * Two conditions, because a date printed about the wrong domain is worse than
 * no date at all:
 *
 *   · it is about confidentiality. A signature is not harvested, so a domain
 *     that only signs never crosses anything;
 *   · it is about an algorithm a quantum computer breaks. A domain protected by
 *     AES or ML-KEM can hold data for a century without crossing a line — and
 *     colouring it by duration alone was the bug this project already fixed
 *     once, in the chart.
 *
 * A lifetime of zero never crosses: published content has no window to close.
 */
final class Crossings
{
    /**
     * @return list<array{domain:string, lifetime:int, year:int, past:bool, outlives:bool, declared:bool}>
     *                                                                                      sorted by date, soonest first
     */
    public static function for(Analysis $analysis): array
    {
        $domains = [];
        foreach ($analysis->findings as $finding) {
            if (!self::harvestable($finding)) {
                continue;
            }
            $domains[$finding->domain] ??= ['lifetime' => 0, 'declared' => $finding->domainDeclared, 'expiry' => $finding->expiry];
            $domains[$finding->domain]['lifetime'] = max($domains[$finding->domain]['lifetime'], $finding->lifetime);
        }

        $crossings = [];
        foreach ($domains as $name => $domain) {
            if ($domain['lifetime'] <= 0) {
                continue;
            }

            // Counted back from the deadline that applies to this domain, which
            // under a graded regime is not the same for all of them.
            $year = $domain['expiry'] - $domain['lifetime'] + 1;
            $serviceUntil = $analysis->declaration->serviceUntil;
            $crossings[] = [
                'domain' => (string) $name,
                'lifetime' => $domain['lifetime'],
                'year' => $year,
                'past' => $year <= $analysis->currentYear,
                // A system retired before its own crossing date never crosses:
                // nothing it will ever write outlives the algorithm protecting
                // it. That is the one answer in this whole report that lets
                // somebody do nothing for a good reason.
                'outlives' => $serviceUntil > 0 && $year > $serviceUntil,
                'declared' => $domain['declared'],
            ];
        }

        usort($crossings, static fn (array $a, array $b): int => $a['year'] <=> $b['year']);

        return $crossings;
    }

    /**
     * The next one still ahead, which is the only one anybody can act on.
     *
     * @return array{domain:string, lifetime:int, year:int, past:bool, outlives:bool, declared:bool}|null
     */
    public static function next(Analysis $analysis): ?array
    {
        foreach (self::for($analysis) as $crossing) {
            if (!$crossing['past'] && !$crossing['outlives']) {
                return $crossing;
            }
        }

        return null;
    }

    /**
     * A calendar, because a date nobody is reminded of is a date nobody keeps.
     *
     * One all-day event per crossing still ahead, on the first of January of
     * that year, written by hand: iCalendar is a line-based format and a
     * dependency to emit it would cost more than the twenty lines below.
     */
    public static function toIcalendar(Analysis $analysis): string
    {
        $stamp = (new \DateTimeImmutable())->format('Ymd\THis\Z');
        $project = $analysis->declaration->project !== ''
            ? $analysis->declaration->project
            : basename($analysis->target);

        $lines = [
            'BEGIN:VCALENDAR',
            'VERSION:2.0',
            'PRODID:-//Sablier//Crossings//EN',
            'CALSCALE:GREGORIAN',
            'METHOD:PUBLISH',
            'X-WR-CALNAME:'.self::escape(Lang::t('crossing.calendar.name', $project)),
        ];

        foreach (self::for($analysis) as $crossing) {
            if ($crossing['past'] || $crossing['outlives']) {
                continue;
            }

            $date = \sprintf('%04d0101', $crossing['year']);
            $lines = [...$lines,
                'BEGIN:VEVENT',
                'UID:'.hash('sha256', $project.'|'.$crossing['domain'].'|'.$crossing['year']).'@sablier',
                'DTSTAMP:'.$stamp,
                'DTSTART;VALUE=DATE:'.$date,
                'DTEND;VALUE=DATE:'.\sprintf('%04d0102', $crossing['year']),
                'SUMMARY:'.self::escape(Lang::t('crossing.calendar.summary', $crossing['domain'], $project)),
                'DESCRIPTION:'.self::escape(Lang::t(
                    'crossing.calendar.description',
                    $crossing['domain'],
                    $crossing['lifetime'],
                    $analysis->declaration->expiryYear,
                )),
                'END:VEVENT',
            ];
        }

        $lines[] = 'END:VCALENDAR';

        return implode("\r\n", array_map(self::fold(...), $lines))."\r\n";
    }

    /** Harvestable, and broken by the machine the expiry date is about. */
    private static function harvestable(Finding $finding): bool
    {
        if ($finding->purpose !== Catalogue::PURPOSE_CONFIDENTIALITY) {
            return false;
        }

        $entry = Catalogue::get($finding->algorithm);

        return $entry !== null && $entry['quantum'];
    }

    /**
     * Fold at 75 octets, as the specification requires.
     *
     * Most calendars forgive a long line; a tool that spends its report
     * telling people to read the standard does not get to ignore one. The
     * split counts bytes and keeps UTF-8 sequences whole, because a folded
     * accent is a corrupted summary in somebody's calendar.
     */
    private static function fold(string $line): string
    {
        if (\strlen($line) <= 75) {
            return $line;
        }

        $out = '';
        $current = 0;
        foreach (preg_split('//u', $line, -1, \PREG_SPLIT_NO_EMPTY) ?: [] as $character) {
            $width = \strlen($character);
            // 74 plus the leading space of the next line: one octet of margin
            // beats a parser that counts differently.
            if ($current + $width > 74) {
                $out .= "\r\n ";
                $current = 1;
            }
            $out .= $character;
            $current += $width;
        }

        return $out;
    }

    /** iCalendar escaping: commas, semicolons, backslashes and newlines. */
    private static function escape(string $text): string
    {
        return str_replace(["\\", "\n", ',', ';'], ['\\\\', '\\n', '\\,', '\\;'], $text);
    }
}
