<?php

declare(strict_types=1);

namespace Sablier;

/**
 * When a document was produced, said in one zone.
 *
 * Every date in these documents used to come from the clock of the machine that
 * rendered them, in whatever zone it happened to be in — while the attested date
 * beside it says UTC, because that is what a timestamping authority answers. A
 * report rendered at half past midnight in Paris therefore printed one day in its
 * masthead and the day before in its seal, both correct and contradicting each
 * other on the page.
 *
 * So there is one zone for the whole document, it is named, and it is the one the
 * third party uses. A reader in Montréal and a reader in Tokyo then read the same
 * instant rather than two different days.
 *
 * The minute is printed as well as the day, and that is deliberate: this is the
 * moment a file was written, not an event with a date. A document that says only
 * the day invites being compared with another from the same day as though the two
 * were the same run.
 */
final class Rendered
{
    public static function at(): string
    {
        return self::now()->format('d/m/Y H:i').' UTC';
    }

    /**
     * The same instant, to the day.
     *
     * Used to compare the run against a date a third party attested, which is
     * printed to the minute and almost never falls in the same minute. The
     * question a reader asks of those two lines is whether they are the same
     * day, so that is the comparison the document makes.
     */
    public static function day(): string
    {
        return self::now()->format('d/m/Y');
    }

    private static function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }
}
