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
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('d/m/Y H:i').' UTC';
    }
}
