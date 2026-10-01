<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Message catalogue.
 *
 * Everything a reader sees goes through here. Nothing else in the codebase
 * holds a sentence, which is the only way a three-language tool stays
 * translated after the third change.
 */
final class Lang
{
    public const array AVAILABLE = ['fr', 'en', 'es'];
    private const string FALLBACK = 'fr';

    private static string $locale = self::FALLBACK;

    /** @var array<string, array<string, string>> */
    private static array $loaded = [];

    public static function use(string $locale): void
    {
        self::$locale = \in_array($locale, self::AVAILABLE, true) ? $locale : self::FALLBACK;
    }

    public static function locale(): string
    {
        return self::$locale;
    }

    /** A missing key returns the key itself: a visible gap beats a silent empty string. */
    public static function t(string $key, int|float|string ...$args): string
    {
        $messages = self::messages(self::$locale);
        $message = $messages[$key] ?? self::messages(self::FALLBACK)[$key] ?? $key;

        return $args === [] ? $message : \sprintf($message, ...$args);
    }

    public static function has(string $key): bool
    {
        return isset(self::messages(self::$locale)[$key]) || isset(self::messages(self::FALLBACK)[$key]);
    }

    /** @return array<string, string> */
    private static function messages(string $locale): array
    {
        if (!isset(self::$loaded[$locale])) {
            $file = __DIR__.'/../translations/'.$locale.'.php';
            /** @var array<string, string> $messages */
            $messages = is_file($file) ? require $file : [];
            self::$loaded[$locale] = $messages;
        }

        return self::$loaded[$locale];
    }
}
