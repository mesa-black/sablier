<?php

declare(strict_types=1);

namespace Sablier\Web;

use Sablier\Value;

/**
 * The state of one interview, between two clicks.
 *
 * A file in the temporary directory rather than a PHP session: the whole thing
 * lives for the length of a conversation, on one machine, for one person, and
 * a cookie would be one more moving part in something that has to work the
 * first time in front of a client.
 *
 * Nothing in here is secret — the subjects came from the project, and the
 * answers are about to be written into a versioned file anyway — but it is
 * still deleted when the server stops, because leaving state behind is a habit
 * this project does not want.
 */
final class Session
{
    private function __construct(
        public readonly string $path,
        /** @var array<string, mixed> */
        public array $data,
    ) {
    }

    /** @param array<string, mixed> $initial */
    public static function create(string $path, array $initial): self
    {
        $session = new self($path, $initial);
        $session->save();

        return $session;
    }

    public static function open(string $path): ?self
    {
        if (!is_file($path)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        $data = Value::map(json_decode((string) file_get_contents($path), true));

        return $data === [] ? null : new self($path, $data);
    }

    public function save(): void
    {
        file_put_contents($this->path, json_encode($this->data, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE));
    }

    public function string(string $key, string $default = ''): string
    {
        return Value::string($this->data[$key] ?? null, $default);
    }

    public function int(string $key, int $default = 0): int
    {
        return Value::int($this->data[$key] ?? null, $default);
    }

    /** @return array<array-key, mixed> */
    public function map(string $key): array
    {
        return Value::map($this->data[$key] ?? null);
    }

    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
        $this->save();
    }
}
