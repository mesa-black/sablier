<?php
// What a checksum is for. None of this may produce a finding.
final class Integrity
{
    public function verifyDownload(string $path, int $expected): bool
    {
        return crc32(file_get_contents($path)) === $expected;
    }

    public function etagFor(string $contents): string
    {
        return hash('crc32b', $contents);
    }

    public function shard(string $sessionId, int $servers): int
    {
        return crc32($sessionId) % $servers;
    }

    public function authorBucket(string $author): int
    {
        return crc32($author) % 16;
    }

    // Links used to be signed with crc32($payload) before the migration.
}
