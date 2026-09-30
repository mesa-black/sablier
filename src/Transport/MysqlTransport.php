<?php

declare(strict_types=1);

namespace Sablier\Transport;

/**
 * MySQL and MariaDB on 3306.
 *
 * The server speaks first, and its greeting says whether TLS is even offered.
 * Reading that flag before asking is what separates "the server refused" from
 * "the server was never built for it" — two very different sentences in a
 * report.
 */
final class MysqlTransport extends StartTlsTransport
{
    private const int CLIENT_SSL = 0x0800;
    private const int CLIENT_PROTOCOL_41 = 0x0200;
    private const int CLIENT_SECURE_CONNECTION = 0x8000;

    public function startTlsFlag(): ?string
    {
        return 'mysql';
    }

    protected function negotiate(mixed $stream): bool
    {
        $header = (string) fread($stream, 4);
        if (\strlen($header) < 4) {
            return false;
        }

        // 3-byte little-endian length, then a sequence number we answer with +1.
        $length = \ord($header[0]) | (\ord($header[1]) << 8) | (\ord($header[2]) << 16);
        $greeting = (string) fread($stream, $length);
        if (!$this->offersTls($greeting)) {
            return false;
        }

        $payload = pack('V', self::CLIENT_SSL | self::CLIENT_PROTOCOL_41 | self::CLIENT_SECURE_CONNECTION)
            .pack('V', 16_777_216)   // maximum packet size
            .\chr(45)                // utf8mb4
            .str_repeat("\0", 23);   // reserved

        fwrite($stream, \chr(\strlen($payload))."\0\0".\chr(\ord($header[3]) + 1).$payload);

        return true;
    }

    /** Capability flags sit after the version string, the thread id and the first salt. */
    private function offersTls(string $greeting): bool
    {
        $endOfVersion = strpos($greeting, "\0", 1);
        if ($endOfVersion === false) {
            return false;
        }

        $offset = $endOfVersion + 1 + 4 + 8 + 1; // thread id, salt part 1, filler
        if (\strlen($greeting) < $offset + 2) {
            return false;
        }

        $capabilities = \ord($greeting[$offset]) | (\ord($greeting[$offset + 1]) << 8);

        return ($capabilities & self::CLIENT_SSL) !== 0;
    }
}
