<?php

declare(strict_types=1);

namespace Sablier\Transport;

/**
 * PostgreSQL on 5432.
 *
 * Its upgrade is two packets and one byte of answer, which makes it the easiest
 * database to check and the one most often left unchecked: `sslmode=prefer`,
 * the historical default of several clients, falls back to plaintext without a
 * word when the server answers no.
 */
final class PostgresTransport extends StartTlsTransport
{
    /** The magic number every PostgreSQL client sends to ask for TLS. */
    private const int SSL_REQUEST_CODE = 80877103;

    public function startTlsFlag(): string
    {
        return 'postgres';
    }

    /** @param resource $stream */
    protected function negotiate(mixed $stream): bool
    {
        // Length-prefixed message: eight bytes in total, and the request code.
        fwrite($stream, pack('NN', 8, self::SSL_REQUEST_CODE));

        return fread($stream, 1) === 'S';
    }
}
