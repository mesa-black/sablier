<?php

declare(strict_types=1);

namespace Sablier\Transport;

/** IMAP on 143. */
final class ImapTransport extends StartTlsTransport
{
    public function startTlsFlag(): string
    {
        return 'imap';
    }

    /** @param resource $stream */
    protected function negotiate(mixed $stream): bool
    {
        if (!str_starts_with($this->line($stream), '* OK')) {
            return false;
        }

        $this->send($stream, 'a001 STARTTLS');

        return str_starts_with($this->line($stream), 'a001 OK');
    }
}
