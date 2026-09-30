<?php

declare(strict_types=1);

namespace Sablier\Transport;

/** POP3 on 110. */
final class Pop3Transport extends StartTlsTransport
{
    public function startTlsFlag(): ?string
    {
        return 'pop3';
    }

    protected function negotiate(mixed $stream): bool
    {
        if (!str_starts_with($this->line($stream), '+OK')) {
            return false;
        }

        $this->send($stream, 'STLS');

        return str_starts_with($this->line($stream), '+OK');
    }
}
