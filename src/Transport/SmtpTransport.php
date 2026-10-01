<?php

declare(strict_types=1);

namespace Sablier\Transport;

/** SMTP on 25 or 587: greeting, EHLO, STARTTLS. */
final class SmtpTransport extends StartTlsTransport
{
    public function startTlsFlag(): string
    {
        return 'smtp';
    }

    /** @param resource $stream */
    protected function negotiate(mixed $stream): bool
    {
        if (!str_starts_with($this->line($stream), '220')) {
            return false;
        }

        $this->send($stream, 'EHLO sablier.local');
        // EHLO answers over several lines; only the last one lacks the hyphen.
        do {
            $line = $this->line($stream);
            if ($line === '') {
                return false;
            }
        } while (isset($line[3]) && $line[3] === '-');

        $this->send($stream, 'STARTTLS');

        return str_starts_with($this->line($stream), '220');
    }
}
