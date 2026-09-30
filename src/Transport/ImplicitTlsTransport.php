<?php

declare(strict_types=1);

namespace Sablier\Transport;

/** TLS from the first byte: HTTPS, SMTPS, IMAPS, POP3S. */
final class ImplicitTlsTransport implements Transport
{
    private ?string $failure = null;

    public function failure(): ?string
    {
        return $this->failure;
    }

    public function open(string $host, int $port, $context, int $timeout)
    {
        $this->failure = null;
        $stream = @stream_socket_client("ssl://$host:$port", $errno, $error, $timeout, \STREAM_CLIENT_CONNECT, $context);
        if ($stream === false) {
            $this->failure = Failure::UNREACHABLE;

            return null;
        }

        return $stream;
    }

    public function startTlsFlag(): ?string
    {
        return null;
    }
}
