<?php

declare(strict_types=1);

namespace Sablier\Transport;

/**
 * Connect in the clear, ask for the upgrade, then turn on TLS.
 *
 * The upgrade is the interesting moment: it is where a session silently stays
 * in plaintext when a server declines or an intermediary interferes.
 */
abstract class StartTlsTransport implements Transport
{
    private ?string $failure = null;

    public function failure(): ?string
    {
        return $this->failure;
    }

    /** Runs the protocol's own dialogue up to the point TLS can start. */
    abstract protected function negotiate(mixed $stream): bool;

    public function open(string $host, int $port, $context, int $timeout)
    {
        $this->failure = null;
        $stream = @stream_socket_client("tcp://$host:$port", $errno, $error, $timeout, \STREAM_CLIENT_CONNECT, $context);
        if ($stream === false) {
            $this->failure = Failure::UNREACHABLE;

            return null;
        }

        stream_set_timeout($stream, $timeout);

        // The version probe forces one TLS version through the context; read it
        // back here so a STARTTLS service is tested exactly like an implicit one.
        $options = stream_context_get_options($context)['ssl'] ?? [];
        $method = (int) ($options['crypto_method'] ?? \STREAM_CRYPTO_METHOD_TLS_CLIENT);

        // Answering and then declining the upgrade is the interesting failure:
        // the service is reachable and the session is in plaintext.
        if (!$this->negotiate($stream)) {
            $this->failure = Failure::NO_UPGRADE;
            fclose($stream);

            return null;
        }

        if (@stream_socket_enable_crypto($stream, true, $method) !== true) {
            $this->failure = Failure::HANDSHAKE;
            fclose($stream);

            return null;
        }

        return $stream;
    }

    /** @param resource $stream */
    protected function line(mixed $stream): string
    {
        return (string) fgets($stream, 4096);
    }

    /** @param resource $stream */
    protected function send(mixed $stream, string $command): void
    {
        fwrite($stream, $command."\r\n");
    }
}
