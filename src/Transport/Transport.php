<?php

declare(strict_types=1);

namespace Sablier\Transport;

/**
 * How to reach the TLS layer of one kind of service.
 *
 * HTTPS hands you TLS the moment the socket opens. Mail and databases do not:
 * they speak in the clear first and are asked to upgrade. That difference is
 * not cosmetic — a server that refuses the upgrade, or an intermediary that
 * strips it, leaves the session in plaintext while every configuration file in
 * the repository claims otherwise. Only a dialogue finds that out.
 *
 * The project's third extension axis, and the reason this is an interface:
 * every protocol added from here is a new implementation, not an edit.
 */
interface Transport
{
    /**
     * Opens a connection and brings it to a TLS state, or returns null.
     *
     * @param resource $context
     *
     * @return resource|null
     */
    public function open(string $host, int $port, $context, int $timeout);

    /** What `openssl s_client -starttls` calls this protocol, if it needs it. */
    public function startTlsFlag(): ?string;

    /**
     * Why the last open() failed, or null if it did not.
     *
     * The distinction matters more than it looks: a host that does not answer
     * proves nothing, while a host that answers and then declines to encrypt is
     * a finding — the session stayed in plaintext, and every configuration file
     * in the repository may still claim otherwise.
     */
    public function failure(): ?string;
}
