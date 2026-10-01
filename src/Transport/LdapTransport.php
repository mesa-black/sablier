<?php

declare(strict_types=1);

namespace Sablier\Transport;

/**
 * LDAP on 389, upgraded by an extended operation rather than a keyword.
 *
 * Where SMTP says STARTTLS in ASCII, LDAP sends a BER-encoded extended request
 * carrying OID 1.3.6.1.4.1.1466.20037. The bytes below are that request, built
 * once and never varying: there is one message to send and the directory either
 * agrees or it does not.
 *
 * It matters because a directory holds the credentials of everybody in the
 * organisation, and an LDAP bind that stays in cleartext hands them out one
 * authentication at a time.
 */
final class LdapTransport extends StartTlsTransport
{
    /**
     * The StartTLS extended request, message id 1.
     *
     * 30 1d — sequence, 29 bytes
     *   02 01 01 — integer, message id 1
     *   77 18 — application 23, extended request
     *     80 16 — context 0, the OID as a string
     *       "1.3.6.1.4.1.1466.20037"
     */
    private const string REQUEST = "\x30\x1d\x02\x01\x01\x77\x18\x80\x16".'1.3.6.1.4.1.1466.20037';

    public function startTlsFlag(): string
    {
        return 'ldap';
    }

    /** @param resource $stream */
    protected function negotiate(mixed $stream): bool
    {
        fwrite($stream, self::REQUEST);
        $answer = (string) fread($stream, 64);

        // An extended response whose result code is 0. Byte 0 opens the
        // sequence, and the success code sits in the enumerated that follows
        // the response tag — looking for the pair is enough to tell an
        // agreement from a refusal without writing a BER parser.
        return str_starts_with($answer, "\x30") && str_contains($answer, "\x0a\x01\x00");
    }
}
