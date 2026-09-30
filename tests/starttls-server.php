<?php

declare(strict_types=1);

/*
 * A minimal STARTTLS server, for the test suite only.
 *
 * Testing the mail dialogues against somebody's real mail server is neither
 * necessary nor polite, and `openssl s_server` does not speak STARTTLS. Twenty
 * lines of PHP do.
 *
 *   php tests/starttls-server.php smtp 14587 cert.pem key.pem
 */

[$protocol, $port, $cert, $key] = [$argv[1], (int) $argv[2], $argv[3], $argv[4]];

$context = stream_context_create(['ssl' => [
    'local_cert' => $cert,
    'local_pk' => $key,
    'allow_self_signed' => true,
    'verify_peer' => false,
]]);

$server = stream_socket_server("tcp://127.0.0.1:$port", $errno, $error, \STREAM_SERVER_BIND | \STREAM_SERVER_LISTEN, $context);
if ($server === false) {
    exit("server failed: $error\n");
}

$client = stream_socket_accept($server, 10);
if ($client === false) {
    exit("no client\n");
}

$read = static fn (): string => (string) fgets($client, 4096);
$write = static function (string $line) use ($client): void { fwrite($client, $line."\r\n"); };

match ($protocol) {
    'smtp' => (static function () use ($read, $write): void {
        $write('220 sablier test ESMTP');
        $read();                       // EHLO
        $write('250-sablier');
        $write('250 STARTTLS');
        $read();                       // STARTTLS
        $write('220 go ahead');
    })(),
    'imap' => (static function () use ($read, $write): void {
        $write('* OK sablier test IMAP');
        $read();                       // a001 STARTTLS
        $write('a001 OK begin TLS');
    })(),
    'pop3' => (static function () use ($read, $write): void {
        $write('+OK sablier test POP3');
        $read();                       // STLS
        $write('+OK begin TLS');
    })(),
};

stream_socket_enable_crypto($client, true, \STREAM_CRYPTO_METHOD_TLS_SERVER);
sleep(1);
fclose($client);
fclose($server);
