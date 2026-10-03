<?php

// A patient record sealed with RSA: twenty years of legal retention against an
// algorithm the regime retires in 2030.
final class Record
{
    public function seal(string $dossier, string $publicKey): string
    {
        openssl_public_encrypt($dossier, $sealed, $publicKey);

        return $sealed;
    }
}
