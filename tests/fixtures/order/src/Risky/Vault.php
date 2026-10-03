<?php

// Harvestable: the answer here decides whether the report turns red.
final class Vault
{
    public function seal(string $secret, string $publicKey): string
    {
        openssl_public_encrypt($secret, $sealed, $publicKey);

        return $sealed;
    }
}
