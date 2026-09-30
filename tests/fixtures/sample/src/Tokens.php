<?php
// Fixture: token signing and digests.
final class Tokens
{
    public function sign(array $claims): string
    {
        return jwt_encode($claims, $this->key, 'RS256');
    }

    public function cacheKey(string $url): string
    {
        return md5($url); // cache key: not a security control
    }

    public function legacyDigest(string $payload): string
    {
        return sha1($payload);
    }

    public function seal(string $plain, string $key): string
    {
        return openssl_encrypt($plain, 'aes-256-gcm', $key, 0, random_bytes(12));
    }
}
