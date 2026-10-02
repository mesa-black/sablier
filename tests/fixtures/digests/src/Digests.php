<?php

// Every line here was taken from a public repository during the false-positive
// measurement. The left column is what the tool must say about it.

final class Digests
{
    // NOISE — identity, not security.
    public function getHashCode(): string { return md5($this->serialised); }
    public function mutexName(): string { return 'framework/schedule-'.sha1($this->description); }
    public function cacheKey(array $options): string { $key = md5(json_encode($options)); return $key; }
    public function fileName(string $path): string { return md5($path).'.tmp'; }
    public function lockName(string $name): string { return sha1($name); }

    // URGENT — a broken digest doing security work.
    public function csrfToken(): string { return md5(uniqid(mt_rand(), true)); }
    public function keyFingerprint(string $publicKey): string { return md5(base64_decode($publicKey)); }
    public function derive(string $password, string $iv): string { return md5($password.$iv, true); }

    // CLEAR — HMAC is not its digest.
    public function legacyAuth(string $data, string $key): string { return hash_hmac('md5', $data, $key); }

    // Nothing at all: a mention in a comment.
    // This used to call hash_hmac('sha1', $data, $key) before the migration.
}
