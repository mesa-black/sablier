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

    // WATCH — a table of what a protocol obliges it to understand, not a use.
    public function macs(string $name): array
    {
        return match ($name) {
            'hmac-sha2-256' => [new Hash('sha256'), 32],
            'hmac-sha1', 'hmac-sha1-etm@openssh.com' => [new Hash('sha1'), 20],
            'hmac-md5'
                => [new Hash('md5'), 16],
            default => null,
        };
    }

    // Nothing at all: a mention in a comment.
    // This used to call hash_hmac('sha1', $data, $key) before the migration.
}
