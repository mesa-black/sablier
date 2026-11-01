<?php
// Password-reset link "signed" with a checksum.
final class ResetLink
{
    public function build(int $userId, int $expires): string
    {
        $payload = $userId.'|'.$expires;
        return $payload.'|'.crc32($payload);
    }

    public function verify(string $link): bool
    {
        [$userId, $expires, $sum] = explode('|', $link);
        return (string) crc32($userId.'|'.$expires) === $sum && $expires > time();
    }

    public function checksum(string $resetToken): string
    {
        return md5($resetToken);
    }

    public function verifyAuthTokenChecksum(string $authToken, string $sum): bool
    {
        return hash('crc32b', $authToken) === $sum;
    }
}
