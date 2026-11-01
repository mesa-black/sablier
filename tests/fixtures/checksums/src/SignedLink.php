<?php
// The control: the same link, keyed.
final class SignedLink
{
    public function __construct(private string $secret) {}

    public function sign(string $payload): string
    {
        return $payload.'|'.hash_hmac('sha256', $payload, $this->secret);
    }
}
