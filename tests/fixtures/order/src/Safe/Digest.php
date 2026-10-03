<?php

// Sound at every lifetime: no answer about this can change a verdict.
final class Digest
{
    public function of(string $payload): string { return hash('sha256', $payload); }
}
