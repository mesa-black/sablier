<?php

// CodeIgniter 4: properties rather than array keys.
class Encryption
{
    public string $driver = 'OpenSSL';
    public string $cipher = 'AES-256-CTR';
    public string $digest = 'SHA512';
}
