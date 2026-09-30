<?php

declare(strict_types=1);

namespace Sablier\Transport;

/** Why a probe could not reach a TLS state. */
final class Failure
{
    /** Nothing answered. Proves nothing about the service. */
    public const string UNREACHABLE = 'unreachable';

    /** The service answered and declined to encrypt: the session stayed in the clear. */
    public const string NO_UPGRADE = 'no_upgrade';

    /** The upgrade was accepted but the handshake itself failed. */
    public const string HANDSHAKE = 'handshake';
}
