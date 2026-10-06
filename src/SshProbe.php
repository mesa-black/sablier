<?php

declare(strict_types=1);

namespace Sablier;

/**
 * What an SSH server offers, read from its own first packet.
 *
 * SSH never becomes TLS, so it does not fit the transport the rest of the
 * probe uses: there is no handshake to upgrade, only a banner and then a
 * KEXINIT listing everything the server is willing to do. That list is the
 * interesting part — it is where `sntrup761x25519-sha512@openssh.com` shows up,
 * which is a post-quantum key exchange somebody enabled on purpose and that no
 * file in the repository mentions.
 *
 * Nothing is negotiated here and nothing is authenticated: the probe sends a
 * banner, reads one packet and hangs up. It never offers a key, never tries a
 * password, and never gets far enough to be an authentication attempt — which
 * matters, because a tool that reads where the keys are has no business
 * knocking on doors.
 */
final class SshProbe
{
    private const int MSG_KEXINIT = 20;

    public function __construct(private readonly int $timeout = 8)
    {
    }

    /**
     * @return array{findings: list<Finding>, facts: array<string, string>, notes: list<string>}
     */
    public function run(string $host, int $port): array
    {
        $label = "ssh://$host:$port";
        $facts = [Lang::t('probe.fact.service') => 'SSH'];

        $stream = @stream_socket_client("tcp://$host:$port", $errno, $error, $this->timeout);
        if ($stream === false) {
            $facts[Lang::t('probe.fact.state')] = Lang::t('probe.no_connection', "$host:$port");

            return ['findings' => [], 'facts' => $facts, 'notes' => [Lang::t('probe.unreachable', "$host:$port")]];
        }

        stream_set_timeout($stream, $this->timeout);
        $banner = trim((string) fgets($stream, 512));
        fwrite($stream, "SSH-2.0-Sablier\r\n");
        $packet = $this->kexinit($stream);
        fclose($stream);

        if (!str_starts_with($banner, 'SSH-2.0') || $packet === null) {
            $facts[Lang::t('probe.fact.state')] = Lang::t('probe.ssh.no_kexinit');

            return ['findings' => [], 'facts' => $facts, 'notes' => [Lang::t('probe.ssh.no_kexinit')]];
        }

        $facts[Lang::t('probe.ssh.banner')] = $banner;
        $lists = $this->nameLists($packet);
        $kex = $lists[0] ?? '';
        $hostKeys = $lists[1] ?? '';
        $ciphers = $lists[2] ?? '';

        $facts[Lang::t('probe.ssh.kex')] = $kex === '' ? '?' : $kex;
        $facts[Lang::t('probe.ssh.host_keys')] = $hostKeys === '' ? '?' : $hostKeys;
        if ($ciphers !== '') {
            $facts[Lang::t('probe.ssh.ciphers')] = $ciphers;
        }

        $findings = [];
        $hybrid = $this->mentions($kex, 'sntrup', 'mlkem', 'kyber');
        $findings[] = new Finding(
            algorithm: $hybrid ? 'ml-kem' : 'ecdh',
            purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
            file: $label,
            line: 0,
            // `kex` and `hostkey` are SSH's own field names, so they read the
            // same in every language — and the evidence is what a fingerprint is
            // hashed from, so it cannot be a translated sentence. See the same
            // fix in Probe and AssetDetector.
            evidence: 'kex · '.$this->first($kex),
            detail: Lang::t($hybrid ? 'probe.ssh.detail.hybrid' : 'probe.ssh.detail.classical'),
        );

        // The host key is what a client pins. It is a signature, so it is not
        // harvested — and it is also the thing every machine in the fleet has
        // trusted for years, which is the definition of a long-lived anchor.
        $algorithm = match (true) {
            $this->mentions($hostKeys, 'ssh-ed25519') => 'ed25519',
            $this->mentions($hostKeys, 'ecdsa-sha2') => 'ecdsa',
            default => 'rsa-sign',
        };
        $findings[] = new Finding(
            algorithm: $algorithm,
            purpose: Catalogue::PURPOSE_AUTHENTICITY,
            file: $label,
            line: 0,
            evidence: 'hostkey · '.$this->first($hostKeys),
            detail: Lang::t('probe.ssh.detail.host_key'),
        );

        return ['findings' => $findings, 'facts' => $facts, 'notes' => []];
    }

    /**
     * The first binary packet, which by the protocol is the server's KEXINIT.
     *
     * @param resource $stream
     */
    private function kexinit(mixed $stream): ?string
    {
        $header = (string) fread($stream, 5);
        if (\strlen($header) < 5) {
            return null;
        }

        $length = self::uint32($header);
        $padding = \ord($header[4]);
        // A KEXINIT is a few hundred bytes; anything else is not one, and
        // reading a length somebody else chose is how a parser becomes a
        // denial of service.
        if ($length < 10 || $length > 65536) {
            return null;
        }

        $body = '';
        $remaining = $length - 1;
        while ($remaining > 0 && !feof($stream)) {
            $chunk = fread($stream, $remaining);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $body .= $chunk;
            $remaining -= \strlen($chunk);
        }

        if ($body === '' || \ord($body[0]) !== self::MSG_KEXINIT) {
            return null;
        }

        // Message type, then 16 bytes of cookie, then the name-lists; the
        // padding at the end is noise.
        return substr($body, 17, max(0, \strlen($body) - 17 - $padding));
    }

    /**
     * The name-lists, each a 32-bit length followed by a comma-separated string.
     *
     * @return list<string>
     */
    private function nameLists(string $payload): array
    {
        $lists = [];
        $offset = 0;
        while ($offset + 4 <= \strlen($payload) && \count($lists) < 4) {
            $length = self::uint32(substr($payload, $offset, 4));
            $offset += 4;
            if ($offset + $length > \strlen($payload)) {
                break;
            }
            $lists[] = substr($payload, $offset, $length);
            $offset += $length;
        }

        return $lists;
    }

    /** A big-endian 32-bit length, which is how SSH measures everything. */
    private static function uint32(string $bytes): int
    {
        $unpacked = unpack('N', $bytes);

        return \is_array($unpacked) ? Value::int($unpacked[1] ?? null) : 0;
    }

    private function mentions(string $list, string ...$needles): bool
    {
        foreach ($needles as $needle) {
            if (str_contains(strtolower($list), $needle)) {
                return true;
            }
        }

        return false;
    }

    /** The server's own first choice, which is the one it prefers. */
    private function first(string $list): string
    {
        return explode(',', $list)[0] ?: '?';
    }
}
