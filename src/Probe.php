<?php

declare(strict_types=1);

namespace Sablier;

use Sablier\Transport\Failure;
use Sablier\Transport\ImapTransport;
use Sablier\Transport\ImplicitTlsTransport;
use Sablier\Transport\MysqlTransport;
use Sablier\Transport\Pop3Transport;
use Sablier\Transport\PostgresTransport;
use Sablier\Transport\SmtpTransport;
use Sablier\Transport\Transport;

/**
 * What a real server actually negotiates — the biggest blind spot of static
 * analysis, and the only place the post-quantum question gets a live answer.
 *
 * A repository declares an intention; a handshake states a fact. The two
 * disagree often enough that reporting only the first is misleading: a project
 * with no PQC anywhere in its code can already be protected by its CDN, and a
 * project that configured everything correctly can be terminated by an
 * intermediary that undoes it.
 *
 * This is an ordinary TLS handshake, the same one a browser performs. It still
 * only belongs against hosts you are responsible for.
 */
final class Probe
{
    /** Key exchange groups that already resist a quantum adversary. */
    private const array HYBRID_GROUPS = ['mlkem', 'kyber', 'x25519mlkem', 'p256mlkem', 'secp256r1mlkem'];

    /**
     * Services the probe knows, by default port. The scheme wins when given, so
     * a service on an unusual port is still reachable: `smtp://mx.example:2525`.
     *
     * @var array<int, array{scheme:string, label:string, transport:class-string<Transport>}>
     */
    private const array BY_PORT = [
        443 => ['scheme' => 'tls', 'label' => 'HTTPS', 'transport' => ImplicitTlsTransport::class],
        465 => ['scheme' => 'smtps', 'label' => 'SMTPS', 'transport' => ImplicitTlsTransport::class],
        993 => ['scheme' => 'imaps', 'label' => 'IMAPS', 'transport' => ImplicitTlsTransport::class],
        995 => ['scheme' => 'pop3s', 'label' => 'POP3S', 'transport' => ImplicitTlsTransport::class],
        25 => ['scheme' => 'smtp', 'label' => 'SMTP', 'transport' => SmtpTransport::class],
        587 => ['scheme' => 'smtp', 'label' => 'SMTP', 'transport' => SmtpTransport::class],
        143 => ['scheme' => 'imap', 'label' => 'IMAP', 'transport' => ImapTransport::class],
        110 => ['scheme' => 'pop3', 'label' => 'POP3', 'transport' => Pop3Transport::class],
        5432 => ['scheme' => 'postgres', 'label' => 'PostgreSQL', 'transport' => PostgresTransport::class],
        3306 => ['scheme' => 'mysql', 'label' => 'MySQL / MariaDB', 'transport' => MysqlTransport::class],
    ];

    /** @var array<string, array{port:int, label:string, transport:class-string<Transport>}> */
    private const array BY_SCHEME = [
        'https' => ['port' => 443, 'label' => 'HTTPS', 'transport' => ImplicitTlsTransport::class],
        'tls' => ['port' => 443, 'label' => 'HTTPS', 'transport' => ImplicitTlsTransport::class],
        'smtps' => ['port' => 465, 'label' => 'SMTPS', 'transport' => ImplicitTlsTransport::class],
        'imaps' => ['port' => 993, 'label' => 'IMAPS', 'transport' => ImplicitTlsTransport::class],
        'pop3s' => ['port' => 995, 'label' => 'POP3S', 'transport' => ImplicitTlsTransport::class],
        'smtp' => ['port' => 587, 'label' => 'SMTP', 'transport' => SmtpTransport::class],
        'imap' => ['port' => 143, 'label' => 'IMAP', 'transport' => ImapTransport::class],
        'pop3' => ['port' => 110, 'label' => 'POP3', 'transport' => Pop3Transport::class],
        'postgres' => ['port' => 5432, 'label' => 'PostgreSQL', 'transport' => PostgresTransport::class],
        'postgresql' => ['port' => 5432, 'label' => 'PostgreSQL', 'transport' => PostgresTransport::class],
        'mysql' => ['port' => 3306, 'label' => 'MySQL / MariaDB', 'transport' => MysqlTransport::class],
        'mariadb' => ['port' => 3306, 'label' => 'MySQL / MariaDB', 'transport' => MysqlTransport::class],
    ];

    public function __construct(private readonly int $timeout = 8)
    {
    }

    /**
     * @return array{findings: list<Finding>, facts: array<string, string>, notes: list<string>}
     */
    public function run(string $target): array
    {
        $service = $this->resolve($target);
        $host = $service['host'];
        $port = $service['port'];
        $transport = $service['transport'];
        $label = "{$service['scheme']}://$host:$port";
        $facts = [];
        $notes = [];
        $findings = [];

        $session = $this->connect($host, $port, $transport);
        if ($session === null) {
            $facts[Lang::t('probe.fact.service')] = $service['label'];

            // A service that answers and then refuses to encrypt is a finding,
            // not an absent host: the session stayed readable on the wire.
            if ($transport->failure() === Failure::NO_UPGRADE) {
                $facts[Lang::t('probe.fact.state')] = Lang::t('probe.state.plaintext');

                return [
                    'findings' => [new Finding(
                        algorithm: 'plaintext',
                        purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                        file: $label,
                        line: 0,
                        evidence: Lang::t('probe.evidence.no_upgrade', $service['label']),
                        detail: Lang::t('probe.detail.no_upgrade'),
                    )],
                    'facts' => $facts,
                    'notes' => [],
                ];
            }

            $facts[Lang::t('probe.fact.state')] = Lang::t('probe.no_connection', "$host:$port");

            return ['findings' => [], 'facts' => $facts, 'notes' => [Lang::t('probe.unreachable', "$host:$port")]];
        }

        $facts[Lang::t('probe.fact.service')] = $service['label'];
        $facts[Lang::t('probe.fact.protocol')] = $session['protocol'];
        $facts[Lang::t('probe.fact.cipher')] = $session['cipher'].' ('.$session['bits'].' '.Lang::t('unit.bits').')';

        // --- Key exchange: the harvestable part of a TLS session ------------
        $group = $this->negotiatedGroup($host, $port, $transport);
        if ($group === null) {
            $notes[] = Lang::t('probe.note.no_group');
            $findings[] = new Finding(
                algorithm: 'ecdh', purpose: Catalogue::PURPOSE_CONFIDENTIALITY, file: $label, line: 0,
                evidence: $session['protocol'].' — '.$session['cipher'],
                confidence: Finding::CONFIDENCE_MEDIUM,
                detail: Lang::t('probe.detail.assumed_classical'),
            );
        } else {
            $facts[Lang::t('probe.fact.group')] = $group;
            $hybrid = $this->isHybrid($group);
            $findings[] = new Finding(
                algorithm: $hybrid ? 'ml-kem' : 'ecdh',
                purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                file: $label, line: 0,
                evidence: Lang::t('probe.evidence.group', $group),
                detail: $hybrid
                    ? Lang::t('probe.detail.hybrid')
                    : Lang::t('probe.detail.classical'),
            );
        }

        // --- Certificate: authenticity, and its own clock -------------------
        if ($session['cert'] !== null) {
            $sig = Value::string($session['cert']['signatureTypeSN'] ?? null, '?');
            $facts[Lang::t('probe.fact.cert_signature')] = $sig;
            $facts[Lang::t('probe.fact.cert_key')] = $session['keyLabel'];
            $facts[Lang::t('probe.fact.chain')] = $session['chain'].' '.Lang::t('probe.certificates');
            $facts[Lang::t('probe.fact.valid_until')] = $session['validTo'];

            $findings[] = new Finding(
                algorithm: str_contains(strtoupper($sig), 'ECDSA') ? 'ecdsa' : 'rsa-sign',
                purpose: Catalogue::PURPOSE_AUTHENTICITY,
                file: $label, line: 0,
                evidence: Lang::t('probe.evidence.cert', $sig, $session['keyLabel']),
                detail: Lang::t('probe.detail.certificate'),
            );
        }

        // --- Obsolete protocol versions -------------------------------------
        $versions = $this->supportedVersions($host, $port, $transport);
        $facts[Lang::t('probe.fact.versions')] = implode(', ', $versions['accepted']) ?: Lang::t('probe.unknown');
        foreach ($versions['accepted'] as $version) {
            if (\in_array($version, ['TLSv1.0', 'TLSv1.1'], true)) {
                $findings[] = new Finding(
                    algorithm: 'tls-obsolete', purpose: Catalogue::PURPOSE_CONFIDENTIALITY, file: $label, line: 0,
                    evidence: Lang::t('probe.evidence.version_accepted', $version),
                    detail: Lang::t('probe.detail.obsolete_version'),
                );
            }
        }
        if ($versions['untestable'] !== []) {
            $notes[] = Lang::t('probe.note.untestable', implode(', ', $versions['untestable']));
        }

        return ['findings' => $findings, 'facts' => $facts, 'notes' => $notes];
    }

    /**
     * @return array{host:string, port:int, label:string, scheme:string, transport:Transport}
     */
    private function resolve(string $target): array
    {
        $target = rtrim(trim($target), '/');
        $scheme = '';
        if (preg_match('#^([a-z0-9+]+)://#i', $target, $m) === 1) {
            $scheme = strtolower($m[1]);
            $target = substr($target, \strlen($m[0]));
        }

        $port = 0;
        if (preg_match('/^(.+):(\d+)$/', $target, $m) === 1) {
            $target = $m[1];
            $port = (int) $m[2];
        }

        // The scheme wins when given, so a service on an unusual port stays
        // reachable; otherwise the port decides; otherwise it is HTTPS.
        $service = self::BY_SCHEME[$scheme] ?? null;
        if ($service !== null) {
            $port = $port !== 0 ? $port : $service['port'];
        } else {
            $service = self::BY_PORT[$port] ?? self::BY_PORT[443];
            $port = $port !== 0 ? $port : 443;
            $scheme = $service['scheme'];
        }

        $transportClass = $service['transport'];

        return [
            'host' => $target,
            'port' => $port,
            'label' => $service['label'],
            'scheme' => $scheme !== '' ? $scheme : 'tls',
            'transport' => new $transportClass(),
        ];
    }

    /** @return array{protocol:string, cipher:string, bits:int, cert:array<array-key, mixed>|null, keyLabel:string, chain:int, validTo:string}|null */
    private function connect(string $host, int $port, Transport $transport): ?array
    {
        $context = stream_context_create(['ssl' => [
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'SNI_enabled' => true,
            'peer_name' => $host,
        ]]);

        $stream = $transport->open($host, $port, $context, $this->timeout);
        if ($stream === null) {
            return null;
        }

        $crypto = Value::map(Value::map(stream_get_meta_data($stream))['crypto'] ?? null);
        $options = Value::map(Value::map(stream_context_get_options($context))['ssl'] ?? null);
        fclose($stream);

        // The captured certificate is an OpenSSL object, not a value we can
        // coerce: anything else in that slot means the capture did not happen.
        $peer = $options['peer_certificate'] ?? null;
        $parsed = $peer instanceof \OpenSSLCertificate ? openssl_x509_parse($peer) : false;
        $cert = \is_array($parsed) ? $parsed : null;

        $keyLabel = Lang::t('probe.unknown');
        $validTo = '?';
        if ($peer instanceof \OpenSSLCertificate) {
            $publicKey = @openssl_pkey_get_public($peer);
            $details = $publicKey instanceof \OpenSSLAsymmetricKey ? @openssl_pkey_get_details($publicKey) : false;
            if (\is_array($details)) {
                $bits = Value::int($details['bits'] ?? null);
                $keyLabel = match (Value::int($details['type'] ?? null, -1)) {
                    \OPENSSL_KEYTYPE_RSA => 'RSA '.$bits.' '.Lang::t('unit.bits'),
                    \OPENSSL_KEYTYPE_EC => Lang::t('probe.elliptic_curve').' '.$bits.' '.Lang::t('unit.bits'),
                    default => $bits.' '.Lang::t('unit.bits'),
                };
            }
            $validTo = isset($cert['validTo_time_t']) ? date('d/m/Y', Value::int($cert['validTo_time_t'])) : '?';
        }

        return [
            'protocol' => Value::string($crypto['protocol'] ?? null, '?'),
            'cipher' => Value::string($crypto['cipher_name'] ?? null, '?'),
            'bits' => Value::int($crypto['cipher_bits'] ?? null),
            'cert' => $cert,
            'keyLabel' => $keyLabel,
            'chain' => \count(Value::map($options['peer_certificate_chain'] ?? null)),
            'validTo' => $validTo,
        ];
    }

    /**
     * The negotiated group is not exposed by PHP's stream layer, so this asks
     * the openssl binary when it is available — and says so when it is not,
     * rather than silently dropping the most important field of the report.
     */
    private function negotiatedGroup(string $host, int $port, Transport $transport): ?string
    {
        $binary = trim((string) @shell_exec('command -v openssl 2>/dev/null'));
        if ($binary === '') {
            return null;
        }

        $startTls = $transport->startTlsFlag();
        $command = \sprintf(
            'echo | %s s_client -connect %s -servername %s %s 2>/dev/null',
            escapeshellarg($binary),
            escapeshellarg("$host:$port"),
            escapeshellarg($host),
            $startTls === null ? '' : '-starttls '.escapeshellarg($startTls),
        );
        $output = (string) @shell_exec($command);

        // Three spellings for one fact, because the label depends on the
        // OpenSSL build and on the negotiated version. Missing one of them does
        // not fail loudly — it silently drops the most important field of the
        // probe, which is how this was found: only by pointing the tool at a
        // server we controlled.
        foreach ([
            '/Negotiated TLS1\.3 group:\s*(\S+)/i',
            '/(?:Server|Peer) Temp Key:\s*([^\n]+)/i',
        ] as $pattern) {
            if (preg_match($pattern, $output, $m) === 1) {
                return self::groupName(trim($m[1]));
            }
        }

        return null;
    }

    /**
     * "ECDH, prime256v1, 256 bits" names a family, a curve and a size. The curve
     * is the part that matters — "ECDH" alone would hide whether the peer is on
     * a classical curve or on a hybrid group.
     */
    private static function groupName(string $raw): string
    {
        $parts = array_map(trim(...), explode(',', $raw));
        if (\count($parts) > 1 && \in_array(strtoupper($parts[0]), ['ECDH', 'DH', 'ECDHE', 'X25519'], true)) {
            return $parts[1];
        }

        return $parts[0];
    }

    private function isHybrid(string $group): bool
    {
        $normalised = strtolower(str_replace(['-', '_'], '', $group));
        foreach (self::HYBRID_GROUPS as $marker) {
            if (str_contains($normalised, $marker)) {
                return true;
            }
        }

        return false;
    }

    /** Whether the local OpenSSL will still propose a given version at all. */
    private static function locallyOffered(int $method): bool
    {
        /** @var array<int, bool> $cache */
        static $cache = [];

        return $cache[$method] ??= (static function () use ($method): bool {
            $server = @stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
            if ($server === false) {
                return true; // Cannot tell: do not claim the version is untestable.
            }
            $name = (string) stream_socket_get_name($server, false);
            $context = stream_context_create(['ssl' => ['crypto_method' => $method, 'verify_peer' => false, 'verify_peer_name' => false]]);
            $client = @stream_socket_client('tcp://'.$name, $errno, $error, 1, \STREAM_CLIENT_CONNECT, $context);
            if ($client !== false) {
                @stream_socket_enable_crypto($client, true, $method);
                fclose($client);
            }
            fclose($server);

            return stripos((string) $error, 'no protocols available') === false
                && stripos((string) $error, 'unsupported protocol') === false;
        })();
    }

    /** @return array{accepted: list<string>, untestable: list<string>} */
    private function supportedVersions(string $host, int $port, Transport $transport): array
    {
        $methods = [
            'TLSv1.0' => \STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT,
            'TLSv1.1' => \STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT,
            'TLSv1.2' => \STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT,
            'TLSv1.3' => \STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
        ];

        $accepted = [];
        $untestable = [];
        foreach ($methods as $version => $method) {
            $context = stream_context_create(['ssl' => [
                'crypto_method' => $method,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'peer_name' => $host,
            ]]);
            $stream = $transport->open($host, $port, $context, $this->timeout);
            if ($stream !== null) {
                $accepted[] = $version;
                fclose($stream);
                continue;
            }
            // Distinguish "the server said no" from "our own OpenSSL refused to
            // ask". The transport swallows the error string, so the local
            // refusal is detected by asking OpenSSL whether it still offers it.
            if (!self::locallyOffered($method)) {
                $untestable[] = $version;
            }
        }

        return ['accepted' => $accepted, 'untestable' => $untestable];
    }
}
