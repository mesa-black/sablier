<?php

declare(strict_types=1);

namespace Sablier;

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

    public function __construct(private readonly int $timeout = 8)
    {
    }

    /**
     * @return array{findings: list<Finding>, facts: array<string, string>, notes: list<string>}
     */
    public function run(string $target): array
    {
        [$host, $port] = $this->split($target);
        $label = "tls://$host:$port";
        $facts = [];
        $notes = [];
        $findings = [];

        $session = $this->connect($host, $port);
        if ($session === null) {
            return [
                'findings' => [],
                'facts' => ['état' => Lang::t('probe.no_connection', "$host:$port")],
                'notes' => [Lang::t('probe.unreachable', "$host:$port")],
            ];
        }

        $facts[Lang::t('probe.fact.protocol')] = $session['protocol'];
        $facts[Lang::t('probe.fact.cipher')] = $session['cipher'].' ('.$session['bits'].' '.Lang::t('unit.bits').')';

        // --- Key exchange: the harvestable part of a TLS session ------------
        $group = $this->negotiatedGroup($host, $port);
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
            $sig = (string) ($session['cert']['signatureTypeSN'] ?? '?');
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
        $versions = $this->supportedVersions($host, $port);
        $facts[Lang::t('probe.fact.versions')] = implode(', ', $versions['accepted']) ?: Lang::t('probe.unknown');
        foreach ($versions['accepted'] as $version) {
            if (\in_array($version, ['TLSv1.0', 'TLSv1.1'], true)) {
                $findings[] = new Finding(
                    algorithm: 'rc4', purpose: Catalogue::PURPOSE_CONFIDENTIALITY, file: $label, line: 0,
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

    /** @return array{0:string, 1:int} */
    private function split(string $target): array
    {
        $target = preg_replace('#^[a-z]+://#i', '', trim($target)) ?? $target;
        $target = rtrim($target, '/');
        if (preg_match('/^(.+):(\d+)$/', $target, $m) === 1) {
            return [$m[1], (int) $m[2]];
        }

        return [$target, 443];
    }

    /** @return array{protocol:string, cipher:string, bits:int, cert:array|null, keyLabel:string, chain:int, validTo:string}|null */
    private function connect(string $host, int $port): ?array
    {
        $context = stream_context_create(['ssl' => [
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'SNI_enabled' => true,
            'peer_name' => $host,
        ]]);

        $stream = @stream_socket_client("ssl://$host:$port", $errno, $error, $this->timeout, \STREAM_CLIENT_CONNECT, $context);
        if ($stream === false) {
            return null;
        }

        $crypto = stream_get_meta_data($stream)['crypto'] ?? [];
        $options = stream_context_get_options($context)['ssl'] ?? [];
        fclose($stream);

        $cert = isset($options['peer_certificate']) ? openssl_x509_parse($options['peer_certificate']) : null;
        $keyLabel = Lang::t('probe.unknown');
        $validTo = '?';
        if (isset($options['peer_certificate'])) {
            $details = @openssl_pkey_get_details(openssl_pkey_get_public($options['peer_certificate']));
            if (\is_array($details)) {
                $keyLabel = match ($details['type']) {
                    \OPENSSL_KEYTYPE_RSA => 'RSA '.$details['bits'].' '.Lang::t('unit.bits'),
                    \OPENSSL_KEYTYPE_EC => Lang::t('probe.elliptic_curve').' '.$details['bits'].' '.Lang::t('unit.bits'),
                    default => $details['bits'].' '.Lang::t('unit.bits'),
                };
            }
            $validTo = isset($cert['validTo_time_t']) ? date('d/m/Y', (int) $cert['validTo_time_t']) : '?';
        }

        return [
            'protocol' => (string) ($crypto['protocol'] ?? '?'),
            'cipher' => (string) ($crypto['cipher_name'] ?? '?'),
            'bits' => (int) ($crypto['cipher_bits'] ?? 0),
            'cert' => \is_array($cert) ? $cert : null,
            'keyLabel' => $keyLabel,
            'chain' => \count($options['peer_certificate_chain'] ?? []),
            'validTo' => $validTo,
        ];
    }

    /**
     * The negotiated group is not exposed by PHP's stream layer, so this asks
     * the openssl binary when it is available — and says so when it is not,
     * rather than silently dropping the most important field of the report.
     */
    private function negotiatedGroup(string $host, int $port): ?string
    {
        $binary = trim((string) @shell_exec('command -v openssl 2>/dev/null'));
        if ($binary === '') {
            return null;
        }

        $command = \sprintf(
            'echo | %s s_client -connect %s -servername %s 2>/dev/null',
            escapeshellarg($binary),
            escapeshellarg("$host:$port"),
            escapeshellarg($host),
        );
        $output = (string) @shell_exec($command);

        // Three spellings for one fact, because the label depends on the
        // OpenSSL build and on the negotiated version. Missing one of them does
        // not fail loudly — it silently drops the most important field of the
        // probe, which is how this was found: only by pointing the tool at a
        // server we controlled.
        foreach ([
            '/Negotiated TLS1\.3 group:\s*(\S+)/i',
            '/(?:Server|Peer) Temp Key:\s*([^,\n]+)/i',
        ] as $pattern) {
            if (preg_match($pattern, $output, $m) === 1) {
                return trim($m[1]);
            }
        }

        return null;
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

    /** @return array{accepted: list<string>, untestable: list<string>} */
    private function supportedVersions(string $host, int $port): array
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
            $stream = @stream_socket_client("ssl://$host:$port", $errno, $error, $this->timeout, \STREAM_CLIENT_CONNECT, $context);
            if ($stream !== false) {
                $accepted[] = $version;
                fclose($stream);
                continue;
            }
            // Distinguish "the server said no" from "our own OpenSSL refused to ask".
            if (stripos($error, 'no protocols available') !== false || stripos($error, 'unsupported protocol') !== false) {
                $untestable[] = $version;
            }
        }

        return ['accepted' => $accepted, 'untestable' => $untestable];
    }
}
