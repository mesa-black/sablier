<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\Analysis;
use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Signature;
use Sablier\Version;

/**
 * The inventory in the format the rest of the field reads: CycloneDX 1.6.
 *
 * The JSON report is a house format, which means nobody consumes it. A CBOM
 * is consumed by tools that already exist, and emitting one costs us nothing
 * we were not already computing — so the inventory travels, and the part that
 * is ours travels with it as properties: the verdict, the domain, the lifetime
 * that produced it, and the fingerprint a decision is keyed on.
 *
 * What is deliberately not claimed here:
 *   · `nistQuantumSecurityLevel` is written only where it is zero — what a
 *     quantum computer breaks. Claiming 1 to 5 for everything else would be
 *     inventing figures, which is the habit this tool exists to refuse.
 *   · `cryptoFunctions` is written only where the primitive settles it.
 *   · an OID is never guessed.
 *
 * And one honest gap: CycloneDX has no way to say "nothing protects this".
 * A plaintext finding is therefore emitted as an algorithm of unknown
 * primitive, carrying `sablier:plaintext`. A consumer that ignores our
 * properties will under-read that component, and there is no way around it
 * short of not reporting the finding at all, which would be worse.
 */
final class CbomReporter implements ReporterInterface
{
    /** CycloneDX primitives, per catalogue key. Omitted where we would be guessing. */
    private const array PRIMITIVE = [
        'rsa' => 'pke',
        'rsa-sign' => 'signature',
        'ecdsa' => 'signature',
        'ed25519' => 'signature',
        'ml-dsa' => 'signature',
        'ecdh' => 'key-agree',
        'dh' => 'key-agree',
        'ml-kem' => 'key-encap',
        'aes-128' => 'block-cipher',
        'aes-256' => 'block-cipher',
        'des' => 'block-cipher',
        'rc4' => 'stream-cipher',
        'chacha20' => 'ae',
        'md5' => 'hash',
        'sha1' => 'hash',
        'sha256' => 'hash',
        'sha512' => 'hash',
        'bcrypt' => 'key-derive',
        'argon2' => 'key-derive',
    ];

    /** Only where the primitive settles the question. */
    private const array FUNCTIONS = [
        'signature' => ['sign', 'verify'],
        'hash' => ['digest'],
        'block-cipher' => ['encrypt', 'decrypt'],
        'stream-cipher' => ['encrypt', 'decrypt'],
        'ae' => ['encrypt', 'decrypt'],
        'pke' => ['encrypt', 'decrypt'],
        'key-encap' => ['encapsulate', 'decapsulate'],
        'key-derive' => ['keyderive'],
    ];

    public function render(Analysis $analysis): string
    {
        $project = $analysis->declaration->project !== ''
            ? $analysis->declaration->project
            : basename($analysis->target);

        $components = [];
        foreach ($analysis->findings as $finding) {
            $components[] = $this->component($finding, $analysis);
        }

        $bom = [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'serialNumber' => self::serialNumber($analysis),
            'version' => 1,
            'metadata' => [
                'timestamp' => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM),
                'tools' => ['components' => [[
                    'type' => 'application',
                    'name' => 'Sablier',
                    'version' => Version::NUMBER,
                    'description' => 'Cryptographic inventory with the expiry date of each protection.',
                ]]],
                'component' => [
                    'type' => 'application',
                    'bom-ref' => 'sablier:target',
                    'name' => $project,
                ],
                'properties' => [
                    ['name' => 'sablier:expiry_year', 'value' => (string) $analysis->declaration->expiryYear],
                    ['name' => 'sablier:current_year', 'value' => (string) $analysis->currentYear],
                    ['name' => 'sablier:default_lifetime_years', 'value' => (string) $analysis->declaration->defaultLifetime],
                ],
            ],
            'components' => $components,
        ];

        return (string) json_encode($bom, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES);
    }

    /**
     * A UUID derived from the findings digest rather than drawn at random:
     * the same inventory produces the same serial number twice, which is the
     * same promise the signature makes.
     */
    private static function serialNumber(Analysis $analysis): string
    {
        $hex = substr(Signature::digest($analysis), 0, 32);
        $bytes = str_split($hex, 2);
        // Version 8 (custom), RFC 4122 variant: this is a derived identifier,
        // and saying so in the UUID itself beats pretending it was random.
        $bytes[6] = dechex((hexdec($bytes[6]) & 0x0F) | 0x80);
        $bytes[8] = dechex((hexdec($bytes[8]) & 0x3F) | 0x80);
        $hex = implode('', array_map(static fn (string $b): string => str_pad($b, 2, '0', \STR_PAD_LEFT), $bytes));

        return 'urn:uuid:'.implode('-', [
            substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12),
        ]);
    }

    /** @return array<string, mixed> */
    private function component(Finding $finding, Analysis $analysis): array
    {
        $entry = Catalogue::get($finding->algorithm);
        $primitive = self::PRIMITIVE[$finding->algorithm] ?? null;

        $algorithmProperties = [];
        if ($primitive !== null) {
            $algorithmProperties['primitive'] = $primitive;
            if (isset(self::FUNCTIONS[$primitive])) {
                $algorithmProperties['cryptoFunctions'] = self::FUNCTIONS[$primitive];
            }
        }
        // Zero is the only level this tool is prepared to assert: it is the one
        // the regulatory deadline is about.
        if ($entry !== null && $entry['quantum']) {
            $algorithmProperties['nistQuantumSecurityLevel'] = 0;
        }

        $cryptoProperties = $finding->algorithm === 'tls-obsolete'
            ? ['assetType' => 'protocol', 'protocolProperties' => ['type' => 'tls']]
            : ['assetType' => 'algorithm', 'algorithmProperties' => $algorithmProperties];

        $properties = [
            // The catalogue key, so our own CBOM reads back exactly: a name
            // like "ECDH / X25519" is for humans, and a round trip through a
            // human-readable string loses the distinction that matters.
            ['name' => 'sablier:algorithm', 'value' => $finding->algorithm],
            ['name' => 'sablier:fingerprint', 'value' => $finding->fingerprint()],
            ['name' => 'sablier:verdict', 'value' => $finding->verdict],
            ['name' => 'sablier:purpose', 'value' => $finding->purpose],
            ['name' => 'sablier:domain', 'value' => $finding->domain],
            ['name' => 'sablier:domain_declared', 'value' => $finding->domainDeclared ? 'true' : 'false'],
            ['name' => 'sablier:lifetime_years', 'value' => (string) $finding->lifetime],
            ['name' => 'sablier:confidence', 'value' => $finding->confidence],
            ['name' => 'sablier:because', 'value' => $finding->because],
        ];
        if ($finding->lifetime > 0) {
            $properties[] = ['name' => 'sablier:exposure_end', 'value' => (string) ($analysis->currentYear + $finding->lifetime)];
        }
        if ($finding->inventory) {
            $properties[] = ['name' => 'sablier:declared_dependency', 'value' => 'true'];
        }
        // Two signals that change the verdict and live in the source line
        // rather than in the algorithm: a digest used as a cache key, and a
        // dependency that is declared rather than called. A foreign CBOM
        // carries neither, which is why an imported finding can read harsher
        // than the same finding scanned — the report says where it came from.
        if ($finding->likelyNonCrypto) {
            $properties[] = ['name' => 'sablier:likely_non_crypto', 'value' => 'true'];
        }
        if ($finding->algorithm === 'plaintext') {
            $properties[] = ['name' => 'sablier:plaintext', 'value' => 'true'];
        }
        if ($finding->acceptedUntil !== '') {
            $properties[] = ['name' => 'sablier:accepted_until', 'value' => $finding->acceptedUntil];
            $properties[] = ['name' => 'sablier:accepted_reason', 'value' => $finding->acceptedReason];
        }

        // CycloneDX has a slot for this: a published defect is an advisory,
        // and it travels with the component rather than in a property of ours.
        $references = array_map(
            static fn (string $reference): array => [
                'url' => Catalogue::referenceUrl($reference),
                'type' => 'advisories',
                'comment' => $reference,
            ],
            $finding->references(),
        );

        $occurrence = ['location' => $finding->file];
        if ($finding->line > 0) {
            $occurrence['line'] = $finding->line;
        }

        $component = [
            'type' => 'cryptographic-asset',
            'bom-ref' => 'sablier:'.$finding->fingerprint(),
            // The label is French for the one entry that is not an algorithm;
            // a BOM is read by machines in every language, so it says none.
            'name' => $finding->algorithm === 'plaintext' ? 'none' : Catalogue::label($finding->algorithm),
            'evidence' => ['occurrences' => [$occurrence]],
            'cryptoProperties' => $cryptoProperties,
            'properties' => $properties,
        ];

        if ($references !== []) {
            $component['externalReferences'] = $references;
        }

        return $component;
    }
}
