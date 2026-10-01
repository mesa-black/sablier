<?php

declare(strict_types=1);

namespace Sablier;

/**
 * Somebody else's inventory, judged by ours.
 *
 * The detectors are not where this tool can win: CycloneDX 1.6 is a published
 * format, several scanners emit it, and they have teams behind them. What
 * nobody else does is cross an inventory with the lifetime of the data it
 * protects. So a CBOM produced by another tool — in Java, Python, Go, a
 * language this project will never parse — comes in here and leaves with a
 * verdict attached.
 *
 * Two refusals hold the import together:
 *   · an algorithm this tool does not know is never guessed at. It is counted,
 *     named, and printed as a blind spot, because an inventory that silently
 *     drops what it did not understand is the failure this project exists to
 *     avoid;
 *   · the detection is not ours and the report says so. We judge what we were
 *     handed; whether the scanner read the code correctly is its author's
 *     claim, not ours.
 */
final class Cbom
{
    /**
     * @return array{findings: list<Finding>, project: string, producer: string, locations: int, ignored: list<string>, unplaced: int}|null
     */
    public static function read(string $path): ?array
    {
        $raw = is_file($path) ? file_get_contents($path) : false;
        if ($raw === false) {
            return null;
        }

        $bom = json_decode($raw, true);
        if (!\is_array($bom) || ($bom['bomFormat'] ?? null) !== 'CycloneDX') {
            return null;
        }

        $findings = [];
        $ignored = [];
        $locations = [];
        $placed = 0;

        foreach ($bom['components'] ?? [] as $component) {
            if (!\is_array($component) || ($component['type'] ?? '') !== 'cryptographic-asset') {
                continue;
            }

            $name = \is_string($component['name'] ?? null) ? $component['name'] : '';
            $algorithm = self::algorithm($component);
            if ($algorithm === null) {
                $ignored[] = $name !== '' ? $name : (string) ($component['bom-ref'] ?? '?');
                continue;
            }

            $entry = Catalogue::get($algorithm);
            $purpose = $entry['purpose'] ?? Catalogue::PURPOSE_UNKNOWN;
            $evidence = trim($name.' '.self::parameter($component));
            $flags = self::properties($component);
            $likelyNonCrypto = ($flags['sablier:likely_non_crypto'] ?? '') === 'true';
            $inventory = ($flags['sablier:declared_dependency'] ?? '') === 'true';

            $occurrences = $component['evidence']['occurrences'] ?? [];
            if (!\is_array($occurrences) || $occurrences === []) {
                // No location: the component still exists and is still judged,
                // but it falls into the default domain and the report says how
                // many did, because a domain nobody could resolve is not a
                // domain that was declared.
                $findings[] = new Finding(
                    algorithm: $algorithm,
                    purpose: $purpose,
                    file: $name !== '' ? $name : (string) ($component['bom-ref'] ?? 'cbom'),
                    line: 0,
                    evidence: $evidence !== '' ? $evidence : $algorithm,
                    likelyNonCrypto: $likelyNonCrypto,
                    inventory: $inventory,
                );
                continue;
            }

            foreach ($occurrences as $occurrence) {
                if (!\is_array($occurrence) || !\is_string($occurrence['location'] ?? null)) {
                    continue;
                }
                // A leading "./" only — ltrim would eat the dot of a
                // dotfile, and .env is exactly the kind of file this tool
                // must keep looking at.
                $location = str_starts_with($occurrence['location'], './')
                    ? substr($occurrence['location'], 2)
                    : $occurrence['location'];
                $locations[$location] = true;
                ++$placed;
                $findings[] = new Finding(
                    algorithm: $algorithm,
                    purpose: $purpose,
                    file: $location,
                    line: (int) ($occurrence['line'] ?? 0),
                    evidence: $evidence !== '' ? $evidence : $algorithm,
                    likelyNonCrypto: $likelyNonCrypto,
                    inventory: $inventory,
                );
            }
        }

        $project = $bom['metadata']['component']['name'] ?? '';

        return [
            'findings' => $findings,
            'project' => \is_string($project) && $project !== '' ? $project : basename($path),
            'producer' => self::producer($bom),
            'locations' => \count($locations),
            'ignored' => $ignored,
            'unplaced' => \count($findings) - $placed,
        ];
    }

    /**
     * Which catalogue entry a component is, or null rather than a guess.
     *
     * Our own CBOM carries the catalogue key in a property, so a round trip is
     * exact. A foreign one is read from the name, the parameter set and the
     * primitive — and the primitive is what settles the distinction this whole
     * risk model rests on: RSA signing is not RSA encrypting, and CycloneDX
     * happens to record exactly that.
     */
    private static function algorithm(array $component): ?string
    {
        foreach ($component['properties'] ?? [] as $property) {
            if (($property['name'] ?? '') === 'sablier:algorithm' && \is_string($property['value'] ?? null)) {
                return Catalogue::get($property['value']) !== null ? $property['value'] : null;
            }
        }

        $name = strtolower(\is_string($component['name'] ?? null) ? $component['name'] : '');
        $parameter = strtolower(self::parameter($component));
        $properties = $component['cryptoProperties']['algorithmProperties'] ?? [];
        $primitive = \is_string($properties['primitive'] ?? null) ? $properties['primitive'] : '';
        $functions = \is_array($properties['cryptoFunctions'] ?? null) ? $properties['cryptoFunctions'] : [];
        $signing = $primitive === 'signature'
            || \in_array('sign', $functions, true)
            || \in_array('verify', $functions, true);

        $protocol = $component['cryptoProperties']['protocolProperties'] ?? [];
        if (($protocol['type'] ?? '') === 'tls') {
            $version = (string) ($protocol['version'] ?? '');

            return \in_array($version, ['1.0', '1.1'], true) ? 'tls-obsolete' : null;
        }

        return match (true) {
            str_contains($name, 'ml-kem'), str_contains($name, 'kyber') => 'ml-kem',
            str_contains($name, 'ml-dsa'), str_contains($name, 'dilithium') => 'ml-dsa',
            str_contains($name, 'ed25519') => 'ed25519',
            str_contains($name, 'ecdsa') => 'ecdsa',
            str_contains($name, 'ecdh'), str_contains($name, 'x25519'), str_contains($name, 'curve25519') => 'ecdh',
            str_contains($name, 'rsa') => $signing ? 'rsa-sign' : 'rsa',
            str_contains($name, 'diffie') || $name === 'dh' => 'dh',
            str_contains($name, 'ec') && $primitive === 'key-agree' => 'ecdh',
            str_contains($name, 'ec') && $signing => 'ecdsa',
            default => ($parameter !== '' ? Catalogue::normalise($name.'-'.$parameter) : null) ?? Catalogue::normalise($name),
        };
    }

    /**
     * The component's properties as a map.
     *
     * One of them is deliberately ignored: `sablier:fingerprint`. The handle a
     * decision is keyed on is always recomputed here, never taken from the
     * file — otherwise a CBOM handed to us could claim the fingerprint of an
     * existing acceptance and walk straight through it.
     *
     * @return array<string, string>
     */
    private static function properties(array $component): array
    {
        $map = [];
        foreach ($component['properties'] ?? [] as $property) {
            if (\is_array($property) && \is_string($property['name'] ?? null) && \is_string($property['value'] ?? null)) {
                $map[$property['name']] = $property['value'];
            }
        }

        return $map;
    }

    private static function parameter(array $component): string
    {
        $properties = $component['cryptoProperties']['algorithmProperties'] ?? [];
        foreach (['parameterSetIdentifier', 'curve'] as $key) {
            if (isset($properties[$key]) && (\is_string($properties[$key]) || \is_int($properties[$key]))) {
                return (string) $properties[$key];
            }
        }

        return '';
    }

    /** Who produced the inventory, named in the report because it is not us. */
    private static function producer(array $bom): string
    {
        $tools = $bom['metadata']['tools']['components'] ?? $bom['metadata']['tools'] ?? [];
        foreach (\is_array($tools) ? $tools : [] as $tool) {
            if (\is_array($tool) && \is_string($tool['name'] ?? null) && $tool['name'] !== '') {
                return $tool['name'].(\is_string($tool['version'] ?? null) ? ' '.$tool['version'] : '');
            }
        }

        return Lang::t('cbom.unknown_producer');
    }
}
