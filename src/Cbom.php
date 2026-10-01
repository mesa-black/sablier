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

        $bom = Value::map(json_decode($raw, true));
        if (($bom['bomFormat'] ?? null) !== 'CycloneDX') {
            return null;
        }

        $findings = [];
        $ignored = [];
        $locations = [];
        $placed = 0;

        foreach (Value::map($bom['components'] ?? null) as $component) {
            $component = Value::map($component);
            if (($component['type'] ?? '') !== 'cryptographic-asset') {
                continue;
            }

            $name = Value::string($component['name'] ?? null);
            $algorithm = self::algorithm($component);
            if ($algorithm === null) {
                $ignored[] = $name !== '' ? $name : Value::string($component['bom-ref'] ?? null, '?');
                continue;
            }

            $entry = Catalogue::get($algorithm);
            $purpose = $entry['purpose'] ?? Catalogue::PURPOSE_UNKNOWN;
            $evidence = trim($name.' '.self::parameter($component));
            $flags = self::properties($component);
            $likelyNonCrypto = ($flags['sablier:likely_non_crypto'] ?? '') === 'true';
            $inventory = ($flags['sablier:declared_dependency'] ?? '') === 'true';

            $occurrences = Value::map(Value::map($component['evidence'] ?? null)['occurrences'] ?? null);
            if ($occurrences === []) {
                // No location: the component still exists and is still judged,
                // but it falls into the default domain and the report says how
                // many did, because a domain nobody could resolve is not a
                // domain that was declared.
                $findings[] = new Finding(
                    algorithm: $algorithm,
                    purpose: $purpose,
                    file: $name !== '' ? $name : Value::string($component['bom-ref'] ?? null, 'cbom'),
                    line: 0,
                    evidence: $evidence !== '' ? $evidence : $algorithm,
                    likelyNonCrypto: $likelyNonCrypto,
                    inventory: $inventory,
                );
                continue;
            }

            foreach ($occurrences as $occurrence) {
                $occurrence = Value::map($occurrence);
                $raw = Value::string($occurrence['location'] ?? null);
                if ($raw === '') {
                    continue;
                }
                // A leading "./" only — ltrim would eat the dot of a
                // dotfile, and .env is exactly the kind of file this tool
                // must keep looking at.
                $location = str_starts_with($raw, './') ? substr($raw, 2) : $raw;
                $locations[$location] = true;
                ++$placed;
                $findings[] = new Finding(
                    algorithm: $algorithm,
                    purpose: $purpose,
                    file: $location,
                    line: Value::int($occurrence['line'] ?? null),
                    evidence: $evidence !== '' ? $evidence : $algorithm,
                    likelyNonCrypto: $likelyNonCrypto,
                    inventory: $inventory,
                );
            }
        }

        $metadata = Value::map($bom['metadata'] ?? null);
        $project = Value::string(Value::map($metadata['component'] ?? null)['name'] ?? null);

        return [
            'findings' => $findings,
            'project' => $project !== '' ? $project : basename($path),
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
    /** @param array<array-key, mixed> $component */
    private static function algorithm(array $component): ?string
    {
        $declared = self::properties($component)['sablier:algorithm'] ?? null;
        if ($declared !== null) {
            return Catalogue::get($declared) !== null ? $declared : null;
        }

        $name = strtolower(Value::string($component['name'] ?? null));
        $parameter = strtolower(self::parameter($component));
        $crypto = Value::map($component['cryptoProperties'] ?? null);
        $properties = Value::map($crypto['algorithmProperties'] ?? null);
        $primitive = Value::string($properties['primitive'] ?? null);
        $functions = Value::strings($properties['cryptoFunctions'] ?? null);
        $signing = $primitive === 'signature'
            || \in_array('sign', $functions, true)
            || \in_array('verify', $functions, true);

        $protocol = Value::map($crypto['protocolProperties'] ?? null);
        if (($protocol['type'] ?? '') === 'tls') {
            $version = Value::string($protocol['version'] ?? null);

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
     * @param array<array-key, mixed> $component
     *
     * @return array<string, string>
     */
    private static function properties(array $component): array
    {
        $map = [];
        foreach (Value::map($component['properties'] ?? null) as $property) {
            $property = Value::map($property);
            $name = Value::string($property['name'] ?? null);
            if ($name !== '' && \is_string($property['value'] ?? null)) {
                $map[$name] = $property['value'];
            }
        }

        return $map;
    }

    /** @param array<array-key, mixed> $component */
    private static function parameter(array $component): string
    {
        $properties = Value::map(Value::map($component['cryptoProperties'] ?? null)['algorithmProperties'] ?? null);
        foreach (['parameterSetIdentifier', 'curve'] as $key) {
            $value = Value::string($properties[$key] ?? null);
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    /**
     * Who produced the inventory, named in the report because it is not us.
     *
     * Two shapes in the wild: CycloneDX 1.5 put a list under `tools`, 1.6 puts
     * it under `tools.components`. Both are read, because the point of the
     * import is to accept files we did not write.
     *
     * @param array<array-key, mixed> $bom
     */
    private static function producer(array $bom): string
    {
        $tools = Value::map($bom['metadata'] ?? null)['tools'] ?? null;
        $candidates = Value::map(Value::map($tools)['components'] ?? null) ?: Value::map($tools);
        foreach ($candidates as $tool) {
            $tool = Value::map($tool);
            $name = Value::string($tool['name'] ?? null);
            if ($name !== '') {
                $version = Value::string($tool['version'] ?? null);

                return $version !== '' ? $name.' '.$version : $name;
            }
        }

        return Lang::t('cbom.unknown_producer');
    }
}
