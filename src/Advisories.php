<?php

declare(strict_types=1);

namespace Sablier;

use Sablier\Detector\DependencyDetector;

/**
 * Published vulnerabilities in the cryptographic libraries a project declares.
 *
 * The post-quantum argument is about a deadline. This is about a hole somebody
 * already found, in a version you are already shipping — which outranks 2035 by
 * about a decade, and belongs in the same report for exactly that reason.
 *
 * Three decisions keep it from turning this tool into a generic scanner:
 *
 *   · only the packages this tool already inventories are judged. A project has
 *     dozens of vulnerable dependencies and a report that lists all of them
 *     buries the cryptography it was asked about. The count of the others is
 *     printed, so the reader knows the rest was seen and left alone;
 *   · high and critical raise a verdict; medium and low are recorded and shown,
 *     not promoted. The threshold is the same one `make cve` applies to our own
 *     containers, and saying which one was used matters more than the choice;
 *   · the database is fetched by a command the operator runs on purpose, and
 *     the result is a file they can read. A scan never reaches the network, and
 *     no package name of yours leaves the machine during one.
 */
final class Advisories
{
    /** The severities that change a verdict rather than informing it. */
    private const array RAISING = ['HIGH', 'CRITICAL'];

    /** @var array<string, list<array{id:string, severity:string, fixed:string}>> */
    private array $packages = [];

    /** @param array<array-key, mixed> $packages */
    private function __construct(
        public readonly string $path,
        public readonly string $scanner,
        public readonly string $generatedAt,
        public readonly int $ignored,
        array $packages,
    ) {
        foreach ($packages as $name => $entries) {
            $name = strtolower((string) $name);
            foreach (Value::map($entries) as $entry) {
                $entry = Value::map($entry);
                $id = Value::string($entry['id'] ?? null);
                if ($id === '') {
                    continue;
                }
                $this->packages[$name][] = [
                    'id' => $id,
                    'severity' => strtoupper(Value::string($entry['severity'] ?? null, 'UNKNOWN')),
                    'fixed' => Value::string($entry['fixed'] ?? null),
                ];
            }
        }
    }

    public static function load(string $path): ?self
    {
        if (!is_file($path)) {
            return null;
        }

        $raw = Value::map(json_decode((string) file_get_contents($path), true));
        if ($raw === []) {
            return null;
        }

        return new self(
            path: $path,
            scanner: Value::string($raw['scanner'] ?? null, '?'),
            generatedAt: Value::string($raw['generated_at'] ?? null, '?'),
            ignored: Value::int($raw['other_vulnerable_packages'] ?? null),
            packages: Value::map($raw['packages'] ?? null),
        );
    }

    /** @return list<array{id:string, severity:string, fixed:string}> */
    public function for(string $package): array
    {
        return $this->packages[strtolower($package)] ?? [];
    }

    /**
     * The ones that change a verdict rather than merely informing it.
     *
     * @return list<array{id:string, severity:string, fixed:string}>
     */
    public function raising(string $package): array
    {
        return array_values(array_filter(
            $this->for($package),
            static fn (array $entry): bool => \in_array($entry['severity'], self::RAISING, true),
        ));
    }

    /** How many cryptographic packages carry at least one advisory. */
    public function count(): int
    {
        return \count($this->packages);
    }

    /**
     * Turn a scanner's report into the file a scan reads.
     *
     * Faithful about severity — everything the scanner said is kept, because
     * the threshold belongs to the judgement and not to the collection — and
     * narrow about scope: a package this tool knows nothing about is counted
     * and dropped, never silently folded into the cryptographic findings.
     *
     * @param array<array-key, mixed> $report the scanner's JSON, decoded
     *
     * @return array<string, mixed>
     */
    public static function fromScannerReport(array $report, string $scanner, string $target): array
    {
        $known = array_map(strtolower(...), DependencyDetector::packages());
        $packages = [];
        $ignored = [];

        foreach (Value::map($report['Results'] ?? null) as $result) {
            foreach (Value::map(Value::map($result)['Vulnerabilities'] ?? null) as $vulnerability) {
                $vulnerability = Value::map($vulnerability);
                $name = strtolower(Value::string($vulnerability['PkgName'] ?? null));
                $id = Value::string($vulnerability['VulnerabilityID'] ?? null);
                if ($name === '' || $id === '') {
                    continue;
                }
                if (!\in_array($name, $known, true)) {
                    $ignored[$name] = true;
                    continue;
                }
                $packages[$name][] = [
                    'id' => $id,
                    'severity' => strtoupper(Value::string($vulnerability['Severity'] ?? null, 'UNKNOWN')),
                    'fixed' => Value::string($vulnerability['FixedVersion'] ?? null),
                    'installed' => Value::string($vulnerability['InstalledVersion'] ?? null),
                ];
            }
        }

        ksort($packages);

        return [
            'generated_at' => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM),
            'scanner' => $scanner,
            'target' => $target,
            'other_vulnerable_packages' => \count($ignored),
            'packages' => $packages,
        ];
    }
}
