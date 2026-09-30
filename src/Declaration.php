<?php

declare(strict_types=1);

namespace Sablier;

/**
 * The only part of the analysis a machine cannot produce: how long each kind of
 * data has to stay confidential.
 *
 * It is written by the team, reviewed, and versioned with the code. That is the
 * point — it is the one artefact here that commits people rather than tooling.
 */
final class Declaration
{
    /** Planning date: the regulatory deadline, not a prediction of when the maths breaks. */
    public int $deprecationYear = 2030;
    public int $expiryYear = 2035;

    public string $project = '';

    /** @var list<array{name:string, paths:list<string>, lifetime:int, trust_anchor:bool, note:string}> */
    public array $domains = [];

    /** Applied when nothing matches — flagged in the report as undeclared. */
    public int $defaultLifetime = 3;

    public static function load(?string $path): self
    {
        $self = new self();
        if ($path === null || !is_file($path)) {
            return $self;
        }

        $raw = json_decode((string) file_get_contents($path), true);
        if (!\is_array($raw)) {
            throw new \RuntimeException("Déclaration illisible : $path");
        }

        $self->project = (string) ($raw['project'] ?? '');
        $self->deprecationYear = (int) ($raw['deprecation_year'] ?? $self->deprecationYear);
        $self->expiryYear = (int) ($raw['expiry_year'] ?? $self->expiryYear);
        $self->defaultLifetime = (int) ($raw['default_lifetime_years'] ?? $self->defaultLifetime);

        foreach ((array) ($raw['domains'] ?? []) as $name => $domain) {
            $self->domains[] = [
                'name' => (string) $name,
                'paths' => array_map(strval(...), (array) ($domain['paths'] ?? [])),
                'lifetime' => (int) ($domain['lifetime_years'] ?? $self->defaultLifetime),
                'trust_anchor' => (bool) ($domain['trust_anchor'] ?? false),
                'note' => (string) ($domain['note'] ?? ''),
            ];
        }

        return $self;
    }

    /**
     * First domain whose globs match. Order matters, so the file reads like a
     * list of rules rather than a set.
     *
     * @return array{name:string, lifetime:int, trust_anchor:bool, declared:bool}
     */
    public function resolve(string $relativePath): array
    {
        foreach ($this->domains as $domain) {
            foreach ($domain['paths'] as $glob) {
                if (fnmatch($glob, $relativePath, \FNM_NOESCAPE)) {
                    return [
                        'name' => $domain['name'],
                        'lifetime' => $domain['lifetime'],
                        'trust_anchor' => $domain['trust_anchor'],
                        'declared' => true,
                    ];
                }
            }
        }

        return ['name' => 'non déclaré', 'lifetime' => $this->defaultLifetime, 'trust_anchor' => false, 'declared' => false];
    }
}
