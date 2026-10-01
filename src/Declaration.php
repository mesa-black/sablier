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
    /**
     * When the regulatory deadlines below were last checked against their
     * sources. It is printed in the report and it goes stale: these dates have
     * already moved several times. A tool that states a deadline as fact without
     * saying when it looked is producing exactly the kind of expired figure this
     * project holds against everyone else.
     *
     * Sources checked on that date: NIST IR 8547, CNSA 2.0, EU Recommendation
     * 2024/1101, ANSSI's position on the post-quantum transition.
     */
    public const string DEADLINES_CHECKED_ON = '2026-09-30';

    /** After this many months without a re-check, the report says so out loud. */
    public const int STALE_AFTER_MONTHS = 12;

    /** Planning date: the regulatory deadline, not a prediction of when the maths breaks. */
    public int $deprecationYear = 2030;
    public int $expiryYear = 2035;

    /** Overridable per project: a team that checked more recently should say so. */
    public string $deadlinesCheckedOn = self::DEADLINES_CHECKED_ON;

    /**
     * The public key reports from this project are expected to be signed with.
     *
     * It lives in the versioned declaration on purpose: a signature that
     * verifies against whatever key came with it proves only that someone had
     * a key. Here, changing the expected key is a reviewable commit.
     */
    public string $signingPublicKey = '';

    public string $project = '';

    /** @var list<array{name:string, paths:list<string>, lifetime:int, trust_anchor:bool, note:string}> */
    public array $domains = [];

    /** Applied when nothing matches — flagged in the report as undeclared. */
    public int $defaultLifetime = 3;

    /**
     * Findings this project has decided to accept, by fingerprint.
     *
     * Two rules are enforced rather than suggested, because a suppression file
     * that is easy to write is how these tools empty themselves out: a reason
     * is required, and so is an expiry date. An acceptance that never expires
     * is not a decision, it is a way of forgetting.
     *
     * @var array<string, array{reason:string, until:string}>
     */
    public array $accepted = [];

    /**
     * Paths this project puts out of scope, as globs.
     *
     * Not a way to hide findings — that is what `accepted` is for, with its
     * reason and its expiry. This is for files that talk *about* cryptography
     * without using any: rule tables, documentation, test fixtures. A scanner's
     * own pattern list is the clearest example, and this tool's repository ships
     * exactly that case.
     *
     * @var list<string>
     */
    public array $exclude = [];

    /**
     * Hosts to probe live. Declared next to the data domains on purpose: what a
     * server negotiates is part of the inventory, not a separate exercise.
     *
     * @var list<string>
     */
    public array $probe = [];

    public static function load(?string $path): self
    {
        $self = new self();
        if ($path === null || !is_file($path)) {
            return $self;
        }

        $raw = json_decode((string) file_get_contents($path), true);
        if (!\is_array($raw)) {
            throw new \RuntimeException("unreadable declaration: $path");
        }

        $self->project = Value::string($raw['project'] ?? null);
        $self->deprecationYear = Value::int($raw['deprecation_year'] ?? null, $self->deprecationYear);
        $self->expiryYear = Value::int($raw['expiry_year'] ?? null, $self->expiryYear);
        $self->defaultLifetime = Value::int($raw['default_lifetime_years'] ?? null, $self->defaultLifetime);
        $self->probe = Value::strings($raw['probe'] ?? null);
        $self->exclude = Value::strings($raw['exclude'] ?? null);
        $self->deadlinesCheckedOn = Value::string($raw['deadlines_checked_on'] ?? null, $self->deadlinesCheckedOn);
        $self->signingPublicKey = Value::string($raw['signing_public_key'] ?? null);

        foreach (Value::map($raw['accepted'] ?? null) as $fingerprint => $entry) {
            $entry = Value::map($entry);
            $reason = trim(Value::string($entry['reason'] ?? null));
            $until = trim(Value::string($entry['until'] ?? null));
            // An entry missing either half is ignored outright and reported as
            // such: silently honouring it would be the failure mode this whole
            // design exists to avoid.
            if ($reason === '' || $until === '') {
                $self->rejectedAcceptances[] = (string) $fingerprint;
                continue;
            }
            $self->accepted[(string) $fingerprint] = ['reason' => $reason, 'until' => $until];
        }

        $audit = Value::map($raw['audit'] ?? null);
        foreach (array_keys($self->audit) as $field) {
            $self->audit[$field] = trim(Value::string($audit[$field] ?? null));
        }

        foreach (Value::map($raw['domains'] ?? null) as $name => $domain) {
            $domain = Value::map($domain);
            $self->domains[] = [
                'name' => (string) $name,
                'paths' => Value::strings($domain['paths'] ?? null),
                'lifetime' => Value::int($domain['lifetime_years'] ?? null, $self->defaultLifetime),
                'trust_anchor' => Value::bool($domain['trust_anchor'] ?? null),
                'note' => Value::string($domain['note'] ?? null),
            ];
        }

        return $self;
    }

    /**
     * Who is auditing, for whom, under what mandate.
     *
     * Only ever read back, never invented: an empty field prints as a field to
     * complete. A report that fills in a plausible auditor's name is a forgery
     * with good intentions.
     *
     * @var array{auditor:string, organisation:string, client:string, reference:string, mandate:string, statement:string}
     */
    public array $audit = ['auditor' => '', 'organisation' => '', 'client' => '', 'reference' => '', 'mandate' => '', 'statement' => ''];

    /** @var list<string> Fingerprints declared without a reason or without an expiry. */
    public array $rejectedAcceptances = [];

    /** @return array{reason:string, until:string, expired:bool}|null */
    public function acceptanceFor(string $fingerprint, ?\DateTimeImmutable $now = null): ?array
    {
        $entry = $this->accepted[$fingerprint] ?? null;
        if ($entry === null) {
            return null;
        }

        $until = \DateTimeImmutable::createFromFormat('Y-m-d', $entry['until']);

        return $entry + ['expired' => $until === false || $until < ($now ?? new \DateTimeImmutable())];
    }

    /** Months elapsed since the deadlines were last checked against their sources. */
    public function monthsSinceCheck(?\DateTimeImmutable $now = null): int
    {
        $checked = \DateTimeImmutable::createFromFormat('Y-m-d', $this->deadlinesCheckedOn);
        if ($checked === false) {
            return self::STALE_AFTER_MONTHS + 1; // Unreadable date: treat it as stale rather than as fresh.
        }

        $diff = $checked->diff($now ?? new \DateTimeImmutable());

        return $diff->y * 12 + $diff->m;
    }

    public function deadlinesAreStale(?\DateTimeImmutable $now = null): bool
    {
        return $this->monthsSinceCheck($now) >= self::STALE_AFTER_MONTHS;
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

        // The label is translated: a hardcoded one printed French in every report.
        return ['name' => Lang::t('domain.undeclared'), 'lifetime' => $this->defaultLifetime, 'trust_anchor' => false, 'declared' => false];
    }
}
