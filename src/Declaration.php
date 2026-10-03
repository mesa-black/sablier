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

    /**
     * The lifetime above which the EU roadmap calls a use case high-risk.
     *
     * "data that needs to remain confidential for at least 10 years should be
     * protected from quantum computer attacks starting no later than by the end
     * of 2030". Ten years is theirs, not a number we picked.
     */
    public const int LONG_TERM_YEARS = 10;

    /** Planning date: the regulatory deadline, not a prediction of when the maths breaks. */
    public int $deprecationYear = 2030;
    public int $expiryYear = 2035;

    /**
     * The year this system stops producing data, when somebody knows it.
     *
     * The exposure of a domain does not end today: it ends when the last
     * record is written. A service retired in 2027 emits its final secret in
     * 2027, and that one is harvestable until 2027 plus its lifetime. Zero
     * means undeclared, and the calculation then assumes the system stops
     * today — which understates the exposure, so the report says so.
     */
    public int $serviceUntil = 0;

    /**
     * Whose deadline applies, and the text it comes from.
     *
     * The expiry year is not a universal constant: a commercial service plans
     * against NIST IR 8547, a system handling classified French material
     * against ANSSI's position that anything needing protection past 2030 has
     * to be post-quantum today. Naming the regime picks the date **and the
     * citation**, which is the only reason this is a setting rather than a
     * number somebody typed.
     *
     * An explicit expiry_year always wins: the regime is a shortcut, not an
     * authority.
     *
     * One regime does not work like the others: see `graded` below.
     *
     * @var array<string, array{expiry:int, deprecation:int, source:string, graded?:bool}>
     */
    public const array REGIMES = [
        'general' => ['expiry' => 2035, 'deprecation' => 2030, 'source' => 'NIST IR 8547'],
        'anssi' => ['expiry' => 2030, 'deprecation' => 2027, 'source' => 'ANSSI'],
        'nss' => ['expiry' => 2030, 'deprecation' => 2027, 'source' => 'CNSA 2.0 (NSA)'],
        // Health data hosted in France. The deadline is ANSSI's, because the
        // data is sensitive; what the regime adds is the other side of the
        // inequality. Retention here is written in law rather than guessed in
        // a meeting — twenty years for a patient record, twenty-one for a
        // vaccine dispensation, up to seventy for pharmacovigilance — which is
        // the one input this tool usually has to go and ask for.
        'hds' => ['expiry' => 2030, 'deprecation' => 2027, 'source' => 'ANSSI · hébergement de données de santé'],
        // The one regime whose deadline is not a date but a function of the
        // data. The NIS Cooperation Group's roadmap classifies a use case by
        // the confidentiality it owes — high risk if a break after ten years
        // would still cause significant damage — and gives each class its own
        // end date. It is the only published framework that asks for the input
        // this tool was built around, which is why the expiry here is read per
        // domain rather than taken from this row. The pair below is what the
        // regime ends on, for the timeline and for anything with no domain.
        'eu' => ['expiry' => 2035, 'deprecation' => 2030, 'source' => 'UE · NIS CG, feuille de route coordonnée du 23/06/2025', 'graded' => true],
    ];

    /** The three levels of the roadmap, highest first. */
    public const string RISK_HIGH = 'high';
    public const string RISK_MEDIUM = 'medium';
    public const string RISK_LOW = 'low';

    public string $regime = 'general';

    /**
     * Somebody wrote the year down themselves.
     *
     * A declaration that states `expiry_year` outranks any regime, including a
     * graded one: the point of the setting is that the team can disagree with
     * the framework and say so in a reviewable file.
     */
    public bool $expiryOverridden = false;

    /**
     * The day data left, when somebody already took it.
     *
     * The rest of this tool reasons forward: harvest now, decrypt later. A
     * breach turns that around — the adversary is not waiting, they hold the
     * data — and the only question left is how much of the confidentiality you
     * asked for the algorithm can still deliver.
     */
    public string $breachedOn = '';

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

    /**
     * The post-quantum half, vouched for in the same versioned file.
     *
     * Without it the ML-DSA key travels inside the signature it is meant to
     * authenticate, which proves nothing to anybody who can forge the other
     * half — and forging the other half is precisely the future this signature
     * exists for. A hybrid whose second key is self-asserted is decoration.
     */
    public string $signingPublicKeyPq = '';

    public string $project = '';

    /** @var list<array{name:string, paths:list<string>, lifetime:int, trust_anchor:bool, hybrid:bool, breached:string, note:string, declared_by:string, declared_on:string}> */
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

    /**
     * Where this file was read from, so the endorsement beside it can be found.
     *
     * Empty when nothing was loaded, which is also when there is nothing to
     * endorse.
     */
    public string $path = '';

    public static function load(?string $path): self
    {
        $self = new self();
        if ($path === null || !is_file($path)) {
            return $self;
        }

        $self->path = $path;

        $raw = json_decode((string) file_get_contents($path), true);
        if (!\is_array($raw)) {
            throw new \RuntimeException("unreadable declaration: $path");
        }

        $self->project = Value::string($raw['project'] ?? null);
        $self->serviceUntil = Value::int($raw['service_until'] ?? null);

        // The regime sets the dates; an explicit year overrides it. A regime
        // nobody declared is the general one, which is also what every report
        // printed before this setting existed.
        $regime = strtolower(Value::string($raw['regime'] ?? null, 'general'));
        $self->breachedOn = Value::string($raw['breached'] ?? null);
        $self->regime = isset(self::REGIMES[$regime]) ? $regime : 'general';
        $self->deprecationYear = self::REGIMES[$self->regime]['deprecation'];
        $self->expiryYear = self::REGIMES[$self->regime]['expiry'];

        $self->deprecationYear = Value::int($raw['deprecation_year'] ?? null, $self->deprecationYear);
        $self->expiryYear = Value::int($raw['expiry_year'] ?? null, $self->expiryYear);
        $self->expiryOverridden = Value::int($raw['expiry_year'] ?? null) !== 0;
        $self->defaultLifetime = Value::int($raw['default_lifetime_years'] ?? null, $self->defaultLifetime);
        $self->probe = Value::strings($raw['probe'] ?? null);
        $self->exclude = Value::strings($raw['exclude'] ?? null);
        $self->deadlinesCheckedOn = Value::string($raw['deadlines_checked_on'] ?? null, $self->deadlinesCheckedOn);
        $self->signingPublicKey = Value::string($raw['signing_public_key'] ?? null);
        $self->signingPublicKeyPq = Value::string($raw['signing_public_key_pq'] ?? null);

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
        $self->mergeIdentity();

        foreach (Value::map($raw['domains'] ?? null) as $name => $domain) {
            $domain = Value::map($domain);
            $self->domains[] = [
                'name' => (string) $name,
                'paths' => Value::strings($domain['paths'] ?? null),
                'lifetime' => Value::int($domain['lifetime_years'] ?? null, $self->defaultLifetime),
                'trust_anchor' => Value::bool($domain['trust_anchor'] ?? null),
                // The classical half of a hybrid is kept on purpose. Declared
                // rather than observed: two call sites in one file are not
                // evidence that they cover the same bytes, and asserting a
                // pairing we cannot see would be the invention this tool
                // refuses everywhere else.
                'hybrid' => Value::bool($domain['hybrid'] ?? null),
                // Per domain, because a breach reaches some data and not
                // others, and a tool that assumed otherwise would turn one
                // stolen table into a report about the whole system.
                'breached' => Value::string($domain['breached'] ?? null, Value::string($raw['breached'] ?? null)),
                'note' => Value::string($domain['note'] ?? null),
                // Who said so, and when. Acceptances expire and regulatory
                // dates carry a verification date; a lifetime had neither, so
                // one declared in 2026 by somebody who left in 2028 still
                // drove the verdicts in 2032 with nobody the wiser.
                'declared_by' => Value::string($domain['declared_by'] ?? null),
                'declared_on' => Value::string($domain['declared_on'] ?? null),
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

    /**
     * Fill the blanks from the auditor's own file, never the other way round.
     *
     * Two different things were being asked of one block. The client, the
     * reference and the mandate belong to an engagement, change every time,
     * and are reviewed with the project they concern — so they stay in the
     * versioned declaration. The auditor's name, their organisation and the
     * statement they sign belong to the person, not to the project, and typing
     * them again into every client's repository is how they end up stale in
     * one of them.
     *
     * So the identity file fills what the declaration left empty, and loses
     * every conflict: the versioned file is the one somebody reviewed.
     */
    private function mergeIdentity(): void
    {
        $path = getenv('SABLIER_IDENTITY') ?: (getenv('HOME') ?: '').'/.config/sablier/identity.json';
        if (!is_file($path)) {
            return;
        }

        $identity = Value::map(json_decode((string) file_get_contents($path), true));
        foreach (array_keys($this->audit) as $field) {
            if ($this->audit[$field] === '') {
                $this->audit[$field] = trim(Value::string($identity[$field] ?? null));
            }
        }
    }

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
     * A digest of what this declaration decides, independent of how it is written.
     *
     * The one input the whole report rests on is also the only artefact here
     * nobody signs: `declared_by` is a string anybody can type. This makes the
     * declaration signable, and what it covers is the decisions rather than the
     * bytes — reformatting the file, reordering the keys or rewrapping a note
     * keeps an endorsement valid, while changing a lifetime, a path, a regime or
     * an author breaks it. That is the behaviour somebody endorsing a file
     * expects: they signed what it says, not how it is laid out.
     *
     * Domains are sorted by name and paths within a domain are sorted too, for
     * the same reason the report's own digest sorts its findings: the order a
     * human happened to type them in is not part of what they decided.
     */
    public function digest(): string
    {
        $rows = [];
        foreach ($this->domains as $domain) {
            $paths = $domain['paths'];
            sort($paths);
            $rows[] = implode('|', [
                $domain['name'],
                (string) $domain['lifetime'],
                $domain['trust_anchor'] ? 'anchor' : '-',
                $domain['hybrid'] ? 'hybrid' : '-',
                implode(',', $paths),
                preg_replace('/\s+/', ' ', trim($domain['note'])) ?? '',
                $domain['declared_by'],
                $domain['declared_on'],
            ]);
        }
        sort($rows);

        return hash('sha256', implode("\n", [
            'sablier-declaration/1',
            $this->project,
            $this->regime,
            (string) $this->expiryYear,
            (string) $this->deprecationYear,
            (string) $this->defaultLifetime,
            (string) $this->serviceUntil,
            (string) \count($rows),
            ...$rows,
        ]));
    }

    /**
     * The endorsement filed beside this declaration, when there is one.
     *
     * Three answers, not two. No file means nobody signed, which is the usual
     * case and not a fault. A file that does not match means the declaration
     * changed after it was endorsed — the interesting answer, and the reason
     * this is checked rather than displayed: an endorsement that is printed
     * without being verified is worse than none.
     *
     * @return array{valid:bool, reason:string, signed_at:string, fingerprint:string, ephemeral:bool}|null
     */
    public function endorsement(): ?array
    {
        if ($this->path === '' || !is_file($this->path.'.sig')) {
            return null;
        }

        $block = Value::map(json_decode((string) file_get_contents($this->path.'.sig'), true));
        /** @var array<string, mixed> $hybrid */
        $hybrid = Value::map($block['hybrid'] ?? null);
        $result = Signature::verify([
            'algorithm' => Value::string($block['algorithm'] ?? null),
            'digest' => Value::string($block['digest'] ?? null),
            'signed_at' => Value::string($block['signed_at'] ?? null),
            'public_key' => Value::string($block['public_key'] ?? null),
            'signature' => Value::string($block['signature'] ?? null),
            'hybrid' => $hybrid,
        ], $this->digest());

        $signedAt = \DateTimeImmutable::createFromFormat(
            \DateTimeInterface::ATOM,
            Value::string($block['signed_at'] ?? null),
        );

        return [
            'valid' => $result['valid'],
            // A changed digest means something different here than on a report:
            // what the reader needs to hear is that the file the report rests
            // on is no longer the file somebody endorsed.
            'reason' => $result['reason'] === 'verify.changed' ? 'endorse.changed' : $result['reason'],
            'signed_at' => $signedAt === false ? Value::string($block['signed_at'] ?? null) : $signedAt->format('d/m/Y H:i'),
            'fingerprint' => Signature::fingerprint(
                Value::string($block['public_key'] ?? null),
                Value::string($hybrid['public_key'] ?? null),
            ),
            'ephemeral' => ($block['ephemeral'] ?? false) === true,
        ];
    }

    /** Whether this regime reads the deadline off the data rather than a row. */
    public function graded(): bool
    {
        return (self::REGIMES[$this->regime]['graded'] ?? false) === true;
    }

    /**
     * The quantum risk level of a domain, as the roadmap defines it.
     *
     * Quoted rather than paraphrased, because the whole point of naming a
     * regime is to borrow somebody else's authority: "If confidentiality needs
     * to be protected, then the quantum risk level is medium or high. If
     * confidentiality needs to be protected for a long time period (at least 10
     * years), and an attack after 10 years or more would still have significant
     * impact, then the quantum risk level is high. […] If the transition effort
     * is high (taking more than 8 years) and the impact of an attack is high,
     * for example for securing software updates, the quantum risk level is
     * high."
     *
     * The second sentence is the lifetime this tool already asks for. The last
     * is what `trust_anchor` marks: a key that signs software or firmware is
     * the roadmap's own example of the high-impact case.
     *
     * The impact clause ("would still have significant damage") is a judgement
     * this tool cannot make. Declaring a ten-year lifetime *is* that judgement,
     * made by the person who declared it, and the report says so where the
     * level is printed.
     */
    public function riskLevel(int $lifetime, bool $trustAnchor): string
    {
        if ($lifetime >= self::LONG_TERM_YEARS || $trustAnchor) {
            return self::RISK_HIGH;
        }

        return self::RISK_MEDIUM;
    }

    /**
     * The year quantum-vulnerable public key cryptography stops being an option
     * for this particular data.
     *
     * Flat for every regime but one. Under the EU roadmap a high-risk use case
     * loses stand-alone quantum-vulnerable public-key mechanisms after the end
     * of 2030 and a medium-risk one after the end of 2035, so two domains in
     * the same repository can hold two different deadlines — which is the
     * roadmap's position, not a refinement of ours.
     */
    public function expiryFor(int $lifetime, bool $trustAnchor): int
    {
        if (!$this->graded() || $this->expiryOverridden) {
            return $this->expiryYear;
        }

        return $this->riskLevel($lifetime, $trustAnchor) === self::RISK_HIGH
            ? self::REGIMES[$this->regime]['deprecation']
            : self::REGIMES[$this->regime]['expiry'];
    }

    /**
     * First domain whose globs match. Order matters, so the file reads like a
     * list of rules rather than a set.
     *
     * @return array{name:string, lifetime:int, trust_anchor:bool, hybrid:bool, breached:string, declared:bool}
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
                        'hybrid' => $domain['hybrid'],
                        'breached' => $domain['breached'],
                        'declared' => true,
                    ];
                }
            }
        }

        // The label is translated: a hardcoded one printed French in every report.
        return ['name' => Lang::t('domain.undeclared'), 'lifetime' => $this->defaultLifetime, 'trust_anchor' => false, 'hybrid' => false, 'breached' => $this->breachedOn, 'declared' => false];
    }
}
