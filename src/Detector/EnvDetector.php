<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;

/**
 * Environment files, read for how they connect rather than for what they hold.
 *
 * Two absolute rules here, because this detector reads the one file in a
 * project that is made of secrets:
 *
 *  · no value is ever copied into a finding. The evidence line carries the
 *    variable name and the connection setting, never what comes after the
 *    equals sign. A security report that leaks the secrets it audits is worse
 *    than no report;
 *  · nothing is judged on entropy or on looking "weak". That is somebody
 *    else's tool, and guessing there produces noise.
 *
 * What it does look for is the setting that decides whether a connection is
 * encrypted at all — and `sslmode=prefer`, the historical default of several
 * PostgreSQL clients, silently falls back to cleartext when the server says no.
 */
final class EnvDetector implements DetectorInterface
{
    public function supports(SourceFile $file): bool
    {
        return str_starts_with($file->name, '.env') || $file->hasExtension('env');
    }

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        foreach (explode("\n", $file->content()) as $number => $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
                continue;
            }

            [$name, $value] = explode('=', $line, 2);
            $name = trim($name);
            $value = strtolower(trim($value, " \t\"'"));

            $finding = $this->inspect($file, $number + 1, $name, $value);
            if ($finding !== null) {
                yield $finding;
            }
        }
    }

    private function inspect(SourceFile $file, int $line, string $name, string $value): ?Finding
    {
        if (preg_match('/[?&]sslmode=([a-z-]+)/', $value, $m) === 1) {
            return match ($m[1]) {
                'disable' => $this->finding($file, $line, 'plaintext', $name, 'sslmode=disable', 'detail.env.sslmode_disable'),
                'allow', 'prefer' => $this->finding($file, $line, 'plaintext', $name, 'sslmode='.$m[1], 'detail.env.sslmode_prefer'),
                'require' => $this->finding($file, $line, 'ecdh', $name, 'sslmode=require', 'detail.env.sslmode_require'),
                default => $this->finding($file, $line, 'ecdh', $name, 'sslmode='.$m[1], 'detail.env.sslmode_verify'),
            };
        }

        // A database URL with no sslmode at all leaves the decision to the
        // client's default, which differs by driver and by version.
        if (preg_match('#^(postgres|postgresql|mysql)://#', $value) === 1) {
            return $this->finding($file, $line, 'plaintext', $name, 'sslmode absent', 'detail.env.no_sslmode');
        }

        if (str_starts_with($value, 'smtp://') && !str_contains($value, ':465') && !str_contains($value, ':587')) {
            return $this->finding($file, $line, 'plaintext', $name, 'smtp', 'detail.env.smtp_plain');
        }

        if (str_contains($value, 'verify_peer=0') || str_contains($value, 'verify_peer=false')) {
            return $this->finding($file, $line, 'ecdh', $name, 'verify_peer=0', 'detail.env.no_verify');
        }

        return null;
    }

    private function finding(SourceFile $file, int $line, string $algorithm, string $name, string $setting, string $detail): Finding
    {
        // A committed .env describes a development default; the deployed value
        // lives in a file that is not in the repository. Reporting the local
        // Docker database as a production breach is the fastest way to lose a
        // reader — so anything that is not explicitly a production file is
        // marked as declared rather than observed.
        $deployed = str_contains(strtolower($file->name), 'prod');

        return new Finding(
            algorithm: $algorithm,
            purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
            file: $file->relativePath,
            line: $line,
            // Name and setting only. Never the value.
            evidence: $name.' — '.$setting,
            detail: Lang::t($detail).($deployed ? '' : ' '.Lang::t('detail.env.not_deployed')),
            inventory: !$deployed,
        );
    }
}
