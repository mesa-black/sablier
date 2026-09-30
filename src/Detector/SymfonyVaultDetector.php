<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;

/**
 * Symfony's secrets vault.
 *
 * A case the rest of this tool would miss, and one of the clearest examples of
 * the whole thesis: the vault seals every production secret with a libsodium
 * sealed box, which is X25519 — quantum-vulnerable — and those secrets are
 * long-lived by nature. Anyone who copies the vault today, from a backup or a
 * repository, decrypts it the day the curve falls. Rotating the secrets later
 * does not help: what was sealed has already been copied.
 */
final class SymfonyVaultDetector implements Detector
{
    public function supports(SourceFile $file): bool
    {
        return str_contains($file->relativePath, 'config/secrets/')
            && (str_ends_with($file->name, '.encrypt.public.php')
                || str_ends_with($file->name, '.decrypt.private.php')
                || str_ends_with($file->name, '.list.php'));
    }

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        // The public key alone identifies the vault; the other files would
        // report the same fact three times.
        if (!str_ends_with($file->name, '.encrypt.public.php')) {
            return;
        }

        yield new Finding(
            algorithm: 'ecdh',
            purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
            file: $file->relativePath,
            line: 1,
            evidence: $file->name,
            detail: Lang::t('detail.symfony.vault'),
        );
    }
}
