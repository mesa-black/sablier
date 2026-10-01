<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\Lang;
use Sablier\SourceFile;
use Sablier\Value;

/**
 * SSH, which is where deployment credentials actually live.
 *
 * Worth its own detector because SSH names its algorithms in a vocabulary
 * nothing else uses, and because it is the one protocol here where a
 * post-quantum key exchange has been shipping and enabled by default for years:
 * `sntrup761x25519-sha512` is a hybrid, and finding it is good news the rest of
 * this report rarely gets to deliver.
 */
final class SshConfigDetector implements DetectorInterface
{
    private const array FILENAMES = ['sshd_config', 'ssh_config', 'config'];

    public function supports(SourceFile $file): bool
    {
        if (\in_array($file->name, self::FILENAMES, true)) {
            // A bare "config" is only SSH's when it sits in an ssh directory.
            return $file->name !== 'config' || str_contains($file->relativePath, 'ssh');
        }

        return str_ends_with($file->name, '.sshd_config') || $file->hasExtension('sshd');
    }

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();

        if (preg_match_all('/^\s*KexAlgorithms\s+([^\n#]+)/mi', $content, $matches, \PREG_OFFSET_CAPTURE) > 0) {
            foreach ($matches[0] as $index => [$hit, $offset]) {
                $offset = Value::int($offset);
                $value = strtolower($matches[1][$index][0]);
                $hybrid = str_contains($value, 'sntrup') || str_contains($value, 'mlkem') || str_contains($value, 'kyber');

                yield new Finding(
                    algorithm: $hybrid ? 'ml-kem' : 'ecdh',
                    purpose: Catalogue::PURPOSE_CONFIDENTIALITY,
                    file: $file->relativePath,
                    line: $file->lineAt($offset),
                    evidence: trim($hit),
                    detail: Lang::t($hybrid ? 'detail.ssh.hybrid_kex' : 'detail.ssh.classical_kex'),
                );
            }
        }

        foreach ([
            '/^\s*(?:HostKeyAlgorithms|PubkeyAcceptedAlgorithms)\s+([^\n#]+)/mi' => Catalogue::PURPOSE_AUTHENTICITY,
            '/^\s*Ciphers\s+([^\n#]+)/mi' => Catalogue::PURPOSE_CONFIDENTIALITY,
        ] as $pattern => $purpose) {
            if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }

            foreach ($matches[0] as $index => [$hit, $offset]) {
                $offset = Value::int($offset);
                $value = strtolower($matches[1][$index][0]);
                $algorithm = $purpose === Catalogue::PURPOSE_AUTHENTICITY
                    ? $this->hostKeyAlgorithm($value)
                    : $this->cipher($value);

                if ($algorithm === null) {
                    continue;
                }

                yield new Finding(
                    algorithm: $algorithm,
                    purpose: $purpose,
                    file: $file->relativePath,
                    line: $file->lineAt($offset),
                    evidence: trim($hit),
                    detail: Lang::t($purpose === Catalogue::PURPOSE_AUTHENTICITY ? 'detail.ssh.host_key' : 'detail.ssh.cipher'),
                );
            }
        }
    }

    /** The weakest thing still allowed is what the line is worth reporting for. */
    private function hostKeyAlgorithm(string $value): ?string
    {
        return match (true) {
            str_contains($value, 'ssh-rsa'), str_contains($value, 'rsa-sha2') => 'rsa-sign',
            str_contains($value, 'ecdsa') => 'ecdsa',
            str_contains($value, 'ed25519') => 'ed25519',
            default => null,
        };
    }

    private function cipher(string $value): ?string
    {
        return match (true) {
            str_contains($value, '3des'), str_contains($value, 'des-cbc') => 'des',
            str_contains($value, 'arcfour'), str_contains($value, 'rc4') => 'rc4',
            str_contains($value, 'aes128') => 'aes-128',
            str_contains($value, 'chacha20') => 'chacha20',
            str_contains($value, 'aes256') => 'aes-256',
            default => null,
        };
    }
}
