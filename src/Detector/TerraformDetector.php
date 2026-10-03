<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\SourceFile;

/**
 * The cryptography of the managed services, as far as a file can tell.
 *
 * Every report this tool writes carries the same admission: the cryptography of
 * your database, your object storage and your TLS termination appears in no
 * file of the repository. That is true of an application repository. It stops
 * being true the moment the infrastructure is declared as code, and that is a
 * large share of the projects this tool is pointed at.
 *
 * What is read here is the *intent*: `storage_encrypted = false` is a decision
 * somebody wrote down, and a managed database holding data with a ten-year
 * lifetime is the same finding as a backup script with no encryption — the
 * provider does not change the arithmetic. What this cannot say is what the
 * provider actually does behind the declaration, which is why the blind spot
 * stays in the report, reworded rather than removed.
 */
final class TerraformDetector extends PatternDetector
{
    public function supports(SourceFile $file): bool
    {
        return $file->hasExtension('tf');
    }

    protected function rules(): array
    {
        return [
            // Encryption turned off on purpose. The attribute is only ever
            // written when somebody considered it, which makes `false` a
            // decision rather than a default.
            ['/^\s*storage_encrypted\s*=\s*false\b/mi', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.at_rest'],
            ['/^\s*encrypted\s*=\s*false\b/mi', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.at_rest'],
            ['/^\s*at_rest_encryption_enabled\s*=\s*false\b/mi', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.at_rest'],

            // …and in transit.
            ['/^\s*enable_https_traffic_only\s*=\s*false\b/mi', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.in_transit'],
            ['/^\s*(?:ssl_enforcement_enabled|transit_encryption_enabled)\s*=\s*(?:false|"?[Dd]isabled"?)/m', 'plaintext', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.in_transit'],

            // What protects the objects at rest when it is switched on. Both
            // values are AES-256; the difference is whose key, which the report
            // says in the detail rather than in the verdict.
            ['/sse_algorithm\s*=\s*"aws:kms"/i', 'aes-256', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.sse_kms'],
            ['/sse_algorithm\s*=\s*"AES256"/i', 'aes-256', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.sse_managed'],

            // A floor somebody set below what is still negotiable today.
            ['/(?:minimum_protocol_version|min_tls_version)\s*=\s*"(?:TLSv1(?:\.1)?|TLS1_[01])"/i', 'tls-obsolete', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.tls_floor'],
            ['/ssl_policy\s*=\s*"[^"]*TLS-1-[01][^"]*"/i', 'tls-obsolete', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.tls_floor'],

            // Keys the infrastructure creates for itself.
            ['/algorithm\s*=\s*"RSA"/i', 'rsa-sign', Catalogue::PURPOSE_AUTHENTICITY, 'detail.tf.key'],
            ['/algorithm\s*=\s*"ECDSA"/i', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, 'detail.tf.key'],
            ['/algorithm\s*=\s*"ED25519"/i', 'ed25519', Catalogue::PURPOSE_AUTHENTICITY, 'detail.tf.key'],

            // A KMS key that is asymmetric is the one case where the provider's
            // key management stops being a symmetric black box.
            ['/customer_master_key_spec\s*=\s*"RSA_\d+"/i', 'rsa', Catalogue::PURPOSE_CONFIDENTIALITY, 'detail.tf.kms_spec'],
            ['/customer_master_key_spec\s*=\s*"ECC_[A-Z0-9_]+"/i', 'ecdsa', Catalogue::PURPOSE_AUTHENTICITY, 'detail.tf.kms_spec'],
        ];
    }
}
