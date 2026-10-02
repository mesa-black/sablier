<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Catalogue;
use Sablier\Finding;
use Sablier\SourceFile;
use Sablier\Value;

/**
 * Shared machinery for detectors that recognise cryptography by pattern.
 *
 * Subclasses provide a rule table and nothing else. The two literals below are
 * the contract: 'capture' resolves the algorithm from the first capture group,
 * null means "cryptography is here but we cannot name it" — reported as
 * undetermined, never inferred.
 */
abstract class PatternDetector implements DetectorInterface
{
    protected const string CAPTURE = 'capture';

    /** Same capture, prefixed: HMAC-SHA-1 is not SHA-1 and must not be judged as one. */
    protected const string CAPTURE_HMAC = 'capture-hmac';

    /**
     * @return list<array{0:string, 1:string|null, 2:string, 3:string}> pattern, algorithm, purpose, detail key
     */
    abstract protected function rules(): array;

    public function blindSpots(): array
    {
        return [];
    }

    public function detect(SourceFile $file): iterable
    {
        $content = $file->content();

        foreach ($this->rules() as [$pattern, $algorithm, $purpose, $detail]) {
            if (preg_match_all($pattern, $content, $matches, \PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }

            foreach ($matches[0] as $index => [, $offset]) {
                $offset = Value::int($offset);
                $captured = \in_array($algorithm, [self::CAPTURE, self::CAPTURE_HMAC], true);
                $resolved = $captured
                    ? Catalogue::normalise($matches[1][$index][0] ?? '')
                    : $algorithm;
                if ($algorithm === self::CAPTURE_HMAC && $resolved !== null) {
                    // Only the outdated digests get an HMAC entry of their own.
                    // HMAC-SHA-256 is judged as SHA-256, which is the same
                    // answer by a shorter road.
                    $resolved = Catalogue::get('hmac-'.$resolved) !== null ? 'hmac-'.$resolved : $resolved;
                }

                // An algorithm we do not know is not ours to judge.
                if ($captured && $resolved === null) {
                    continue;
                }

                $finding = $this->finding($file, $offset, $resolved, $purpose, $detail);
                if ($finding !== null) {
                    yield $finding;
                }
            }
        }
    }

    protected function finding(SourceFile $file, int $offset, ?string $algorithm, string $purpose, string $detail): ?Finding
    {
        // A match inside a comment is somebody describing the code, not the
        // code. PHPMailer documents its own HMAC with the call it replaces, and
        // that sentence was reported as a cryptographic use.
        if ($file->isCommentAt($offset)) {
            return null;
        }

        return new Finding(
            algorithm: $algorithm ?? 'undetermined',
            purpose: $purpose,
            file: $file->relativePath,
            line: $file->lineAt($offset),
            evidence: trim($file->lineTextAt($offset)),
            confidence: $algorithm === null ? Finding::CONFIDENCE_MEDIUM : Finding::CONFIDENCE_HIGH,
            detail: $detail === '' ? '' : \Sablier\Lang::t($detail),
        );
    }
}
