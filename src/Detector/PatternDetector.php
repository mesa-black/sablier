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
abstract class PatternDetector implements Detector
{
    protected const string CAPTURE = 'capture';

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
                $resolved = $algorithm === self::CAPTURE
                    ? Catalogue::normalise($matches[1][$index][0] ?? '')
                    : $algorithm;

                // An algorithm we do not know is not ours to judge.
                if ($algorithm === self::CAPTURE && $resolved === null) {
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
