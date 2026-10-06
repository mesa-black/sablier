<?php

declare(strict_types=1);

namespace Sablier;

/**
 * What the analysis looked for and did not find.
 *
 * The report has always printed what it could not see. That is half a sentence.
 * "No private key in this repository" and "nobody looked for one" arrive on the
 * page as the same silence, and the second is worth nothing while the first is
 * exactly what an auditor came for.
 *
 * So this is the other box: every line here means **a detector opened files and
 * produced nothing**, which is a measured claim rather than an absence of
 * output. Three rules keep it from becoming reassurance:
 *
 * - **A detector that opened no file makes no claim.** Saying "no Terraform
 *   resource leaves a volume unencrypted" about a repository with no Terraform
 *   in it would be true and dishonest at once, which is the worst combination a
 *   report can print.
 * - **Only detectors whose absence means something are listed.** Some look at
 *   every PHP file and bail on the first line unless the file belongs to their
 *   framework; counting those files as "examined" would turn a guard clause into
 *   an inspection. They are simply not in the table below.
 * - **Each line names what was searched and how much was read**, so the reader
 *   can judge the claim rather than take it. A number is checkable; "nothing
 *   found" is not.
 */
final class Absences
{
    /**
     * The detectors whose silence is a finding, and what that silence says.
     *
     * A detector absent from this table never produces a line, which is the
     * conservative direction: a missing claim costs a reader nothing, a claim
     * that overstates what was examined costs them the whole document.
     *
     * The second value is the number the sentence should carry. Most detectors
     * select their files by name and the right denominator is what they opened.
     * One does not: the key detector decides by reading every file's content,
     * so counting the files it "supported" would print "2 files read: no
     * private key in the versioned tree" about a repository of a hundred and
     * thirty — a true sentence with a number that quietly contradicts it.
     *
     */
    private const string SUPPORTED = 'supported';
    private const string TREE = 'tree';

    /** @var array<string, array{0:string, 1:string}> */
    private const array CLAIMS = [
        'PhpDetector' => ['absence.php', self::SUPPORTED],
        'KeyMaterialDetector' => ['absence.keys', self::TREE],
        'AssetDetector' => ['absence.assets', self::SUPPORTED],
        'DependencyDetector' => ['absence.dependencies', self::SUPPORTED],
        'EnvDetector' => ['absence.env', self::SUPPORTED],
        'ServerConfigDetector' => ['absence.server', self::SUPPORTED],
        'SshConfigDetector' => ['absence.ssh', self::SUPPORTED],
        'TerraformDetector' => ['absence.terraform', self::SUPPORTED],
        'FrameworkConfigDetector' => ['absence.framework', self::SUPPORTED],
        'FrameworkYamlDetector' => ['absence.yaml', self::SUPPORTED],
        'ShellDetector' => ['absence.shell', self::SUPPORTED],
    ];

    /** @return list<string> */
    public static function for(Analysis $analysis): array
    {
        $lines = [];
        foreach (self::CLAIMS as $detector => [$key, $scope]) {
            $tally = $analysis->searched[$detector] ?? null;
            // Something found: it is in the inventory, and a line here would
            // contradict it.
            if ($tally === null || $tally['findings'] > 0) {
                continue;
            }

            $read = $scope === self::TREE ? $analysis->filesRead : $tally['files'];
            // Nothing opened, nothing to say. A repository with no Terraform in
            // it must not be told that its Terraform is clean.
            if ($read === 0) {
                continue;
            }

            $lines[] = Lang::t($key, $read);
        }

        return $lines;
    }
}
