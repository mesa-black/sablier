<?php

declare(strict_types=1);

namespace Sablier\Detector;

use Sablier\Finding;
use Sablier\SourceFile;

/**
 * One way of finding cryptography in one kind of file.
 *
 * This is the project's single extension point, and it exists because the
 * scoping study names extension as a planned axis: other languages, other
 * ecosystems, other file formats. Everything else here has one implementation
 * and no second one in sight, so it stays concrete — an interface with a single
 * implementation and no prospect of another is a cost with no buyer.
 */
interface DetectorInterface
{
    /** Cheap decision, made on the file's name alone where possible. */
    public function supports(SourceFile $file): bool;

    /**
     * @return iterable<Finding>
     */
    public function detect(SourceFile $file): iterable;

    /**
     * What this detector knows it could not see in the files it read. Printed in
     * the report: a detector that stays silent about its limits makes the whole
     * inventory dishonest.
     *
     * @return list<string>
     */
    public function blindSpots(): array;
}
