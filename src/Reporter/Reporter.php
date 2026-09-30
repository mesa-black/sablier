<?php

declare(strict_types=1);

namespace Sablier\Reporter;

use Sablier\Analysis;

/**
 * One way of rendering an analysis.
 *
 * The second real extension axis: an inventory that cannot leave the tool in the
 * format the reader needs is an inventory nobody acts on. HTML for the person
 * who decides, JSON for the pipeline that gates.
 */
interface Reporter
{
    public function render(Analysis $analysis): string;
}
