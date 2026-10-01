<?php

declare(strict_types=1);

/*
 * The whole web interview, served by PHP's own server and nothing else.
 *
 *   php -S 127.0.0.1:8765 src/Web/router.php
 *
 * Bound to the loopback, started by `sablier serve`, and gone when that command
 * ends. There is no framework here and no dependency to add one: a form, a file
 * in the temporary directory, and four routes.
 */

spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'Sablier\\')) {
        $path = __DIR__.'/../../src/'.str_replace('\\', '/', substr($class, 8)).'.php';
        if (is_file($path)) {
            require $path;
        }
    }
});

use Sablier\Lang;
use Sablier\Web\Interview;
use Sablier\Web\Session;

Lang::use(getenv('SABLIER_LANG') ?: 'fr');

$session = Session::open((string) getenv('SABLIER_SESSION'));
if ($session === null) {
    http_response_code(500);
    echo 'session introuvable';

    return true;
}

$path = parse_url(\Sablier\Value::string($_SERVER['REQUEST_URI'] ?? null, '/'), \PHP_URL_PATH);
$path = \is_string($path) ? $path : '/';

// The report is a file this interview just produced: it is served, not routed.
if ($path === '/report') {
    $report = $session->string('report');
    if (is_file($report)) {
        header('Content-Type: text/html; charset=utf-8');
        readfile($report);

        return true;
    }
}

$post = [];
foreach ($_POST as $key => $value) {
    if (\is_string($key) && \is_string($value)) {
        $post[$key] = $value;
    }
}

echo (new Interview($session))->handle(\Sablier\Value::string($_SERVER['REQUEST_METHOD'] ?? null, 'GET'), $path, $post);

return true;
