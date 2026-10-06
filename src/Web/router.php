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
    echo htmlspecialchars(Lang::t('web.no_session'));

    return true;
}

$path = parse_url(\Sablier\Value::string($_SERVER['REQUEST_URI'] ?? null, '/'), \PHP_URL_PATH);
$path = \is_string($path) ? $path : '/';

// A token only exists when the operator deliberately left the loopback. It is
// handed over once in the link, kept in a cookie, and checked on everything
// after that — enough to keep a stray visitor out of somebody's declaration,
// and not pretending to be more than that.
$token = $session->string('token');
if ($token !== '') {
    $given = \Sablier\Value::string($_GET['k'] ?? null);
    $held = \Sablier\Value::string($_COOKIE['sablier'] ?? null);
    if ($given !== '' && hash_equals($token, $given)) {
        // Secure when the public leg is TLS, which only the proxy in front can
        // say: a cookie that carries the key has no business travelling in
        // clear once somebody took the trouble to terminate HTTPS.
        $https = \Sablier\Value::string($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null) === 'https';
        setcookie('sablier', $token, ['path' => '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => $https]);
    } elseif (!hash_equals($token, $held)) {
        http_response_code(403);
        echo htmlspecialchars(Lang::t('web.incomplete_link'));

        return true;
    }
}

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
