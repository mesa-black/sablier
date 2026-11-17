<?php

declare(strict_types=1);

namespace Sablier\Ots;

/**
 * The one HTTP call this part of the tool makes, written once.
 *
 * The same mechanism as the RFC 3161 request in Timestamp: PHP's own stream
 * wrapper, no curl extension assumed, a timeout short enough that a build does
 * not hang on a calendar having a bad day. Two things differ, both because the
 * answers here are read by a parser rather than by openssl: the body is capped
 * (a calendar answer is a few hundred bytes; the reference refuses anything
 * over 10,000), and redirects are not followed — the reference follows one
 * only to the same host over https, and a calendar that moves can be named by
 * its new address instead.
 */
final class Http
{
    /** The same budget as an RFC 3161 authority gets. */
    public const int TIMEOUT = 20;

    /**
     * @param list<string> $headers
     *
     * @return array{status:int, body:string}|null null when nothing answered
     */
    public static function request(string $method, string $url, string $body = '', array $headers = [], int $limit = 10000): ?array
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", [...$headers, 'Content-Length: '.\strlen($body)])."\r\n",
                'content' => $body,
                'timeout' => self::TIMEOUT,
                'follow_location' => 0,
                // A 404 says "still pending"; an exception would throw that away.
                'ignore_errors' => true,
            ],
        ]);

        // Cleared first: a request that never connects would otherwise report
        // the status of the previous one.
        http_clear_last_response_headers();
        $answer = @file_get_contents($url, false, $context, 0, max(1, $limit + 1));
        $status = 0;
        foreach (http_get_last_response_headers() ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }
        if ($answer === false || $status === 0) {
            return null;
        }
        if (\strlen($answer) > $limit) {
            return ['status' => 413, 'body' => ''];
        }

        return ['status' => $status, 'body' => $answer];
    }
}
