<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/ssh_access.php';

require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

$id = (int) ($_GET['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid firewall id.']);
    exit;
}

function ssh_tcp_probe(array $firewall, int $port = 22, float $timeout = 1.5): array
{
    $baseUrl = trim((string) ($firewall['base_url'] ?? ''));
    $host = parse_url($baseUrl, PHP_URL_HOST);
    $host = is_string($host) ? trim($host, '[]') : '';
    if ($host === '') {
        return ['reachable' => false, 'host' => '', 'port' => $port, 'error' => 'Could not resolve firewall host from Web/API URL.'];
    }

    $target = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ? 'tcp://[' . $host . ']:' . $port
        : 'tcp://' . $host . ':' . $port;

    $errno = 0;
    $errstr = '';
    $started = microtime(true);
    $socket = @stream_socket_client($target, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
    $elapsedMs = (int) round((microtime(true) - $started) * 1000);

    if (is_resource($socket)) {
        fclose($socket);
        return [
            'reachable' => true,
            'host' => $host,
            'port' => $port,
            'latency_ms' => $elapsedMs,
            'error' => null,
        ];
    }

    return [
        'reachable' => false,
        'host' => $host,
        'port' => $port,
        'latency_ms' => $elapsedMs,
        'error' => trim($errstr) !== '' ? trim($errstr) : ('TCP connect failed' . ($errno ? ' (' . $errno . ')' : '')),
    ];
}

try {
    $firewall = firewall_by_id($id);
    $probe = ssh_tcp_probe($firewall, 22);

    $managed = null;
    $managedError = null;
    try {
        $source = ssh_access_public_source();
        $managed = ssh_access_objects_status($firewall, $source);
    } catch (Throwable $exception) {
        $managedError = $exception->getMessage();
    }

    echo json_encode([
        'ok' => true,
        'ssh' => $probe,
        'managed' => $managed,
        'managed_error' => $managedError,
        'checked_at' => gmdate('c'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
