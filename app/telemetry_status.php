<?php

declare(strict_types=1);

ini_set('display_errors', '0');

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/update_check.php';
require_once __DIR__ . '/inc/telemetry.php';

require_login();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $force = isset($_GET['force']) && $_GET['force'] === '1';
    $state = $force ? telemetry_send(true) : telemetry_load_state();

    echo json_encode([
        'ok' => true,
        'configured' => telemetry_endpoint() !== '',
        'endpoint' => telemetry_endpoint() !== ''
            ? preg_replace('#^https://([^/]+).*$#', 'https://$1/…', telemetry_endpoint())
            : null,
        'state' => [
            'enabled' => ($state['enabled'] ?? false) === true,
            'last_attempt' => $state['last_attempt'] ?? null,
            'last_sent' => $state['last_sent'] ?? null,
            'last_status' => $state['last_status'] ?? null,
            'last_error' => $state['last_error'] ?? null,
        ],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
