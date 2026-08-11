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
    $state = telemetry_send(false);
    echo json_encode([
        'ok' => true,
        'status' => $state['last_status'] ?? null,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    // Telemetry must never affect normal opnCentral operation.
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
