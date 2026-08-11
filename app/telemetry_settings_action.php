<?php

declare(strict_types=1);

ini_set('display_errors', '0');

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/update_check.php';
require_once __DIR__ . '/inc/telemetry.php';

require_login();
require_csrf();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $state = telemetry_load_state();
    $state['enabled'] =
        isset($_POST['enabled']) &&
        filter_var($_POST['enabled'], FILTER_VALIDATE_BOOL);

    telemetry_installation_secret($state);

    if (!$state['enabled']) {
        $state['last_status'] = 'disabled';
        $state['last_error'] = null;
    }

    telemetry_save_state($state);

    if ($state['enabled']) {
        $state = telemetry_send(true);
    }

    echo json_encode([
        'ok' => true,
        'state' => [
            'enabled' => $state['enabled'],
            'last_attempt' => $state['last_attempt'],
            'last_sent' => $state['last_sent'],
            'last_status' => $state['last_status'],
            'last_error' => $state['last_error'],
        ],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
