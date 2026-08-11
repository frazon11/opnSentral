<?php

declare(strict_types=1);

ini_set('display_errors', '0');
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/update_check.php';

require_login();
require_csrf();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $state = update_check_load();
    $state['enabled'] = isset($_POST['enabled']) &&
        filter_var($_POST['enabled'], FILTER_VALIDATE_BOOL);
    update_check_save($state);

    echo json_encode([
        'ok' => true,
        'enabled' => $state['enabled'],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
