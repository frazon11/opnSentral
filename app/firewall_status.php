<?php

declare(strict_types=1);

/*
 * JSON endpoints must never mix PHP warning/fatal HTML with JSON.
 */
ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

register_shutdown_function(static function (): void {
    $error = error_get_last();

    if ($error === null || !in_array(
        $error['type'],
        [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR],
        true
    )) {
        return;
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => false,
            'error' => 'PHP fatal error: ' . $error['message'],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
});

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/firmware.php';

require_login();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

$id = (int) ($_GET['id'] ?? 0);
$type = (string) ($_GET['type'] ?? 'all');

try {
    $firewall = firewall_by_id($id);

    $result = [
        'ok' => true,
        'type' => $type,
        'data' => [],
    ];

    if ($type === 'system' || $type === 'all') {
        try {
            $result['data']['system'] = [
                'ok' => true,
                'value' => opn_request(
                    $firewall,
                    'core/system/status',
                    'GET',
                    [],
                    10
                ),
            ];
        } catch (Throwable $exception) {
            $result['data']['system'] = [
                'ok' => false,
                'error' => $exception->getMessage(),
            ];
        }
    }

    if ($type === 'firmware' || $type === 'all') {
        try {
            $value = opn_request(
                $firewall,
                'core/firmware/status',
                'GET',
                [],
                20
            );

            $result['data']['firmware'] = [
                'ok' => true,
                'value' => $value,
                'summary' => normalize_firmware_status($value),
            ];
        } catch (Throwable $exception) {
            $result['data']['firmware'] = [
                'ok' => false,
                'error' => $exception->getMessage(),
            ];
        }
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        $result,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    http_response_code(500);

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => false,
            'error' => $exception->getMessage(),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
