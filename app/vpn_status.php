<?php

declare(strict_types=1);

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

require_login();

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

    $requests = [];

    if ($type === 'wireguard' || $type === 'all') {
        $requests['wireguard.service'] = [
            'firewall' => $firewall,
            'path' => 'wireguard/service/status',
            'timeout' => 15,
        ];
        $requests['wireguard.tunnels'] = [
            'firewall' => $firewall,
            'path' => 'wireguard/service/show',
            'timeout' => 20,
        ];
    }

    if ($type === 'ipsec' || $type === 'all') {
        $requests['ipsec.service'] = [
            'firewall' => $firewall,
            'path' => 'ipsec/service/status',
            'timeout' => 15,
        ];
        $requests['ipsec.phase1'] = [
            'firewall' => $firewall,
            'path' => 'ipsec/sessions/search_phase1',
            'timeout' => 20,
        ];
        $requests['ipsec.phase2'] = [
            'firewall' => $firewall,
            'path' => 'ipsec/sessions/search_phase2',
            'timeout' => 20,
        ];
    }

    if ($type === 'openvpn' || $type === 'all') {
        $requests['openvpn.sessions'] = [
            'firewall' => $firewall,
            'path' => 'openvpn/service/search_sessions',
            'timeout' => 20,
        ];
        $requests['openvpn.routes'] = [
            'firewall' => $firewall,
            'path' => 'openvpn/service/search_routes',
            'timeout' => 20,
        ];
    }

    $parallel = opn_requests_parallel($requests);

    foreach ($parallel as $requestKey => $requestResult) {
        [$vpnType, $part] = explode('.', (string) $requestKey, 2);
        $result['data'][$vpnType][$part] = $requestResult;
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        $result,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    http_response_code(500);

    echo json_encode(
        [
            'ok' => false,
            'error' => $exception->getMessage(),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
