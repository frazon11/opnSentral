<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/network_settings.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

echo json_encode([
    'ok' => true,
    'disable_ipv6' => opnsense_ipv6_disabled(),
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
