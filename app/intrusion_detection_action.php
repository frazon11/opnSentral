<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();
require_csrf();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
http_response_code(503);

echo json_encode([
    'ok' => false,
    'error' => 'Intrusion Detection writes are temporarily disabled while the OPNsense IDS MVC write contract is being hardened. The IDS pages remain read-only; this endpoint performs no configuration change.'
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
