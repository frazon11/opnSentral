<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();
require_csrf();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
http_response_code(503);

echo json_encode([
    'ok' => false,
    'error' => 'Administration fleet writes are temporarily disabled after a confirmed remote lockout incident. Read-only comparison remains available; no configuration change will be queued from this endpoint.'
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
