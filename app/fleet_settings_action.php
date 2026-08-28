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
    'error' => 'General and Advanced fleet writes are disabled because the current opnSentral agent intentionally rejects these job types. Read-only comparison remains available; no backup, configuration change, or agent job was created.'
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
