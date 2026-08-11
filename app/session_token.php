<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

echo json_encode(
    ['ok' => true, 'csrf' => csrf_token()],
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
);
