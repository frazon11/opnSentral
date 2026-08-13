<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$path = __DIR__ . '/opnsentral-agent';
if (!is_file($path) || !is_readable($path)) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'error' => 'Agent binary is unavailable.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$binary = file_get_contents($path);
if (!is_string($binary) || strlen($binary) < 1000 || !str_starts_with($binary, '#!/usr/local/bin/php')) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'error' => 'Agent binary is invalid.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$sha256 = hash('sha256', $binary);
$version = null;
if (preg_match("/const AGENT_VERSION = '([^']+)'/", $binary, $match)) {
    $version = (string) $match[1];
}

if ($version === null || !preg_match('/^[0-9A-Za-z.+_-]{1,64}$/', $version)) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'error' => 'Agent version is unavailable.'], JSON_UNESCAPED_SLASHES);
    exit;
}

echo json_encode([
    'ok' => true,
    'agent_url' => '/agent/opnsentral-agent',
    'agent_sha256' => $sha256,
    'agent_size' => strlen($binary),
    'agent_version' => $version,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
