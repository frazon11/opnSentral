<?php

declare(strict_types=1);

ini_set('display_errors', '0');

require_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['ok' => false, 'error' => 'POST required.'], 405);
}

require_write_token();

$contentType = strtolower(
    trim((string) ($_SERVER['CONTENT_TYPE'] ?? ''))
);
if (!str_starts_with($contentType, 'application/json')) {
    json_response(
        ['ok' => false, 'error' => 'application/json required.'],
        415
    );
}

$length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($length < 2 || $length > 4096) {
    json_response(
        ['ok' => false, 'error' => 'Invalid request size.'],
        413
    );
}

$raw = file_get_contents('php://input');
$data = json_decode((string) $raw, true);

if (!is_array($data)) {
    json_response(['ok' => false, 'error' => 'Invalid JSON.'], 400);
}

$installationHash = strtolower(
    trim((string) ($data['installation_hash'] ?? ''))
);
$version = trim((string) ($data['version'] ?? ''));
$architecture = strtolower(
    trim((string) ($data['architecture'] ?? 'unknown'))
);
$platform = strtolower(
    trim((string) ($data['platform'] ?? 'docker'))
);

if (!preg_match('/^[a-f0-9]{64}$/', $installationHash)) {
    json_response(
        ['ok' => false, 'error' => 'Invalid installation hash.'],
        400
    );
}

if (!preg_match('/^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/', $version)) {
    json_response(['ok' => false, 'error' => 'Invalid version.'], 400);
}

if (!preg_match('/^[a-z0-9._-]{1,32}$/', $architecture)) {
    json_response(
        ['ok' => false, 'error' => 'Invalid architecture.'],
        400
    );
}

if (!preg_match('/^[a-z0-9._-]{1,32}$/', $platform)) {
    json_response(['ok' => false, 'error' => 'Invalid platform.'], 400);
}

$now = gmdate('c');
$statement = telemetry_db()->prepare(
    'INSERT INTO installations (
        installation_hash,
        first_seen,
        last_seen,
        version,
        architecture,
        platform,
        checks
    ) VALUES (
        :installation_hash,
        :first_seen,
        :last_seen,
        :version,
        :architecture,
        :platform,
        1
    )
    ON CONFLICT(installation_hash) DO UPDATE SET
        last_seen = excluded.last_seen,
        version = excluded.version,
        architecture = excluded.architecture,
        platform = excluded.platform,
        checks = installations.checks + 1'
);

$statement->execute([
    'installation_hash' => $installationHash,
    'first_seen' => $now,
    'last_seen' => $now,
    'version' => $version,
    'architecture' => $architecture,
    'platform' => $platform,
]);

cleanup_old_installations();

json_response([
    'ok' => true,
    'accepted_at' => $now,
]);
