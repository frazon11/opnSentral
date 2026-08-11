<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';

require_login();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

const SERVICES_CACHE_MAX_AGE = 300;
const SERVICES_API_TIMEOUT = 10;

function services_cache_path(): string
{
    return DATA_DIR . '/services-cache.json';
}

function services_read_cache(): ?array
{
    $path = services_cache_path();

    if (!is_file($path)) {
        return null;
    }

    $raw = file_get_contents($path);
    if ($raw === false) {
        return null;
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || !is_array($decoded['firewalls'] ?? null)) {
        return null;
    }

    $modified = filemtime($path);
    $age = $modified === false ? null : max(0, time() - $modified);

    return [
        'firewalls' => $decoded['firewalls'],
        'created_at' => $decoded['created_at'] ?? null,
        'age' => $age,
    ];
}

function services_write_cache(array $firewalls): void
{
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0770, true) && !is_dir(DATA_DIR)) {
        return;
    }

    $path = services_cache_path();
    $temporary = $path . '.tmp-' . bin2hex(random_bytes(4));

    $payload = json_encode(
        [
            'created_at' => gmdate('c'),
            'firewalls' => $firewalls,
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );

    if (file_put_contents($temporary, $payload, LOCK_EX) !== false) {
        @chmod($temporary, 0660);
        @rename($temporary, $path);
    } else {
        @unlink($temporary);
    }
}

function services_rows(array $response): array
{
    if (isset($response['rows']) && is_array($response['rows'])) {
        return $response['rows'];
    }

    foreach ($response as $value) {
        if (is_array($value) && array_is_list($value)) {
            return $value;
        }
    }

    return [];
}

function services_is_running(mixed $value): bool
{
    if (is_bool($value)) {
        return $value;
    }

    return in_array(
        strtolower(trim((string) $value)),
        ['1', 'true', 'yes', 'on', 'running', 'active'],
        true
    );
}

function services_fetch_live(array $firewalls): array
{
    $requests = [];

    foreach ($firewalls as $firewall) {
        $id = (int) $firewall['id'];

        $requests[(string) $id] = [
            'firewall' => $firewall,
            'path' => 'core/service/search',
            'method' => 'POST',
            'payload' => [
                'current' => 1,
                'rowCount' => -1,
                'sort' => new stdClass(),
                'searchPhrase' => '',
            ],
            'timeout' => SERVICES_API_TIMEOUT,
        ];
    }

    $results = opn_requests_parallel($requests);
    $output = [];

    foreach ($firewalls as $firewall) {
        $id = (int) $firewall['id'];
        $result = $results[(string) $id] ?? [
            'ok' => false,
            'error' => 'No result returned.',
        ];

        $entry = [
            'id' => $id,
            'name' => (string) $firewall['name'],
            'base_url' => (string) $firewall['base_url'],
            'ok' => ($result['ok'] ?? false) === true,
            'error' => null,
            'active_services' => [],
            'active_count' => 0,
            'total_count' => 0,
        ];

        if (($result['ok'] ?? false) !== true) {
            $entry['error'] = (string) ($result['error'] ?? 'Unavailable');
            $output[] = $entry;
            continue;
        }

        $rows = services_rows((array) $result['value']);
        $entry['total_count'] = count($rows);

        foreach ($rows as $row) {
            if (!is_array($row) || !services_is_running($row['running'] ?? false)) {
                continue;
            }

            $name = trim((string) ($row['name'] ?? $row['id'] ?? ''));
            $description = trim((string) ($row['description'] ?? ''));

            if ($name === '' && $description === '') {
                continue;
            }

            $entry['active_services'][] = [
                'id' => (string) ($row['id'] ?? $name),
                'name' => $name !== '' ? $name : $description,
                'description' => $description,
                'locked' => services_is_running($row['locked'] ?? false),
            ];
        }

        usort(
            $entry['active_services'],
            static fn(array $a, array $b): int =>
                strcasecmp(
                    $a['description'] !== '' ? $a['description'] : $a['name'],
                    $b['description'] !== '' ? $b['description'] : $b['name']
                )
        );

        $entry['active_count'] = count($entry['active_services']);
        $output[] = $entry;
    }

    services_write_cache($output);

    return [
        'firewalls' => $output,
        'created_at' => gmdate('c'),
        'age' => 0,
    ];
}

try {
    $force = isset($_GET['force']) && $_GET['force'] === '1';
    $cache = services_read_cache();
    $source = 'cache';

    if ($force || $cache === null) {
        $firewalls = db()
            ->query('SELECT * FROM firewalls ORDER BY name')
            ->fetchAll();

        $cache = services_fetch_live($firewalls);
        $source = 'live';
    }

    $age = is_int($cache['age']) ? $cache['age'] : null;

    echo json_encode(
        [
            'ok' => true,
            'firewalls' => $cache['firewalls'],
            'cache' => [
                'source' => $source,
                'age' => $age,
                'created_at' => $cache['created_at'],
                'refresh_recommended' =>
                    $source === 'cache' &&
                    ($age === null || $age >= SERVICES_CACHE_MAX_AGE),
            ],
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    http_response_code(500);

    echo json_encode(
        ['ok' => false, 'error' => $exception->getMessage()],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    );
}
