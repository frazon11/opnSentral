<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';

require_login();

// External OPNsense requests must not hold the user's PHP session lock.
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

const WG_CACHE_REFRESH_AGE = 300;
const WG_API_TIMEOUT = 5;

function overview_wg_rows(array $value): array
{
    if (isset($value['rows']) && is_array($value['rows'])) {
        return $value['rows'];
    }

    foreach ($value as $candidate) {
        if (is_array($candidate) && array_is_list($candidate)) {
            return $candidate;
        }
    }

    return [];
}

function overview_wg_enabled(mixed $value): bool
{
    return in_array(
        strtolower(trim((string) $value)),
        ['1', 'true', 'yes', 'on', 'enabled'],
        true
    );
}

function overview_wg_read_cache(): ?array
{
    $path = wireguard_inventory_cache_path();

    if (!is_file($path)) {
        return null;
    }

    $raw = file_get_contents($path);
    if ($raw === false) {
        return null;
    }

    $cached = json_decode($raw, true);
    if (
        !is_array($cached) ||
        !is_array($cached['inventory'] ?? null)
    ) {
        return null;
    }

    $modified = filemtime($path);
    $age = $modified === false
        ? null
        : max(0, time() - (int) $modified);

    return [
        'inventory' => $cached['inventory'],
        'errors' => is_array($cached['errors'] ?? null)
            ? $cached['errors']
            : [],
        'age' => $age,
        'created_at' => $cached['created_at'] ?? null,
    ];
}

function overview_wg_write_cache(array $inventory, array $errors): void
{
    if (!is_dir(DATA_DIR)) {
        @mkdir(DATA_DIR, 0770, true);
    }

    $temporary = wireguard_inventory_cache_path() .
        '.tmp-' .
        bin2hex(random_bytes(4));

    $payload = json_encode(
        [
            'created_at' => gmdate('c'),
            'inventory' => $inventory,
            'errors' => $errors,
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );

    if (file_put_contents($temporary, $payload, LOCK_EX) !== false) {
        @chmod($temporary, 0660);
        @rename($temporary, wireguard_inventory_cache_path());
    } else {
        @unlink($temporary);
    }
}

function overview_wg_fetch_inventory(array $firewalls): array
{
    $inventory = [];
    $errors = [];
    $requests = [];

    foreach ($firewalls as $firewall) {
        $id = (int) $firewall['id'];

        $inventory[$id] = [
            'firewall' => [
                'id' => $id,
                'name' => (string) $firewall['name'],
            ],
            'clients' => [],
            'servers' => [],
        ];

        $requests[$id . '.clients'] = [
            'firewall' => $firewall,
            'path' => 'wireguard/client/search_client',
            'timeout' => WG_API_TIMEOUT,
        ];

        $requests[$id . '.servers'] = [
            'firewall' => $firewall,
            'path' => 'wireguard/server/search_server',
            'timeout' => WG_API_TIMEOUT,
        ];
    }

    $parallel = opn_requests_parallel($requests);

    foreach ($firewalls as $firewall) {
        $id = (int) $firewall['id'];
        $clientResult = $parallel[$id . '.clients'] ?? [];
        $serverResult = $parallel[$id . '.servers'] ?? [];

        if (($clientResult['ok'] ?? false) !== true) {
            $errors[] = $firewall['name'] . ' clients: ' .
                ($clientResult['error'] ?? 'Unavailable');
        }

        if (($serverResult['ok'] ?? false) !== true) {
            $errors[] = $firewall['name'] . ' servers: ' .
                ($serverResult['error'] ?? 'Unavailable');
        }

        $clients = ($clientResult['ok'] ?? false) === true
            ? overview_wg_rows($clientResult['value'])
            : [];

        $servers = ($serverResult['ok'] ?? false) === true
            ? overview_wg_rows($serverResult['value'])
            : [];

        $inventory[$id]['clients'] = array_values(array_map(
            static fn(array $row): array => [
                'uuid' => (string) ($row['uuid'] ?? $row['id'] ?? ''),
                'name' => (string) (
                    $row['name'] ??
                    $row['description'] ??
                    ''
                ),
                'pubkey' => (string) (
                    $row['pubkey'] ??
                    $row['public-key'] ??
                    $row['public_key'] ??
                    ''
                ),
                'enabled' => overview_wg_enabled(
                    $row['enabled'] ?? '1'
                ),
            ],
            $clients
        ));

        $inventory[$id]['servers'] = array_values(array_map(
            static fn(array $row): array => [
                'uuid' => (string) ($row['uuid'] ?? $row['id'] ?? ''),
                'name' => (string) (
                    $row['name'] ??
                    $row['description'] ??
                    ''
                ),
                'pubkey' => (string) (
                    $row['pubkey'] ??
                    $row['public-key'] ??
                    $row['public_key'] ??
                    ''
                ),
                'enabled' => overview_wg_enabled(
                    $row['enabled'] ?? '1'
                ),
            ],
            $servers
        ));
    }

    overview_wg_write_cache($inventory, $errors);

    return [
        'inventory' => $inventory,
        'errors' => $errors,
        'age' => 0,
        'created_at' => gmdate('c'),
    ];
}

function overview_wg_connections(array $inventory): array
{
    $connections = [];
    $seen = [];

    foreach ($inventory as $localId => $local) {
        foreach ($local['clients'] as $localClient) {
            if (
                $localClient['uuid'] === '' ||
                $localClient['pubkey'] === ''
            ) {
                continue;
            }

            foreach ($inventory as $remoteId => $remote) {
                if ((int) $remoteId === (int) $localId) {
                    continue;
                }

                foreach ($remote['servers'] as $remoteServer) {
                    if ($remoteServer['pubkey'] !== $localClient['pubkey']) {
                        continue;
                    }

                    foreach ($local['servers'] as $localServer) {
                        if ($localServer['pubkey'] === '') {
                            continue;
                        }

                        foreach ($remote['clients'] as $remoteClient) {
                            if (
                                $remoteClient['uuid'] === '' ||
                                $remoteClient['pubkey'] !==
                                    $localServer['pubkey']
                            ) {
                                continue;
                            }

                            $pairIds = [(int) $localId, (int) $remoteId];
                            sort($pairIds, SORT_NUMERIC);

                            $pairKey =
                                implode(':', $pairIds) . ':' .
                                min(
                                    $localClient['uuid'],
                                    $remoteClient['uuid']
                                ) . ':' .
                                max(
                                    $localClient['uuid'],
                                    $remoteClient['uuid']
                                );

                            if (isset($seen[$pairKey])) {
                                continue;
                            }

                            $seen[$pairKey] = true;

                            $partial =
                                $localClient['enabled'] !==
                                $remoteClient['enabled'];

                            $enabled =
                                $localClient['enabled'] &&
                                $remoteClient['enabled'];

                            $connections[] = [
                                'pair_key' => $pairKey,
                                'status' => $partial
                                    ? 'partial'
                                    : ($enabled
                                        ? 'enabled'
                                        : 'disabled'),
                                'local' => [
                                    'firewall_id' => (int) $localId,
                                    'firewall_name' =>
                                        (string) $local['firewall']['name'],
                                    'client_uuid' => $localClient['uuid'],
                                    'client_name' => $localClient['name'],
                                    'enabled' => $localClient['enabled'],
                                    'expected_peer_key' =>
                                        $localClient['pubkey'],
                                ],
                                'remote' => [
                                    'firewall_id' => (int) $remoteId,
                                    'firewall_name' =>
                                        (string) $remote['firewall']['name'],
                                    'client_uuid' => $remoteClient['uuid'],
                                    'client_name' => $remoteClient['name'],
                                    'enabled' => $remoteClient['enabled'],
                                    'expected_peer_key' =>
                                        $remoteClient['pubkey'],
                                ],
                            ];
                        }
                    }
                }
            }
        }
    }

    usort(
        $connections,
        static fn(array $a, array $b): int =>
            strcasecmp(
                $a['local']['firewall_name'] .
                $a['remote']['firewall_name'],
                $b['local']['firewall_name'] .
                $b['remote']['firewall_name']
            )
    );

    return $connections;
}

try {
    $force = isset($_GET['force']) && $_GET['force'] === '1';
    $cache = overview_wg_read_cache();
    $source = 'cache';

    if ($force || $cache === null) {
        $firewalls = db()
            ->query('SELECT * FROM firewalls ORDER BY name')
            ->fetchAll();

        $cache = overview_wg_fetch_inventory($firewalls);
        $source = 'live';
    }

    $age = is_int($cache['age']) ? $cache['age'] : null;

    echo json_encode(
        [
            'ok' => true,
            'connections' => overview_wg_connections(
                $cache['inventory']
            ),
            'errors' => $cache['errors'],
            'cache' => [
                'source' => $source,
                'age' => $age,
                'refresh_recommended' =>
                    $source === 'cache' &&
                    ($age === null || $age >= WG_CACHE_REFRESH_AGE),
                'refresh_age' => WG_CACHE_REFRESH_AGE,
                'created_at' => $cache['created_at'],
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
