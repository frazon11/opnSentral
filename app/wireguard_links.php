<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';

require_login();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

function wg_rows(array $value): array
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

function wg_enabled(mixed $value): bool
{
    return in_array(strtolower(trim((string) $value)), ['1', 'true', 'yes', 'on', 'enabled'], true);
}

try {
    $currentId = (int) ($_GET['id'] ?? 0);
    if ($currentId < 1) {
        throw new RuntimeException('Invalid firewall ID.');
    }

    $firewalls = db()->query('SELECT * FROM firewalls ORDER BY name')->fetchAll();
    $inventory = [];
    $errors = [];
    $cacheHit = false;
    $cacheTtl = 30;
    $cachePath = wireguard_inventory_cache_path();

    if (
        is_file($cachePath) &&
        filemtime($cachePath) !== false &&
        (time() - (int) filemtime($cachePath)) < $cacheTtl
    ) {
        $cached = json_decode((string) file_get_contents($cachePath), true);

        if (
            is_array($cached) &&
            isset($cached['inventory']) &&
            is_array($cached['inventory'])
        ) {
            $inventory = $cached['inventory'];
            $errors = is_array($cached['errors'] ?? null)
                ? $cached['errors']
                : [];
            $cacheHit = true;
        }
    }

    if (!$cacheHit) {
        $requests = [];

        foreach ($firewalls as $firewall) {
            $id = (int) $firewall['id'];
            $requests[$id . '.clients'] = [
                'firewall' => $firewall,
                'path' => 'wireguard/client/search_client',
                'timeout' => 12,
            ];
            $requests[$id . '.servers'] = [
                'firewall' => $firewall,
                'path' => 'wireguard/server/search_server',
                'timeout' => 12,
            ];

            $inventory[$id] = [
                'firewall' => [
                    'id' => $id,
                    'name' => (string) $firewall['name'],
                ],
                'clients' => [],
                'servers' => [],
            ];
        }

        $parallel = opn_requests_parallel($requests);

        foreach ($firewalls as $firewall) {
            $id = (int) $firewall['id'];
            $clientResult = $parallel[$id . '.clients'] ?? null;
            $serverResult = $parallel[$id . '.servers'] ?? null;

            if (($clientResult['ok'] ?? false) !== true) {
                $errors[] =
                    (string) $firewall['name'] .
                    ' clients: ' .
                    (string) ($clientResult['error'] ?? 'Unavailable');
            }

            if (($serverResult['ok'] ?? false) !== true) {
                $errors[] =
                    (string) $firewall['name'] .
                    ' servers: ' .
                    (string) ($serverResult['error'] ?? 'Unavailable');
            }

            $clients = ($clientResult['ok'] ?? false) === true
                ? wg_rows($clientResult['value'])
                : [];
            $servers = ($serverResult['ok'] ?? false) === true
                ? wg_rows($serverResult['value'])
                : [];

            $inventory[$id]['clients'] = array_values(array_map(
                static function (array $row): array {
                    return [
                        'uuid' => (string) ($row['uuid'] ?? $row['id'] ?? ''),
                        'name' => (string) ($row['name'] ?? $row['description'] ?? ''),
                        'pubkey' => (string) ($row['pubkey'] ?? $row['public-key'] ?? $row['public_key'] ?? ''),
                        'enabled' => wg_enabled($row['enabled'] ?? '1'),
                    ];
                },
                $clients
            ));

            $inventory[$id]['servers'] = array_values(array_map(
                static function (array $row): array {
                    return [
                        'uuid' => (string) ($row['uuid'] ?? $row['id'] ?? ''),
                        'name' => (string) ($row['name'] ?? $row['description'] ?? ''),
                        'pubkey' => (string) ($row['pubkey'] ?? $row['public-key'] ?? $row['public_key'] ?? ''),
                        'enabled' => wg_enabled($row['enabled'] ?? '1'),
                    ];
                },
                $servers
            ));
        }

        @file_put_contents(
            $cachePath,
            json_encode(
                ['inventory' => $inventory, 'errors' => $errors],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            ),
            LOCK_EX
        );
    }

    $links = [];
    $current = $inventory[$currentId] ?? null;
    if ($current !== null) {
        foreach ($current['clients'] as $localClient) {
            if ($localClient['uuid'] === '' || $localClient['pubkey'] === '') {
                continue;
            }
            foreach ($inventory as $remoteId => $remote) {
                if ($remoteId === $currentId) {
                    continue;
                }
                foreach ($remote['servers'] as $remoteServer) {
                    if ($remoteServer['pubkey'] !== $localClient['pubkey']) {
                        continue;
                    }
                    foreach ($current['servers'] as $localServer) {
                        if ($localServer['pubkey'] === '') {
                            continue;
                        }
                        foreach ($remote['clients'] as $remoteClient) {
                            if ($remoteClient['pubkey'] !== $localServer['pubkey'] || $remoteClient['uuid'] === '') {
                                continue;
                            }
                            $links[$localClient['pubkey']] = [
                                'managed' => true,
                                'local' => [
                                    'firewall_id' => $currentId,
                                    'firewall_name' => $current['firewall']['name'],
                                    'client_uuid' => $localClient['uuid'],
                                    'client_name' => $localClient['name'],
                                    'enabled' => $localClient['enabled'],
                                    'expected_peer_key' => $localClient['pubkey'],
                                    'server_key' => $localServer['pubkey'],
                                ],
                                'remote' => [
                                    'firewall_id' => $remoteId,
                                    'firewall_name' => $remote['firewall']['name'],
                                    'client_uuid' => $remoteClient['uuid'],
                                    'client_name' => $remoteClient['name'],
                                    'enabled' => $remoteClient['enabled'],
                                    'expected_peer_key' => $remoteClient['pubkey'],
                                    'server_key' => $remoteServer['pubkey'],
                                ],
                                'paired_enabled' => $localClient['enabled'] && $remoteClient['enabled'],
                                'partial_state' => $localClient['enabled'] !== $remoteClient['enabled'],
                            ];
                        }
                    }
                }
            }
        }
    }

    echo json_encode([
        'ok' => true,
        'links' => $links,
        'errors' => $errors,
        'cache' => ['hit' => $cacheHit, 'ttl' => $cacheTtl],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $exception->getMessage()], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
