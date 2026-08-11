<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';

require_login();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function ovpn_rows(array $value): array
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

function ovpn_bool(mixed $value): bool
{
    if (is_bool($value)) {
        return $value;
    }

    return in_array(
        strtolower(trim((string) $value)),
        ['1', 'true', 'yes', 'on', 'enabled', 'running'],
        true
    );
}

function ovpn_instance_config(array $response): array
{
    if (isset($response['instance']) && is_array($response['instance'])) {
        return $response['instance'];
    }

    if (isset($response['Instance']) && is_array($response['Instance'])) {
        return $response['Instance'];
    }

    foreach ($response as $candidate) {
        if (
            is_array($candidate) &&
            (
                array_key_exists('vpnid', $candidate) ||
                array_key_exists('role', $candidate) ||
                array_key_exists('description', $candidate)
            )
        ) {
            return $candidate;
        }
    }

    return $response;
}

function ovpn_mask_config(array $config): array
{
    $sensitive = [
        'password',
        'auth-gen-token-secret',
        'auth_gen_token_secret',
        'key',
        'private_key',
        'private-key',
        'secret',
    ];

    foreach ($config as $key => $value) {
        $normalized = strtolower((string) $key);

        if (in_array($normalized, $sensitive, true)) {
            $config[$key] = trim((string) $value) === ''
                ? ''
                : '••••••••';
            continue;
        }

        if (is_array($value)) {
            $config[$key] = ovpn_mask_config($value);
        }
    }

    return $config;
}

try {
    $firewallId = (int) ($_GET['firewall_id'] ?? 0);

    if ($firewallId < 1) {
        throw new RuntimeException('Select a firewall.');
    }

    $firewall = firewall_by_id($firewallId);

    $baseRequests = [
        'instances' => [
            'firewall' => $firewall,
            'path' => 'openvpn/instances/search',
            'method' => 'POST',
            'payload' => [
                'current' => 1,
                'rowCount' => -1,
                'sort' => new stdClass(),
                'searchPhrase' => '',
            ],
            'timeout' => 20,
        ],
        'sessions' => [
            'firewall' => $firewall,
            'path' => 'openvpn/service/search_sessions',
            'timeout' => 20,
        ],
    ];

    $responses = opn_requests_parallel($baseRequests);

    if (($responses['instances']['ok'] ?? false) !== true) {
        throw new RuntimeException(
            (string) (
                $responses['instances']['error'] ??
                'Could not load OpenVPN instances.'
            )
        );
    }

    $instances = [];

    foreach (
        ovpn_rows((array) $responses['instances']['value'])
        as $row
    ) {
        if (!is_array($row)) {
            continue;
        }

        $uuid = trim((string) ($row['uuid'] ?? $row['id'] ?? ''));

        if ($uuid === '') {
            continue;
        }

        $instances[$uuid] = [
            'uuid' => $uuid,
            'vpnid' => (string) ($row['vpnid'] ?? ''),
            'description' => (string) (
                $row['description'] ??
                $row['descr'] ??
                ''
            ),
            'role' => (string) ($row['role'] ?? ''),
            'enabled' => ovpn_bool($row['enabled'] ?? false),
            'proto' => (string) ($row['proto'] ?? ''),
            'port' => (string) ($row['port'] ?? ''),
            'local' => (string) ($row['local'] ?? ''),
            'server' => (string) ($row['server'] ?? ''),
            'remote' => (string) ($row['remote'] ?? ''),
            'dev_type' => (string) ($row['dev_type'] ?? ''),
            'config' => [],
            'config_error' => null,
        ];
    }

    $configRequests = [];

    foreach ($instances as $uuid => $_instance) {
        $configRequests[$uuid] = [
            'firewall' => $firewall,
            'path' => 'openvpn/instances/get/' . rawurlencode($uuid),
            'method' => 'GET',
            'timeout' => 20,
        ];
    }

    $configResponses = opn_requests_parallel($configRequests);

    foreach ($instances as $uuid => &$instance) {
        $configResult = $configResponses[$uuid] ?? null;

        if (($configResult['ok'] ?? false) === true) {
            $config = ovpn_mask_config(
                ovpn_instance_config(
                    (array) $configResult['value']
                )
            );

            $instance['config'] = $config;

            foreach (
                [
                    'vpnid',
                    'description',
                    'role',
                    'proto',
                    'port',
                    'local',
                    'server',
                    'remote',
                    'dev_type',
                ] as $field
            ) {
                if (
                    isset($config[$field]) &&
                    trim((string) $config[$field]) !== ''
                ) {
                    $instance[$field] = (string) $config[$field];
                }
            }

            if (array_key_exists('enabled', $config)) {
                $instance['enabled'] = ovpn_bool($config['enabled']);
            }
        } else {
            $instance['config_error'] = (string) (
                $configResult['error'] ??
                'Could not retrieve the instance configuration.'
            );
        }
    }
    unset($instance);

    $instances = array_values($instances);

    usort(
        $instances,
        static fn(array $a, array $b): int =>
            strnatcasecmp(
                $a['description'] ?: $a['vpnid'],
                $b['description'] ?: $b['vpnid']
            )
    );

    $sessions =
        ($responses['sessions']['ok'] ?? false) === true
            ? ovpn_rows((array) $responses['sessions']['value'])
            : [];

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => true,
            'firewall' => [
                'id' => (int) $firewall['id'],
                'name' => (string) $firewall['name'],
                'base_url' => (string) $firewall['base_url'],
            ],
            'instances' => $instances,
            'sessions' => $sessions,
            'sessions_error' =>
                $responses['sessions']['error'] ?? null,
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE |
        JSON_THROW_ON_ERROR
    );
} catch (Throwable $exception) {
    http_response_code(500);

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => false,
            'error' => $exception->getMessage(),
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    );
}
