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

function ovpn_rows(array $response): array
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

function ovpn_value(array $row, array $keys): string
{
    foreach ($keys as $key) {
        if (isset($row[$key]) && trim((string) $row[$key]) !== '') {
            return trim((string) $row[$key]);
        }
    }

    return '';
}

function ovpn_normalize_reference_rows(
    array $response,
    array $idKeys,
    array $labelKeys
): array {
    $result = [];

    foreach (ovpn_rows($response) as $row) {
        if (!is_array($row)) {
            continue;
        }

        $id = ovpn_value($row, $idKeys);
        $label = ovpn_value($row, $labelKeys);

        if ($id === '') {
            continue;
        }

        $result[] = [
            'id' => $id,
            'label' => $label !== '' ? $label : $id,
            'raw' => $row,
        ];
    }

    usort(
        $result,
        static fn(array $a, array $b): int =>
            strnatcasecmp($a['label'], $b['label'])
    );

    return $result;
}

try {
    $firewallId = (int) ($_GET['firewall_id'] ?? 0);

    if ($firewallId < 1) {
        throw new RuntimeException('Select a firewall.');
    }

    $firewall = firewall_by_id($firewallId);

    $requests = [
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
        'defaults' => [
            'firewall' => $firewall,
            'path' => 'openvpn/instances/get',
            'timeout' => 20,
        ],
        'cas' => [
            'firewall' => $firewall,
            'path' => 'trust/ca/search',
            'method' => 'POST',
            'payload' => [
                'current' => 1,
                'rowCount' => -1,
                'sort' => new stdClass(),
                'searchPhrase' => '',
            ],
            'timeout' => 20,
        ],
        'certs' => [
            'firewall' => $firewall,
            'path' => 'trust/cert/search',
            'method' => 'POST',
            'payload' => [
                'current' => 1,
                'rowCount' => -1,
                'sort' => new stdClass(),
                'searchPhrase' => '',
            ],
            'timeout' => 20,
        ],
        'static_keys' => [
            'firewall' => $firewall,
            'path' => 'openvpn/instances/search_static_key',
            'method' => 'POST',
            'payload' => [
                'current' => 1,
                'rowCount' => -1,
                'sort' => new stdClass(),
                'searchPhrase' => '',
            ],
            'timeout' => 20,
        ],
        'providers' => [
            'firewall' => $firewall,
            'path' => 'openvpn/export/providers',
            'timeout' => 20,
        ],
    ];

    $responses = opn_requests_parallel($requests);
    $errors = [];

    foreach ($responses as $key => $response) {
        if (($response['ok'] ?? false) !== true) {
            $errors[$key] = (string) ($response['error'] ?? 'Unavailable');
        }
    }

    $instances = ($responses['instances']['ok'] ?? false) === true
        ? ovpn_rows((array) $responses['instances']['value'])
        : [];

    $nextVpnId = 1;
    foreach ($instances as $instance) {
        if (!is_array($instance)) {
            continue;
        }

        $vpnId = (int) ($instance['vpnid'] ?? 0);
        $nextVpnId = max($nextVpnId, $vpnId + 1);
    }

    $cas = ($responses['cas']['ok'] ?? false) === true
        ? ovpn_normalize_reference_rows(
            (array) $responses['cas']['value'],
            ['uuid', 'refid', 'caref', 'id'],
            ['descr', 'description', 'name', 'subject']
        )
        : [];

    $certs = ($responses['certs']['ok'] ?? false) === true
        ? ovpn_normalize_reference_rows(
            (array) $responses['certs']['value'],
            ['uuid', 'refid', 'certref', 'id'],
            ['descr', 'description', 'name', 'subject', 'common_name']
        )
        : [];

    $staticKeys = ($responses['static_keys']['ok'] ?? false) === true
        ? ovpn_normalize_reference_rows(
            (array) $responses['static_keys']['value'],
            ['uuid', 'id'],
            ['description', 'name', 'mode']
        )
        : [];

    $providers = [];
    if (($responses['providers']['ok'] ?? false) === true) {
        $providerResponse = (array) $responses['providers']['value'];

        foreach ($providerResponse as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $providerKey => $providerValue) {
                    if (is_scalar($providerValue)) {
                        $providers[] = [
                            'id' => (string) $providerKey,
                            'label' => (string) $providerValue,
                        ];
                    } elseif (is_array($providerValue)) {
                        $id = ovpn_value(
                            $providerValue,
                            ['id', 'uuid', 'name', 'value']
                        );
                        $label = ovpn_value(
                            $providerValue,
                            ['label', 'description', 'name']
                        );

                        if ($id !== '') {
                            $providers[] = [
                                'id' => $id,
                                'label' => $label !== '' ? $label : $id,
                            ];
                        }
                    }
                }
            } elseif (is_scalar($value)) {
                $providers[] = [
                    'id' => (string) $key,
                    'label' => (string) $value,
                ];
            }
        }

        $seen = [];
        $providers = array_values(array_filter(
            $providers,
            static function (array $provider) use (&$seen): bool {
                if (
                    $provider['id'] === '' ||
                    isset($seen[$provider['id']])
                ) {
                    return false;
                }

                $seen[$provider['id']] = true;
                return true;
            }
        ));
    }

    $defaults = ($responses['defaults']['ok'] ?? false) === true
        ? (array) $responses['defaults']['value']
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
            'next_vpnid' => $nextVpnId,
            'instances' => $instances,
            'cas' => $cas,
            'certificates' => $certs,
            'static_keys' => $staticKeys,
            'providers' => $providers,
            'defaults' => $defaults,
            'errors' => $errors,
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
        ['ok' => false, 'error' => $exception->getMessage()],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
