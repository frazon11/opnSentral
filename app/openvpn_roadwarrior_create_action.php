<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';

require_login();
require_csrf();
require_configuration_unlocked();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function ovpn_fail(string $message): never
{
    throw new RuntimeException($message);
}

function ovpn_post_string(string $name, bool $required = false): string
{
    $value = trim((string) ($_POST[$name] ?? ''));

    if ($required && $value === '') {
        ovpn_fail('Missing required field: ' . $name);
    }

    return $value;
}

function ovpn_post_int(
    string $name,
    int $minimum,
    int $maximum,
    bool $required = true
): int {
    $raw = trim((string) ($_POST[$name] ?? ''));

    if ($raw === '' && !$required) {
        return 0;
    }

    if (!ctype_digit($raw)) {
        ovpn_fail('Invalid numeric value: ' . $name);
    }

    $value = (int) $raw;

    if ($value < $minimum || $value > $maximum) {
        ovpn_fail(
            sprintf(
                '%s must be between %d and %d.',
                $name,
                $minimum,
                $maximum
            )
        );
    }

    return $value;
}

function ovpn_validate_ip(string $value, string $label): string
{
    if ($value === '') {
        return '';
    }

    if (filter_var($value, FILTER_VALIDATE_IP) === false) {
        ovpn_fail($label . ' is not a valid IP address.');
    }

    return $value;
}

function ovpn_validate_network(string $value, string $label): string
{
    if (!preg_match('#^([^/]+)/([0-9]{1,3})$#', $value, $matches)) {
        ovpn_fail($label . ' must use CIDR notation.');
    }

    $ip = $matches[1];
    $prefix = (int) $matches[2];

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        if ($prefix < 0 || $prefix > 32) {
            ovpn_fail($label . ' has an invalid IPv4 prefix.');
        }

        $packed = inet_pton($ip);
        if ($packed === false) {
            ovpn_fail($label . ' is invalid.');
        }

        $integer = unpack('N', $packed)[1];
        $mask = $prefix === 0
            ? 0
            : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);
        $network = long2ip($integer & $mask);

        if ($network !== $ip) {
            ovpn_fail(
                $label . ' must be the network address: ' .
                $network . '/' . $prefix
            );
        }

        return $network . '/' . $prefix;
    }

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        if ($prefix < 0 || $prefix > 128) {
            ovpn_fail($label . ' has an invalid IPv6 prefix.');
        }

        return $value;
    }

    ovpn_fail($label . ' contains an invalid IP address.');
}

function ovpn_list_lines(
    string $name,
    callable $validator,
    string $label
): string {
    $raw = trim((string) ($_POST[$name] ?? ''));

    if ($raw === '') {
        return '';
    }

    $result = [];

    foreach (preg_split('/[\r\n,;]+/', $raw) ?: [] as $value) {
        $value = trim($value);

        if ($value === '') {
            continue;
        }

        $result[] = $validator($value, $label);
    }

    return implode(',', array_values(array_unique($result)));
}

function ovpn_response_uuid(array $response): string
{
    foreach (['uuid', 'id'] as $key) {
        if (
            isset($response[$key]) &&
            is_scalar($response[$key]) &&
            trim((string) $response[$key]) !== ''
        ) {
            return trim((string) $response[$key]);
        }
    }

    foreach ($response as $value) {
        if (!is_array($value)) {
            continue;
        }

        $uuid = ovpn_response_uuid($value);
        if ($uuid !== '') {
            return $uuid;
        }
    }

    return '';
}

function ovpn_response_is_success(array $response): bool
{
    $result = strtolower(trim((string) (
        $response['result'] ??
        $response['status'] ??
        ''
    )));

    if ($result === '') {
        return isset($response['uuid']) || isset($response['id']);
    }

    return in_array($result, ['ok', 'saved', 'success'], true);
}

function ovpn_validation_message(array $response): string
{
    $messages = [];

    foreach (['validations', 'validation_errors', 'errors'] as $key) {
        if (!isset($response[$key]) || !is_array($response[$key])) {
            continue;
        }

        array_walk_recursive(
            $response[$key],
            static function (mixed $value) use (&$messages): void {
                if (is_scalar($value) && trim((string) $value) !== '') {
                    $messages[] = trim((string) $value);
                }
            }
        );
    }

    return implode(' | ', array_values(array_unique($messages)));
}

try {
    $firewallId = ovpn_post_int('firewall_id', 1, PHP_INT_MAX);
    $vpnId = ovpn_post_int('vpnid', 1, 999999);
    $port = ovpn_post_int('port', 1, 65535);
    $maxClients = ovpn_post_int('maxclients', 1, 10000, false);
    $keepaliveInterval = ovpn_post_int(
        'keepalive_interval',
        0,
        3600,
        false
    );
    $keepaliveTimeout = ovpn_post_int(
        'keepalive_timeout',
        0,
        3600,
        false
    );
    $renegSec = ovpn_post_int('reneg_sec', 0, 31536000, false);

    $description = ovpn_post_string('description', true);
    $proto = ovpn_post_string('proto', true);
    $local = ovpn_validate_ip(
        ovpn_post_string('local'),
        'Bind address'
    );
    $serverNetwork = ovpn_validate_network(
        ovpn_post_string('server', true),
        'Tunnel network'
    );
    $ca = ovpn_post_string('ca', true);
    $cert = ovpn_post_string('cert', true);
    $tlsKey = ovpn_post_string('tls_key');
    $authmode = ovpn_post_string('authmode');
    $verifyClientCert = ovpn_post_string('verify_client_cert', true);
    $strictUserCn = ovpn_post_string('strictusercn', true);
    $dnsDomain = ovpn_post_string('dns_domain');
    $redirectGateway = ovpn_post_string('redirect_gateway');
    $auth = ovpn_post_string('auth', true);
    $devType = ovpn_post_string('dev_type', true);

    if (!in_array($proto, ['udp4', 'udp6', 'tcp4', 'tcp6'], true)) {
        ovpn_fail('Unsupported OpenVPN protocol.');
    }

    if (!in_array($devType, ['tun', 'ovpn'], true)) {
        ovpn_fail('Unsupported device type.');
    }

    if (!in_array($verifyClientCert, ['require', 'none'], true)) {
        ovpn_fail('Unsupported client certificate mode.');
    }

    if (!in_array($strictUserCn, ['0', '1', '2'], true)) {
        ovpn_fail('Unsupported Strict User/CN option.');
    }

    if (!in_array($redirectGateway, ['', 'default'], true)) {
        ovpn_fail('Unsupported redirect gateway option.');
    }

    if (!in_array($auth, ['SHA256', 'SHA384', 'SHA512'], true)) {
        ovpn_fail('Unsupported digest.');
    }

    if (empty($_POST['acknowledge_rules'])) {
        ovpn_fail('Firewall rule acknowledgement is required.');
    }

    $pushRoutes = ovpn_list_lines(
        'push_route',
        'ovpn_validate_network',
        'Local network'
    );

    if ($pushRoutes === '') {
        ovpn_fail('At least one local network is required.');
    }

    $dnsServers = ovpn_list_lines(
        'dns_servers',
        'ovpn_validate_ip',
        'DNS server'
    );

    $dataCiphers = $_POST['data_ciphers'] ?? [];
    if (!is_array($dataCiphers)) {
        $dataCiphers = [$dataCiphers];
    }

    $allowedCiphers = [
        'AES-256-GCM',
        'AES-128-GCM',
        'CHACHA20-POLY1305',
        'AES-256-CBC',
    ];

    $dataCiphers = array_values(array_unique(array_filter(
        array_map(
            static fn(mixed $value): string => trim((string) $value),
            $dataCiphers
        ),
        static fn(string $value): bool =>
            in_array($value, $allowedCiphers, true)
    )));

    if ($dataCiphers === []) {
        ovpn_fail('Select at least one data cipher.');
    }

    $firewall = firewall_by_id($firewallId);

    $search = opn_request(
        $firewall,
        'openvpn/instances/search',
        'POST',
        [
            'current' => 1,
            'rowCount' => -1,
            'sort' => new stdClass(),
            'searchPhrase' => '',
        ],
        20
    );

    $rows = isset($search['rows']) && is_array($search['rows'])
        ? $search['rows']
        : [];

    foreach ($rows as $row) {
        if (!is_array($row)) {
            continue;
        }

        if ((int) ($row['vpnid'] ?? 0) === $vpnId) {
            ovpn_fail('OpenVPN instance ID ' . $vpnId . ' already exists.');
        }

        $rowRole = strtolower((string) ($row['role'] ?? ''));
        $rowProto = strtolower((string) ($row['proto'] ?? ''));
        $rowPort = (int) ($row['port'] ?? 0);
        $rowLocal = trim((string) ($row['local'] ?? ''));

        if (
            $rowRole === 'server' &&
            $rowProto === strtolower($proto) &&
            $rowPort === $port &&
            ($rowLocal === '' || $local === '' || $rowLocal === $local)
        ) {
            ovpn_fail(
                'Another OpenVPN server already uses this protocol, port ' .
                'and overlapping bind address.'
            );
        }
    }

    $backup = backup_before_change(
        $firewall,
        'openvpn-roadwarrior-' . $description
    );

    $instance = [
        'vpnid' => (string) $vpnId,
        'enabled' => isset($_POST['enabled']) ? '1' : '0',
        'dev_type' => $devType,
        'verb' => '3',
        'proto' => $proto,
        'port' => (string) $port,
        'local' => $local,
        'topology' => 'subnet',
        'role' => 'server',
        'server' => $serverNetwork,
        'nopool' => '0',
        'route' => '',
        'push_route' => $pushRoutes,
        'cert' => $cert,
        'ca' => $ca,
        'remote_cert_tls' => '0',
        'verify_client_cert' => $verifyClientCert,
        'use_ocsp' => '0',
        'auth' => $auth,
        'data-ciphers' => implode(',', $dataCiphers),
        'data-ciphers-fallback' => '',
        'tls_key' => $tlsKey,
        'authmode' => $authmode,
        'various_flags' => 'explicit-exit-notify',
        'various_push_flags' => '',
        'username_as_common_name' =>
            isset($_POST['username_as_common_name']) ? '1' : '0',
        'strictusercn' => $strictUserCn,
        'maxclients' => $maxClients > 0 ? (string) $maxClients : '',
        'keepalive_interval' =>
            $keepaliveInterval > 0 ? (string) $keepaliveInterval : '',
        'keepalive_timeout' =>
            $keepaliveTimeout > 0 ? (string) $keepaliveTimeout : '',
        'reneg-sec' => $renegSec > 0 ? (string) $renegSec : '',
        'redirect_gateway' => $redirectGateway,
        'register_dns' => '0',
        'dns_domain' => $dnsDomain,
        'dns_servers' => $dnsServers,
        'mssfix' => '0',
        'description' => $description,
    ];

    $addResponse = opn_request(
        $firewall,
        'openvpn/instances/add',
        'POST',
        ['instance' => $instance],
        30
    );

    if (!ovpn_response_is_success($addResponse)) {
        $validation = ovpn_validation_message($addResponse);

        ovpn_fail(
            'OPNsense rejected the OpenVPN instance.' .
            ($validation !== '' ? ' ' . $validation : '')
        );
    }

    $uuid = ovpn_response_uuid($addResponse);

    if ($uuid === '') {
        $verifySearch = opn_request(
            $firewall,
            'openvpn/instances/search',
            'POST',
            [
                'current' => 1,
                'rowCount' => -1,
                'sort' => new stdClass(),
                'searchPhrase' => $description,
            ],
            20
        );

        $verifyRows = isset($verifySearch['rows']) &&
            is_array($verifySearch['rows'])
            ? $verifySearch['rows']
            : [];

        foreach ($verifyRows as $row) {
            if (
                is_array($row) &&
                (int) ($row['vpnid'] ?? 0) === $vpnId
            ) {
                $uuid = trim((string) (
                    $row['uuid'] ??
                    $row['id'] ??
                    ''
                ));
                break;
            }
        }
    }

    if ($uuid === '') {
        ovpn_fail(
            'The instance may have been created, but its UUID could not be ' .
            'verified. Check OPNsense before retrying.'
        );
    }

    try {
        $reconfigure = opn_request(
            $firewall,
            'openvpn/service/reconfigure',
            'POST',
            null,
            60
        );

        $result = strtolower(trim((string) (
            $reconfigure['result'] ??
            $reconfigure['status'] ??
            'ok'
        )));

        if (!in_array($result, ['ok', 'success', 'saved'], true)) {
            throw new RuntimeException(
                (string) (
                    $reconfigure['message'] ??
                    'OpenVPN reconfigure failed.'
                )
            );
        }
    } catch (Throwable $exception) {
        try {
            opn_request(
                $firewall,
                'openvpn/instances/del/' . rawurlencode($uuid),
                'POST',
                null,
                30
            );
            opn_request(
                $firewall,
                'openvpn/service/reconfigure',
                'POST',
                null,
                60
            );
        } catch (Throwable) {
        }

        ovpn_fail(
            'The instance could not be applied and rollback was attempted. ' .
            $exception->getMessage()
        );
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => true,
            'firewall' => (string) $firewall['name'],
            'uuid' => $uuid,
            'vpnid' => $vpnId,
            'port' => $port,
            'protocol' => $proto,
            'backup_id' => $backup['id'],
            'backup_filename' => $backup['filename'],
            'message' => 'OpenVPN instance created and reconfigured.',
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
