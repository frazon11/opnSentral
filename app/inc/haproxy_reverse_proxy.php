<?php

declare(strict_types=1);

require_once __DIR__ . '/opnsense.php';
require_once __DIR__ . '/backups.php';

function rp_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    return in_array(strtolower(trim((string) $value)), ['1','true','yes','on','installed','locked','running'], true);
}

function rp_find_plugin(mixed $node, string $packageName): ?array
{
    if (!is_array($node)) return null;
    $name = trim((string) ($node['name'] ?? $node['pkg_name'] ?? $node['package'] ?? ''));
    if ($name === $packageName) {
        $status = strtolower(trim((string) ($node['status'] ?? '')));
        $current = trim((string) ($node['current'] ?? ''));
        return [
            'name' => $name,
            'installed' => array_key_exists('installed', $node)
                ? rp_bool($node['installed'])
                : ($status === 'installed' || $current !== ''),
            'version' => trim((string) ($node['version'] ?? $node['installed_version'] ?? $current)),
        ];
    }
    foreach ($node as $value) {
        $found = rp_find_plugin($value, $packageName);
        if ($found !== null) return $found;
    }
    return null;
}

function rp_require_plugin(array $firewall): array
{
    $firmware = opn_request($firewall, 'core/firmware/info', 'GET', [], 30);
    $plugin = rp_find_plugin($firmware, 'os-haproxy');
    if ($plugin === null || ($plugin['installed'] ?? false) !== true) {
        throw new RuntimeException(
            'Required plugin os-haproxy is not installed on ' . (string) $firewall['name'] .
            '. Install it under System → Firmware → Plugins first.'
        );
    }
    return $plugin;
}

function rp_api_ok(array $response, string $operation): void
{
    $validations = $response['validations'] ?? null;
    if (is_array($validations) && $validations !== []) {
        throw new RuntimeException($operation . ' failed validation: ' . json_encode($validations, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
    foreach (['result','status'] as $field) {
        if (!array_key_exists($field, $response)) continue;
        $value = strtolower(trim((string) $response[$field]));
        if (in_array($value, ['failed','failure','error','invalid','rejected','0','false'], true)) {
            throw new RuntimeException($operation . ' failed: ' . json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        }
    }
}

function rp_endpoint_plural(string $kind): string
{
    return match ($kind) {
        'acl' => 'acls',
        'action' => 'actions',
        'backend' => 'backends',
        'frontend' => 'frontends',
        'server' => 'servers',
        default => throw new RuntimeException('Unsupported HAProxy object type: ' . $kind),
    };
}

function rp_search_rows(array $firewall, string $kind, string $phrase = ''): array
{
    $response = opn_request(
        $firewall,
        'haproxy/settings/search_' . rp_endpoint_plural($kind),
        'POST',
        ['current' => 1, 'rowCount' => 500, 'searchPhrase' => $phrase],
        25
    );
    return is_array($response['rows'] ?? null) ? $response['rows'] : [];
}

function rp_find_exact(array $firewall, string $kind, string $name): ?array
{
    foreach (rp_search_rows($firewall, $kind, $name) as $row) {
        if (is_array($row) && strcasecmp(trim((string) ($row['name'] ?? '')), $name) === 0) return $row;
    }
    return null;
}

function rp_get_payload(array $firewall, string $kind, ?string $uuid = null): array
{
    $path = 'haproxy/settings/get_' . $kind . ($uuid ? '/' . rawurlencode($uuid) : '');
    $response = opn_request($firewall, $path, 'GET', [], 20);
    $payload = $response[$kind] ?? null;
    if (!is_array($payload)) {
        throw new RuntimeException('Unexpected HAProxy get_' . $kind . ' response.');
    }
    return $payload;
}

function rp_upsert(array $firewall, string $kind, string $name, array $changes): array
{
    $existing = rp_find_exact($firewall, $kind, $name);
    $uuid = $existing !== null ? trim((string) ($existing['uuid'] ?? $existing['id'] ?? '')) : '';
    $payload = rp_get_payload($firewall, $kind, $uuid !== '' ? $uuid : null);
    $payload = array_replace($payload, $changes, ['name' => $name]);

    if ($uuid !== '') {
        $response = opn_request(
            $firewall,
            'haproxy/settings/set_' . $kind . '/' . rawurlencode($uuid),
            'POST',
            [$kind => $payload],
            30
        );
        rp_api_ok($response, 'HAProxy ' . $kind . ' update');
        $action = 'updated';
    } else {
        $response = opn_request(
            $firewall,
            'haproxy/settings/add_' . $kind,
            'POST',
            [$kind => $payload],
            30
        );
        rp_api_ok($response, 'HAProxy ' . $kind . ' creation');
        $uuid = trim((string) ($response['uuid'] ?? ''));
        $action = 'created';
    }

    if ($uuid === '') {
        $verified = rp_find_exact($firewall, $kind, $name);
        $uuid = trim((string) ($verified['uuid'] ?? $verified['id'] ?? ''));
    }
    if ($uuid === '') throw new RuntimeException('HAProxy ' . $kind . ' saved but UUID could not be resolved.');

    return ['uuid' => $uuid, 'action' => $action, 'name' => $name];
}

function rp_csv_merge(string $current, string ...$values): string
{
    $items = array_values(array_filter(array_map('trim', explode(',', $current)), static fn(string $v): bool => $v !== ''));
    foreach ($values as $value) {
        $value = trim($value);
        if ($value !== '' && !in_array($value, $items, true)) $items[] = $value;
    }
    return implode(',', $items);
}

function rp_assert_bind_available(array $firewall, string $frontendName, string $bind): void
{
    foreach (rp_search_rows($firewall, 'frontend', '') as $row) {
        if (!is_array($row)) continue;
        $name = trim((string) ($row['name'] ?? ''));
        if (strcasecmp($name, $frontendName) === 0) continue;
        $rowBind = trim((string) ($row['bind'] ?? ''));
        $bindings = array_map('trim', explode(',', $rowBind));
        if (in_array($bind, $bindings, true)) {
            throw new RuntimeException('Frontend bind conflict: ' . $bind . ' is already used by HAProxy frontend "' . $name . '".');
        }
    }
}

function rp_validate_certificate(array $firewall, string $reference): void
{
    $reference = trim($reference);
    if ($reference === '') throw new RuntimeException('A server certificate reference is required for HTTPS.');
    $response = opn_request(
        $firewall,
        'trust/cert/search',
        'POST',
        ['current' => 1, 'rowCount' => 500, 'searchPhrase' => $reference],
        25
    );
    foreach (($response['rows'] ?? []) as $row) {
        if (!is_array($row)) continue;
        foreach (['refid','uuid','id'] as $field) {
            if (isset($row[$field]) && hash_equals($reference, trim((string) $row[$field]))) return;
        }
    }
    throw new RuntimeException('Certificate reference "' . $reference . '" was not found on the selected firewall.');
}

function rp_enable_haproxy(array $firewall): void
{
    $settings = opn_request($firewall, 'haproxy/settings/get', 'GET', [], 25);
    if (!isset($settings['haproxy']) || !is_array($settings['haproxy'])) {
        throw new RuntimeException('Unexpected HAProxy settings response.');
    }
    if (rp_bool($settings['haproxy']['general']['enabled'] ?? false)) return;
    $payload = $settings['haproxy'];
    if (!isset($payload['general']) || !is_array($payload['general'])) $payload['general'] = [];
    $payload['general']['enabled'] = '1';
    $response = opn_request($firewall, 'haproxy/settings/set', 'POST', ['haproxy' => $payload], 30);
    rp_api_ok($response, 'Enable HAProxy');
}

function rp_configtest_ok(array $response): bool
{
    $text = strtolower(json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    if (str_contains($text, 'error') || str_contains($text, 'failed') || str_contains($text, 'invalid')) return false;
    if (isset($response['result'])) return in_array(strtolower(trim((string) $response['result'])), ['ok','success','passed'], true);
    if (isset($response['status'])) return in_array(strtolower(trim((string) $response['status'])), ['ok','success','passed'], true);
    return str_contains($text, 'configuration file is valid') || str_contains($text, 'valid');
}

function rp_deploy(array $firewall, array $form): array
{
    $plugin = rp_require_plugin($firewall);
    rp_validate_certificate($firewall, (string) $form['certificate']);
    $backup = backup_before_change($firewall, 'haproxy-reverse-proxy');

    $slug = strtolower(trim((string) preg_replace('/[^a-z0-9]+/i', '_', (string) $form['public_hostname']), '_'));
    $bindSlug = strtolower(trim((string) preg_replace('/[^a-z0-9]+/i', '_', (string) $form['bind_address']), '_')) ?: 'any';
    $prefix = 'opnsentral_' . $slug;
    $frontendName = 'opnsentral_https_' . $bindSlug . '_' . (int) $form['frontend_port'];
    $bind = (string) $form['bind_address'] . ':' . (int) $form['frontend_port'];

    rp_assert_bind_available($firewall, $frontendName, $bind);

    $backendTls = ((string) $form['backend_protocol'] === 'https');
    $server = rp_upsert($firewall, 'server', $prefix . '_server', [
        'enabled' => '1',
        'description' => 'Managed by opnSentral for ' . (string) $form['public_hostname'],
        'address' => (string) $form['backend_ip'],
        'port' => (string) (int) $form['backend_port'],
        'mode' => 'active',
        'type' => 'static',
        'ssl' => $backendTls ? '1' : '0',
        'sslVerify' => $backendTls && !empty($form['backend_verify_tls']) ? '1' : '0',
    ]);

    $isGuacamole = ((string) $form['template'] === 'guacamole');
    $backend = rp_upsert($firewall, 'backend', $prefix . '_backend', [
        'enabled' => '1',
        'description' => 'Managed by opnSentral for ' . (string) $form['public_hostname'],
        'mode' => 'http',
        'algorithm' => 'roundrobin',
        'linkedServers' => $server['uuid'],
        'healthCheckEnabled' => !empty($form['healthcheck']) ? '1' : '0',
        'tuning_timeoutConnect' => '10s',
        'tuning_timeoutServer' => $isGuacamole ? '1h' : '30s',
        'customOptions' => $isGuacamole ? "timeout tunnel 1h" : '',
    ]);

    $acl = rp_upsert($firewall, 'acl', $prefix . '_host', [
        'description' => 'Host match for ' . (string) $form['public_hostname'],
        'expression' => 'hdr',
        'negate' => '0',
        'caseSensitive' => '0',
        'hdr' => (string) $form['public_hostname'],
    ]);

    $action = rp_upsert($firewall, 'action', $prefix . '_use_backend', [
        'enabled' => '1',
        'description' => 'Route ' . (string) $form['public_hostname'],
        'testType' => 'if',
        'linkedAcls' => $acl['uuid'],
        'operator' => 'and',
        'type' => 'use_backend',
        'use_backend' => $backend['uuid'],
    ]);

    $existingFrontend = rp_find_exact($firewall, 'frontend', $frontendName);
    $existingFrontendUuid = trim((string) ($existingFrontend['uuid'] ?? $existingFrontend['id'] ?? ''));
    $existingPayload = $existingFrontendUuid !== '' ? rp_get_payload($firewall, 'frontend', $existingFrontendUuid) : [];
    $linkedActions = rp_csv_merge((string) ($existingPayload['linkedActions'] ?? ''), $action['uuid']);
    $certificates = rp_csv_merge((string) ($existingPayload['ssl_certificates'] ?? ''), (string) $form['certificate']);

    $frontend = rp_upsert($firewall, 'frontend', $frontendName, [
        'enabled' => '1',
        'description' => 'Shared opnSentral HTTPS frontend ' . $bind,
        'bind' => $bind,
        'mode' => 'http',
        'ssl_enabled' => '1',
        'ssl_certificates' => $certificates,
        'ssl_default_certificate' => (string) (($existingPayload['ssl_default_certificate'] ?? '') ?: $form['certificate']),
        'ssl_minVersion' => 'TLSv1.2',
        'linkedActions' => $linkedActions,
        'connectionBehaviour' => 'http-keep-alive',
        'tuning_timeoutClient' => $isGuacamole ? '1h' : '30s',
        'customOptions' => $isGuacamole ? "timeout tunnel 1h" : (string) ($existingPayload['customOptions'] ?? ''),
    ]);

    rp_enable_haproxy($firewall);
    $test = opn_request($firewall, 'haproxy/service/configtest', 'GET', [], 30);
    if (!rp_configtest_ok($test)) {
        throw new RuntimeException(
            'HAProxy configuration test failed. The new settings were NOT reconfigured. Pre-change backup: ' .
            (string) ($backup['filename'] ?? 'created') . '. Result: ' . json_encode($test, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        );
    }
    $reconfigure = opn_request($firewall, 'haproxy/service/reconfigure', 'POST', [], 45);
    rp_api_ok($reconfigure, 'HAProxy reconfigure');

    return [
        'plugin' => $plugin,
        'backup' => $backup['filename'] ?? '',
        'objects' => compact('server','backend','acl','action','frontend'),
        'configtest' => $test,
        'reconfigure' => $reconfigure,
        'bind' => $bind,
    ];
}
