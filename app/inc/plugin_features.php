<?php

declare(strict_types=1);

function plugin_feature_cache_path(): string
{
    return DATA_DIR . '/plugins-cache.json';
}

function plugin_feature_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    return in_array(strtolower(trim((string) $value)), ['1','true','yes','on','installed','locked'], true);
}

function plugin_feature_find_packages(mixed $node, array &$output): void
{
    if (!is_array($node)) return;

    $name = trim((string) ($node['name'] ?? $node['pkg_name'] ?? $node['package'] ?? ''));
    if ($name !== '' && str_starts_with($name, 'os-')) {
        $status = strtolower(trim((string) ($node['status'] ?? '')));
        $current = trim((string) ($node['current'] ?? ''));
        $installed = array_key_exists('installed', $node)
            ? plugin_feature_bool($node['installed'])
            : ($status === 'installed' || $current !== '');

        $output[$name] = [
            'name' => $name,
            'version' => trim((string) ($node['version'] ?? $node['installed_version'] ?? $current)),
            'available_version' => trim((string) ($node['available_version'] ?? $node['new_version'] ?? $node['version'] ?? '')),
            'installed' => $installed,
            'locked' => plugin_feature_bool($node['locked'] ?? false),
            'description' => trim((string) ($node['comment'] ?? $node['description'] ?? '')),
        ];
    }

    foreach ($node as $value) plugin_feature_find_packages($value, $output);
}

function plugin_feature_refresh_cache(): ?array
{
    if (!function_exists('db') || !function_exists('opn_requests_parallel')) return null;

    try {
        $firewalls = db()->query(
            'SELECT id,name,base_url,api_key_enc,api_secret_enc,verify_tls FROM firewalls ORDER BY name'
        )->fetchAll();
        if ($firewalls === []) return null;

        $requests = [];
        foreach ($firewalls as $firewall) {
            $requests[(string) $firewall['id']] = [
                'firewall' => $firewall,
                'path' => 'core/firmware/info',
                'timeout' => 20,
            ];
        }

        $responses = opn_requests_parallel($requests);
        $rows = [];

        foreach ($firewalls as $firewall) {
            $key = (string) $firewall['id'];
            $response = $responses[$key] ?? ['ok' => false, 'error' => 'No result'];
            $plugins = [];
            if (($response['ok'] ?? false) === true) {
                plugin_feature_find_packages($response['value'] ?? [], $plugins);
            }
            uksort($plugins, 'strnatcasecmp');
            $rows[] = [
                'id' => (int) $firewall['id'],
                'name' => (string) $firewall['name'],
                'base_url' => (string) $firewall['base_url'],
                'ok' => ($response['ok'] ?? false) === true,
                'error' => $response['error'] ?? null,
                'plugins' => array_values($plugins),
            ];
        }

        $cache = ['created_at' => gmdate('c'), 'firewalls' => $rows];
        if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0770, true);
        @file_put_contents(
            plugin_feature_cache_path(),
            json_encode($cache, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            LOCK_EX
        );
        return $cache;
    } catch (Throwable $exception) {
        return null;
    }
}

function plugin_feature_cache(bool $refreshIfStale = true): ?array
{
    $path = plugin_feature_cache_path();
    $decoded = null;
    $age = null;

    if (is_file($path)) {
        $raw = file_get_contents($path);
        $decoded = $raw === false ? null : json_decode($raw, true);
        if (!is_array($decoded) || !is_array($decoded['firewalls'] ?? null)) $decoded = null;
        $mtime = filemtime($path);
        if ($mtime !== false) $age = max(0, time() - $mtime);
    }

    if ($refreshIfStale && ($decoded === null || $age === null || $age >= 300)) {
        $fresh = plugin_feature_refresh_cache();
        if ($fresh !== null) return $fresh;
    }

    return $decoded;
}

function plugin_feature_installed_firewall_ids(string $packageName): array
{
    $cache = plugin_feature_cache(true);
    if ($cache === null) return [];

    $ids = [];
    foreach ($cache['firewalls'] as $firewall) {
        if (!is_array($firewall) || ($firewall['ok'] ?? false) !== true) continue;

        foreach (($firewall['plugins'] ?? []) as $plugin) {
            if (!is_array($plugin)) continue;
            if ((string) ($plugin['name'] ?? '') !== $packageName) continue;
            if (!plugin_feature_bool($plugin['installed'] ?? false)) continue;

            $id = (int) ($firewall['id'] ?? 0);
            if ($id > 0) $ids[] = $id;
            break;
        }
    }

    return array_values(array_unique($ids));
}

function plugin_feature_installed_anywhere(string $packageName): bool
{
    return plugin_feature_installed_firewall_ids($packageName) !== [];
}
