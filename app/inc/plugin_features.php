<?php

declare(strict_types=1);

function plugin_feature_cache_path(): string
{
    return DATA_DIR . '/plugins-cache.json';
}

function plugin_feature_cache(): ?array
{
    $path = plugin_feature_cache_path();
    if (!is_file($path)) return null;

    $raw = file_get_contents($path);
    if ($raw === false) return null;

    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || !is_array($decoded['firewalls'] ?? null)) return null;

    return $decoded;
}

function plugin_feature_installed_firewall_ids(string $packageName): array
{
    $cache = plugin_feature_cache();
    if ($cache === null) return [];

    $ids = [];
    foreach ($cache['firewalls'] as $firewall) {
        if (!is_array($firewall) || ($firewall['ok'] ?? false) !== true) continue;

        foreach (($firewall['plugins'] ?? []) as $plugin) {
            if (!is_array($plugin)) continue;
            if ((string) ($plugin['name'] ?? '') !== $packageName) continue;
            if (($plugin['installed'] ?? false) !== true) continue;

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
