<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function network_settings_prepare_database(): void
{
    db()->exec(
        'CREATE TABLE IF NOT EXISTS app_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )'
    );
}

function opnsense_ipv6_disabled(): bool
{
    network_settings_prepare_database();

    $statement = db()->prepare(
        'SELECT setting_value FROM app_settings WHERE setting_key = ?'
    );
    $statement->execute(['opnsense_disable_ipv6']);
    $value = $statement->fetchColumn();

    return is_string($value) && $value === '1';
}

function save_opnsense_ipv6_disabled(bool $disabled): void
{
    network_settings_prepare_database();

    $statement = db()->prepare(
        'INSERT INTO app_settings (setting_key, setting_value, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(setting_key) DO UPDATE SET
            setting_value=excluded.setting_value,
            updated_at=excluded.updated_at'
    );

    $statement->execute([
        'opnsense_disable_ipv6',
        $disabled ? '1' : '0',
        gmdate('c'),
    ]);
}

function opnsense_curl_ipresolve_option(): int
{
    return opnsense_ipv6_disabled()
        ? CURL_IPRESOLVE_V4
        : CURL_IPRESOLVE_WHATEVER;
}
