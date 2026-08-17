<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

const DEFAULT_MANAGED_CATEGORY_NAME = 'Managed by opnSentral';
const DEFAULT_MANAGED_CATEGORY_COLOR = 'F0AD4E';

function managed_category_prepare_database(): void
{
    db()->exec(
        'CREATE TABLE IF NOT EXISTS app_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )'
    );
}

function managed_category_setting(
    string $key,
    string $default
): string {
    managed_category_prepare_database();

    $statement = db()->prepare(
        'SELECT setting_value
         FROM app_settings
         WHERE setting_key = ?'
    );
    $statement->execute([$key]);

    $value = $statement->fetchColumn();

    return is_string($value) && trim($value) !== ''
        ? trim($value)
        : $default;
}

function managed_category_name(): string
{
    return managed_category_setting(
        'managed_category_name',
        DEFAULT_MANAGED_CATEGORY_NAME
    );
}

function managed_category_color(): string
{
    $value = strtoupper(
        preg_replace(
            '/[^0-9A-Fa-f]/',
            '',
            managed_category_setting(
                'managed_category_color',
                DEFAULT_MANAGED_CATEGORY_COLOR
            )
        ) ?? ''
    );

    return preg_match('/^[0-9A-F]{6}$/', $value)
        ? $value
        : DEFAULT_MANAGED_CATEGORY_COLOR;
}

function save_managed_category_settings(
    string $name,
    string $color
): void {
    managed_category_prepare_database();

    $name = trim($name);

    if ($name === '' || mb_strlen($name) > 255) {
        throw new RuntimeException(
            'Managed category name must contain between 1 and 255 characters.'
        );
    }

    $color = strtoupper(
        preg_replace('/[^0-9A-Fa-f]/', '', trim($color)) ?? ''
    );

    if (!preg_match('/^[0-9A-F]{6}$/', $color)) {
        throw new RuntimeException(
            'Managed category color must contain exactly six hexadecimal digits.'
        );
    }

    $statement = db()->prepare(
        'INSERT INTO app_settings
            (setting_key, setting_value, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(setting_key) DO UPDATE SET
            setting_value=excluded.setting_value,
            updated_at=excluded.updated_at'
    );

    $now = gmdate('c');

    $statement->execute([
        'managed_category_name',
        $name,
        $now,
    ]);

    $statement->execute([
        'managed_category_color',
        $color,
        $now,
    ]);
}
