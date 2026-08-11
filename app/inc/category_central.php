<?php

function central_category_init(): void
{
    db()->exec(
        'CREATE TABLE IF NOT EXISTS central_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            color TEXT NOT NULL DEFAULT "",
            automatic INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )'
    );

    db()->exec(
        'CREATE TABLE IF NOT EXISTS central_category_targets (
            category_id INTEGER NOT NULL,
            firewall_id INTEGER NOT NULL,
            last_status TEXT NOT NULL DEFAULT "unknown",
            last_message TEXT NOT NULL DEFAULT "",
            last_checked_at TEXT,
            PRIMARY KEY (category_id, firewall_id)
        )'
    );
}

function central_category_search(array $firewall, string $name): ?array
{
    $response = opn_request(
        $firewall,
        'firewall/category/search_item',
        'POST',
        [
            'current' => 1,
            'rowCount' => 500,
            'searchPhrase' => $name,
        ],
        20
    );

    foreach (($response['rows'] ?? []) as $row) {
        if (strcasecmp((string) ($row['name'] ?? ''), $name) !== 0) {
            continue;
        }

        $uuid = (string) ($row['uuid'] ?? '');
        if ($uuid === '') {
            return $row;
        }

        $item = opn_request(
            $firewall,
            'firewall/category/get_item/' . rawurlencode($uuid),
            'GET',
            [],
            15
        );

        $category = is_array($item['category'] ?? null)
            ? $item['category']
            : $item;
        $category['uuid'] = $uuid;

        return $category;
    }

    return null;
}

function central_category_payload(
    string $name,
    string $color,
    int $automatic,
    ?array $existing = null
): array {
    $category = $existing ?? [];
    unset($category['uuid']);

    $category['name'] = $name;
    $category['color'] = $color;
    $category['auto'] = (string) $automatic;

    return ['category' => $category];
}

function central_category_save_definition(
    string $name,
    string $color,
    int $automatic
): int {
    $statement = db()->prepare(
        'INSERT INTO central_categories (name, color, automatic, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET
            color=excluded.color,
            automatic=excluded.automatic,
            updated_at=excluded.updated_at'
    );

    $statement->execute([
        $name,
        $color,
        $automatic,
        gmdate('c'),
    ]);

    $lookup = db()->prepare('SELECT id FROM central_categories WHERE name = ?');
    $lookup->execute([$name]);
    return (int) $lookup->fetchColumn();
}

function central_category_target_status(
    int $categoryId,
    int $firewallId,
    string $status,
    string $message
): void {
    $statement = db()->prepare(
        'INSERT INTO central_category_targets
            (category_id, firewall_id, last_status, last_message, last_checked_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(category_id, firewall_id) DO UPDATE SET
            last_status=excluded.last_status,
            last_message=excluded.last_message,
            last_checked_at=excluded.last_checked_at'
    );

    $statement->execute([
        $categoryId,
        $firewallId,
        $status,
        $message,
        gmdate('c'),
    ]);
}

function central_category_normalize_color(string $color): string
{
    $color = strtoupper(
        preg_replace('/[^0-9A-Fa-f]/', '', trim($color)) ?? ''
    );

    if ($color === '') {
        $color = 'F0AD4E';
    }

    if (!preg_match('/^[0-9A-F]{6}$/', $color)) {
        throw new RuntimeException(
            'Color must contain exactly six hexadecimal digits, for example F0AD4E.'
        );
    }

    return $color;
}
