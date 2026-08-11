<?php

require_once __DIR__ . '/managed_category.php';

function central_alias_init(): void
{
    db()->exec(
        'CREATE TABLE IF NOT EXISTS central_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            content TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT "",
            enabled INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL
        )'
    );

    db()->exec(
        'CREATE TABLE IF NOT EXISTS central_alias_targets (
            alias_id INTEGER NOT NULL,
            firewall_id INTEGER NOT NULL,
            last_status TEXT NOT NULL DEFAULT "unknown",
            last_message TEXT NOT NULL DEFAULT "",
            last_checked_at TEXT,
            PRIMARY KEY (alias_id, firewall_id)
        )'
    );
}

function central_alias_lines(string $content): array
{
    $lines = preg_split('/\R+/', $content) ?: [];
    $result = [];

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line !== '' && !in_array($line, $result, true)) {
            $result[] = $line;
        }
    }

    sort($result, SORT_NATURAL | SORT_FLAG_CASE);
    return $result;
}

function central_alias_category_uuid(array $firewall): ?string
{
    $response = opn_request(
        $firewall,
        'firewall/alias/list_categories',
        'GET',
        [],
        15
    );

    $walk = function ($value, $key = null) use (&$walk): ?string {
        if (is_array($value)) {
            $name = $value['name'] ?? $value['label'] ?? null;
            $uuid = $value['uuid'] ?? $value['id'] ?? null;

            if (is_string($name) && strcasecmp($name, managed_category_name()) === 0 && is_string($uuid)) {
                return $uuid;
            }

            foreach ($value as $childKey => $childValue) {
                if (is_string($childValue) && strcasecmp($childValue, managed_category_name()) === 0 && is_string($childKey)) {
                    return $childKey;
                }

                $found = $walk($childValue, $childKey);
                if ($found !== null) {
                    return $found;
                }
            }
        }

        return null;
    };

    return $walk($response);
}

function central_alias_find(array $firewall, string $name): ?array
{
    try {
        $uuidResponse = opn_request(
            $firewall,
            'firewall/alias/get_alias_u_u_i_d/' . rawurlencode($name),
            'GET',
            [],
            15
        );

        $uuid = $uuidResponse['uuid'] ?? $uuidResponse['result'] ?? null;
        if (is_string($uuid) && $uuid !== '') {
            $item = opn_request(
                $firewall,
                'firewall/alias/get_item/' . rawurlencode($uuid),
                'GET',
                [],
                15
            );
            $alias = is_array($item['alias'] ?? null) ? $item['alias'] : $item;
            $alias['uuid'] = $uuid;
            return $alias;
        }
    } catch (Throwable $exception) {
        // Search fallback below.
    }

    $search = opn_request(
        $firewall,
        'firewall/alias/search_item',
        'POST',
        [
            'current' => 1,
            'rowCount' => 500,
            'searchPhrase' => $name,
        ],
        20
    );

    foreach (($search['rows'] ?? []) as $row) {
        if (strcasecmp((string) ($row['name'] ?? ''), $name) === 0) {
            $uuid = (string) ($row['uuid'] ?? '');
            if ($uuid === '') {
                return $row;
            }

            $item = opn_request(
                $firewall,
                'firewall/alias/get_item/' . rawurlencode($uuid),
                'GET',
                [],
                15
            );
            $alias = is_array($item['alias'] ?? null) ? $item['alias'] : $item;
            $alias['uuid'] = $uuid;
            return $alias;
        }
    }

    return null;
}

function central_alias_has_category(array $alias, string $categoryUuid): bool
{
    $categories = $alias['categories'] ?? '';

    if (is_array($categories)) {
        return in_array($categoryUuid, array_map('strval', $categories), true);
    }

    $parts = preg_split('/[\s,;]+/', (string) $categories) ?: [];
    return in_array($categoryUuid, $parts, true);
}

function central_alias_merge_category(
    mixed $categories,
    string $categoryUuid
): array|string {
    if (is_array($categories)) {
        $result = array_values(array_unique(array_filter(
            array_map('strval', $categories),
            static fn (string $value): bool => trim($value) !== ''
        )));

        if (!in_array($categoryUuid, $result, true)) {
            $result[] = $categoryUuid;
        }

        return $result;
    }

    $parts = preg_split('/[\s,;]+/', trim((string) $categories)) ?: [];
    $parts = array_values(array_unique(array_filter(
        array_map('trim', $parts),
        static fn (string $value): bool => $value !== ''
    )));

    if (!in_array($categoryUuid, $parts, true)) {
        $parts[] = $categoryUuid;
    }

    return implode(',', $parts);
}

function central_alias_save_definition(
    string $name,
    string $type,
    string $content,
    string $description,
    int $enabled
): int {
    $statement = db()->prepare(
        'INSERT INTO central_aliases (name, type, content, description, enabled, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET
            type=excluded.type,
            content=excluded.content,
            description=excluded.description,
            enabled=excluded.enabled,
            updated_at=excluded.updated_at'
    );

    $statement->execute([
        $name,
        $type,
        $content,
        $description,
        $enabled,
        gmdate('c'),
    ]);

    $lookup = db()->prepare('SELECT id FROM central_aliases WHERE name = ?');
    $lookup->execute([$name]);
    return (int) $lookup->fetchColumn();
}

function central_alias_target_status(
    int $aliasId,
    int $firewallId,
    string $status,
    string $message
): void {
    $statement = db()->prepare(
        'INSERT INTO central_alias_targets
            (alias_id, firewall_id, last_status, last_message, last_checked_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(alias_id, firewall_id) DO UPDATE SET
            last_status=excluded.last_status,
            last_message=excluded.last_message,
            last_checked_at=excluded.last_checked_at'
    );

    $statement->execute([
        $aliasId,
        $firewallId,
        $status,
        $message,
        gmdate('c'),
    ]);
}
