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

/**
 * Normalize OPNsense MVC option / relation values.
 *
 * Depending on the field and OPNsense version, get_item can return a scalar,
 * a numeric list, an associative map such as ["geoip" => "GeoIP"], or the
 * older nested selected/value representation. The keys of associative maps
 * are the actual stored values (for example alias type or category UUID).
 */
function central_alias_selected_values(mixed $value): array
{
    if ($value === null || $value === '') {
        return [];
    }
    if (is_string($value) || is_int($value) || is_float($value)) {
        $parts = preg_split('/[\s,;]+/', trim((string) $value)) ?: [];
        return array_values(array_unique(array_filter($parts, static fn(string $item): bool => $item !== '')));
    }
    if (!is_array($value)) {
        return [];
    }

    $result = [];
    foreach ($value as $key => $item) {
        if (is_int($key)) {
            if (is_array($item)) {
                foreach (central_alias_selected_values($item) as $nested) {
                    $result[] = $nested;
                }
            } else {
                $candidate = trim((string) $item);
                if ($candidate !== '') {
                    $result[] = $candidate;
                }
            }
            continue;
        }

        $keyValue = trim((string) $key);
        if ($keyValue === '') {
            continue;
        }

        if (is_array($item)) {
            $selected = $item['selected'] ?? null;
            if ($selected === null || in_array($selected, [1, '1', true, 'true', 'selected'], true)) {
                $candidate = trim((string) ($item['value'] ?? $keyValue));
                if ($candidate !== '') {
                    $result[] = $candidate;
                }
            }
            continue;
        }

        // Current OPNsense MVC get_item responses use value => label maps,
        // e.g. ["geoip" => "GeoIP"] or ["<uuid>" => "Category name"].
        $result[] = $keyValue;
    }

    return array_values(array_unique($result));
}

function central_alias_scalar(mixed $value): string
{
    if (is_string($value) || is_int($value) || is_float($value)) {
        return trim((string) $value);
    }
    $values = central_alias_selected_values($value);
    return $values[0] ?? '';
}

function central_alias_content_value(mixed $value): string
{
    if (is_string($value) || is_int($value) || is_float($value)) {
        return trim((string) $value);
    }
    if (!is_array($value)) {
        return '';
    }

    $result = [];
    foreach ($value as $key => $item) {
        $candidate = '';

        if (is_array($item)) {
            // AliasContentField::getNodeData() exposes configured items as
            // value => [value => ..., selected => 1]. AliasController::getItemAction()
            // also appends every other alias with selected => 0 for the UI chooser.
            // Only selected entries are actual alias content.
            $selected = $item['selected'] ?? null;
            if (!in_array($selected, [1, '1', true, 'true', 'selected'], true)) {
                continue;
            }
            $candidate = trim((string) ($item['value'] ?? (is_string($key) ? $key : '')));
        } elseif (is_int($key)) {
            // Be tolerant of plain numeric lists returned by older APIs.
            $candidate = trim((string) $item);
        }

        if ($candidate !== '' && !in_array($candidate, $result, true)) {
            $result[] = $candidate;
        }
    }

    return implode("\n", $result);
}

function central_alias_normalize_remote(array $alias): array
{
    foreach (['name', 'type', 'enabled', 'description'] as $field) {
        if (array_key_exists($field, $alias) && is_array($alias[$field])) {
            $alias[$field] = central_alias_scalar($alias[$field]);
        }
    }
    if (array_key_exists('content', $alias) && is_array($alias['content'])) {
        $alias['content'] = central_alias_content_value($alias['content']);
    }
    if (array_key_exists('categories', $alias) && is_array($alias['categories'])) {
        $alias['categories'] = implode(',', central_alias_selected_values($alias['categories']));
    }
    return $alias;
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
            $alias = central_alias_normalize_remote($alias);
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
                return central_alias_normalize_remote($row);
            }

            $item = opn_request(
                $firewall,
                'firewall/alias/get_item/' . rawurlencode($uuid),
                'GET',
                [],
                15
            );
            $alias = is_array($item['alias'] ?? null) ? $item['alias'] : $item;
            $alias = central_alias_normalize_remote($alias);
            $alias['uuid'] = $uuid;
            return $alias;
        }
    }

    return null;
}

function central_alias_has_category(array $alias, string $categoryUuid): bool
{
    $categories = $alias['categories'] ?? '';
    $values = central_alias_selected_values($categories);
    return in_array($categoryUuid, $values, true);
}

function central_alias_merge_category(
    mixed $categories,
    string $categoryUuid
): array|string {
    $result = central_alias_selected_values($categories);
    if (!in_array($categoryUuid, $result, true)) {
        $result[] = $categoryUuid;
    }
    return implode(',', $result);
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