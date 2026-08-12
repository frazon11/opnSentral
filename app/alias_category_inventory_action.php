<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/alias_central.php';
require_once __DIR__ . '/inc/category_central.php';
require_once __DIR__ . '/inc/managed_category.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function inventory_action_success(array $response): bool
{
    if (($response['error'] ?? '') !== '') return false;
    foreach (['result', 'status'] as $key) {
        if (!array_key_exists($key, $response)) continue;
        return in_array(
            strtolower(trim((string) $response[$key])),
            ['1', 'true', 'ok', 'saved', 'success', 'done'],
            true
        );
    }
    return true;
}

function inventory_action_firewalls(array $ids): array
{
    if ($ids === []) throw new RuntimeException('No target firewall selected.');
    $marks = implode(',', array_fill(0, count($ids), '?'));
    $stmt = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $marks . ') ORDER BY name');
    $stmt->execute($ids);
    return $stmt->fetchAll();
}

function inventory_action_preflight_central_name(
    string $type,
    string $oldName,
    string $newName
): void {
    $pdo = db();
    $table = $type === 'aliases' ? 'central_aliases' : 'central_categories';
    $init = $type === 'aliases' ? 'central_alias_init' : 'central_category_init';
    $init();

    $old = $pdo->prepare('SELECT id FROM ' . $table . ' WHERE name = ?');
    $old->execute([$oldName]);
    $oldId = (int) ($old->fetchColumn() ?: 0);
    if ($oldId <= 0) return;

    $duplicate = $pdo->prepare('SELECT id FROM ' . $table . ' WHERE name = ? AND id <> ?');
    $duplicate->execute([$newName, $oldId]);
    if ($duplicate->fetchColumn()) {
        throw new RuntimeException(
            'A central ' . ($type === 'aliases' ? 'alias' : 'category') .
            ' named "' . $newName . '" already exists.'
        );
    }
}

function inventory_action_sync_central_definition(
    string $type,
    string $oldName,
    string $newName
): void {
    $pdo = db();

    if ($type === 'aliases') {
        central_alias_init();
        $check = $pdo->prepare('SELECT id FROM central_aliases WHERE name = ?');
        $check->execute([$oldName]);
        $id = (int) ($check->fetchColumn() ?: 0);
        if ($id <= 0) return;

        $update = $pdo->prepare('UPDATE central_aliases SET name = ?, updated_at = ? WHERE id = ?');
        $update->execute([$newName, gmdate('c'), $id]);
        return;
    }

    central_category_init();
    $check = $pdo->prepare('SELECT id FROM central_categories WHERE name = ?');
    $check->execute([$oldName]);
    $id = (int) ($check->fetchColumn() ?: 0);
    if ($id > 0) {
        $update = $pdo->prepare('UPDATE central_categories SET name = ?, updated_at = ? WHERE id = ?');
        $update->execute([$newName, gmdate('c'), $id]);
    }

    if (strcasecmp($oldName, managed_category_name()) === 0) {
        save_managed_category_settings($newName, managed_category_color());
    }
}

function inventory_action_search_exact(
    array $firewall,
    string $controller,
    string $name
): ?array {
    $search = opn_raw_request(
        $firewall,
        'firewall/' . $controller . '/search_item',
        'POST',
        [
            'current' => 1,
            'rowCount' => -1,
            'searchPhrase' => $name,
            'sort' => new stdClass(),
        ],
        25
    );

    foreach (($search['rows'] ?? []) as $row) {
        if (
            is_array($row)
            && strcasecmp(trim((string) ($row['name'] ?? '')), $name) === 0
        ) {
            return $row;
        }
    }

    return null;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();
    require_configuration_unlocked();

    $type = strtolower(trim((string) ($_POST['type'] ?? '')));
    if (!in_array($type, ['categories', 'aliases'], true)) {
        throw new RuntimeException('Unsupported inventory type.');
    }

    $oldName = trim((string) ($_POST['old_name'] ?? ''));
    $newName = trim((string) ($_POST['new_name'] ?? ''));
    if ($oldName === '' || $newName === '') {
        throw new RuntimeException('Old and new names are required.');
    }
    if ($oldName === $newName) throw new RuntimeException('The new name is unchanged.');

    if ($type === 'aliases' && !preg_match('/^[A-Za-z0-9_]+$/', $newName)) {
        throw new RuntimeException('Alias name may contain only letters, numbers and underscores.');
    }
    if ($type === 'categories' && mb_strlen($newName) > 255) {
        throw new RuntimeException('Category name may contain at most 255 characters.');
    }

    $syncCentral = isset($_POST['sync_central']) && $_POST['sync_central'] === '1';
    if ($syncCentral) {
        inventory_action_preflight_central_name($type, $oldName, $newName);
    }

    $ids = array_values(array_unique(array_filter(
        array_map('intval', (array) ($_POST['firewall_ids'] ?? [])),
        static fn (int $id): bool => $id > 0
    )));
    $firewalls = inventory_action_firewalls($ids);
    $controller = $type === 'categories' ? 'category' : 'alias';
    $root = $type === 'categories' ? 'category' : 'alias';
    $results = [];

    foreach ($firewalls as $firewall) {
        $entry = [
            'id' => (int) $firewall['id'],
            'name' => (string) $firewall['name'],
            'ok' => false,
            'message' => '',
        ];

        try {
            $match = inventory_action_search_exact($firewall, $controller, $oldName);
            if ($match === null) throw new RuntimeException('Entry not found.');

            $duplicate = inventory_action_search_exact($firewall, $controller, $newName);
            if ($duplicate !== null) {
                throw new RuntimeException('An entry named "' . $newName . '" already exists.');
            }

            backup_before_change(
                $firewall,
                $type === 'aliases' ? 'alias-rename' : 'category-rename'
            );

            $uuid = trim((string) ($match['uuid'] ?? $match['id'] ?? ''));
            if ($uuid === '') throw new RuntimeException('OPNsense did not return a UUID.');

            $current = opn_raw_request(
                $firewall,
                'firewall/' . $controller . '/get_item/' . rawurlencode($uuid),
                'GET',
                null,
                20
            );
            $model = isset($current[$root]) && is_array($current[$root])
                ? $current[$root]
                : $current;
            $model['name'] = $newName;

            $response = opn_raw_request(
                $firewall,
                'firewall/' . $controller . '/set_item/' . rawurlencode($uuid),
                'POST',
                [$root => $model],
                30
            );
            if (!inventory_action_success($response)) {
                throw new RuntimeException(
                    'OPNsense rejected the rename: ' . json_encode($response)
                );
            }

            if ($type === 'aliases') {
                $apply = opn_raw_request(
                    $firewall,
                    'firewall/alias/reconfigure',
                    'POST',
                    [],
                    45
                );
                if (!inventory_action_success($apply)) {
                    throw new RuntimeException(
                        'Alias renamed, but reconfigure failed: ' . json_encode($apply)
                    );
                }
            }

            $entry['ok'] = true;
            $entry['message'] = $oldName . ' renamed to ' . $newName . '.';
        } catch (Throwable $exception) {
            $entry['message'] = $exception->getMessage();
        }

        $results[] = $entry;
    }

    $failures = array_filter($results, static fn (array $result): bool => !$result['ok']);
    if ($syncCentral && $failures === []) {
        inventory_action_sync_central_definition($type, $oldName, $newName);
    }

    echo json_encode([
        'ok' => true,
        'central_synced' => $syncCentral && $failures === [],
        'results' => $results,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
