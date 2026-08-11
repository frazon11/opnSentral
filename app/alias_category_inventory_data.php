<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
ob_start();

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/alias_central.php';
require_once __DIR__ . '/inc/category_central.php';
require_once __DIR__ . '/inc/managed_category.php';

require_login();
central_alias_init();
central_category_init();

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function inventory_rows(array $response): array
{
    if (isset($response['rows']) && is_array($response['rows'])) {
        return $response['rows'];
    }

    foreach ($response as $candidate) {
        if (is_array($candidate) && array_is_list($candidate)) {
            return $candidate;
        }
    }

    return [];
}

function inventory_bool(mixed $value): bool
{
    if (is_bool($value)) {
        return $value;
    }

    return in_array(
        strtolower(trim((string) $value)),
        ['1', 'true', 'yes', 'on', 'enabled'],
        true
    );
}

function inventory_category_uuid(array $value): ?string
{
    $walk = function (mixed $node) use (&$walk): ?string {
        if (!is_array($node)) {
            return null;
        }

        $name = $node['name'] ?? $node['label'] ?? null;
        $uuid = $node['uuid'] ?? $node['id'] ?? null;

        if (
            is_string($name) &&
            strcasecmp($name, managed_category_name()) === 0 &&
            is_string($uuid) &&
            trim($uuid) !== ''
        ) {
            return trim($uuid);
        }

        foreach ($node as $key => $child) {
            if (
                is_string($child) &&
                strcasecmp($child, managed_category_name()) === 0 &&
                is_string($key) &&
                trim($key) !== ''
            ) {
                return trim($key);
            }

            $found = $walk($child);
            if ($found !== null) {
                return $found;
            }
        }

        return null;
    };

    return $walk($value);
}

function inventory_alias_categories(mixed $value): array
{
    if (is_array($value)) {
        return array_values(array_unique(array_filter(
            array_map(
                static fn(mixed $item): string => trim((string) $item),
                $value
            ),
            static fn(string $item): bool => $item !== ''
        )));
    }

    return array_values(array_unique(array_filter(
        preg_split('/[\s,;]+/', trim((string) $value)) ?: [],
        static fn(string $item): bool => trim($item) !== ''
    )));
}

try {
    $firewalls = db()
        ->query('SELECT * FROM firewalls ORDER BY name')
        ->fetchAll();

    $centralAliases = db()
        ->query(
            'SELECT id,name,type,enabled
             FROM central_aliases
             ORDER BY name'
        )
        ->fetchAll();

    $centralCategories = db()
        ->query(
            'SELECT id,name,color,automatic
             FROM central_categories
             ORDER BY name'
        )
        ->fetchAll();

    $aliasDefinitions = [];
    foreach ($centralAliases as $alias) {
        $aliasDefinitions[strtolower((string) $alias['name'])] = $alias;
    }

    $categoryDefinitions = [];
    foreach ($centralCategories as $category) {
        $categoryDefinitions[
            strtolower((string) $category['name'])
        ] = $category;
    }

    $aliasTargets = [];
    foreach (
        db()->query(
            'SELECT t.*,a.name
             FROM central_alias_targets t
             JOIN central_aliases a ON a.id=t.alias_id'
        )->fetchAll() as $target
    ) {
        $aliasTargets[
            (int) $target['firewall_id']
        ][
            strtolower((string) $target['name'])
        ] = $target;
    }

    $categoryTargets = [];
    foreach (
        db()->query(
            'SELECT t.*,c.name
             FROM central_category_targets t
             JOIN central_categories c ON c.id=t.category_id'
        )->fetchAll() as $target
    ) {
        $categoryTargets[
            (int) $target['firewall_id']
        ][
            strtolower((string) $target['name'])
        ] = $target;
    }

    $requests = [];

    foreach ($firewalls as $firewall) {
        $id = (int) $firewall['id'];

        $requests["{$id}.aliases"] = [
            'firewall' => $firewall,
            'path' => 'firewall/alias/search_item',
            'method' => 'POST',
            'payload' => [
                'current' => 1,
                'rowCount' => -1,
                'searchPhrase' => '',
                'sort' => new stdClass(),
            ],
            'timeout' => 25,
        ];

        $requests["{$id}.alias_categories"] = [
            'firewall' => $firewall,
            'path' => 'firewall/alias/list_categories',
            'method' => 'GET',
            'timeout' => 20,
        ];

        $requests["{$id}.categories"] = [
            'firewall' => $firewall,
            'path' => 'firewall/category/search_item',
            'method' => 'POST',
            'payload' => [
                'current' => 1,
                'rowCount' => -1,
                'searchPhrase' => '',
                'sort' => new stdClass(),
            ],
            'timeout' => 25,
        ];
    }

    $responses = opn_requests_parallel($requests);
    $result = [];

    foreach ($firewalls as $firewall) {
        $id = (int) $firewall['id'];
        $aliasResponse = $responses["{$id}.aliases"] ?? [];
        $aliasCategoryResponse =
            $responses["{$id}.alias_categories"] ?? [];
        $categoryResponse = $responses["{$id}.categories"] ?? [];

        $aliasError = ($aliasResponse['ok'] ?? false) === true
            ? null
            : (string) (
                $aliasResponse['error'] ??
                'Could not load aliases.'
            );

        $categoryError = ($categoryResponse['ok'] ?? false) === true
            ? null
            : (string) (
                $categoryResponse['error'] ??
                'Could not load categories.'
            );

        $opnCentralCategoryUuid =
            ($aliasCategoryResponse['ok'] ?? false) === true
                ? inventory_category_uuid(
                    (array) $aliasCategoryResponse['value']
                )
                : null;

        $aliases = [];

        if ($aliasError === null) {
            foreach (
                inventory_rows(
                    (array) $aliasResponse['value']
                ) as $row
            ) {
                if (!is_array($row)) {
                    continue;
                }

                $name = trim((string) ($row['name'] ?? ''));

                if ($name === '') {
                    continue;
                }

                $key = strtolower($name);
                $categories = inventory_alias_categories(
                    $row['categories'] ?? ''
                );
                $managedByMarker =
                    $opnCentralCategoryUuid !== null &&
                    in_array(
                        $opnCentralCategoryUuid,
                        $categories,
                        true
                    );
                $definition = $aliasDefinitions[$key] ?? null;
                $target = $aliasTargets[$id][$key] ?? null;

                $aliases[] = [
                    'uuid' => (string) (
                        $row['uuid'] ??
                        $row['id'] ??
                        ''
                    ),
                    'name' => $name,
                    'type' => (string) ($row['type'] ?? ''),
                    'description' => (string) (
                        $row['description'] ??
                        $row['descr'] ??
                        ''
                    ),
                    'enabled' => inventory_bool(
                        $row['enabled'] ?? true
                    ),
                    'content' => (string) (
                        $row['content'] ??
                        ''
                    ),
                    'managed' => $managedByMarker,
                    'known_definition' => $definition !== null,
                    'management_reason' => $managedByMarker
                        ? 'Assigned to the managed category: ' . managed_category_name()
                        : 'Not assigned to the managed category: ' . managed_category_name(),
                    'last_status' => (string) (
                        $target['last_status'] ??
                        ($managedByMarker ? 'unknown' : 'unmanaged')
                    ),
                    'last_message' => (string) (
                        $target['last_message'] ??
                        ($managedByMarker
                            ? 'Not checked'
                            : 'Exists only on this OPNsense')
                    ),
                    'last_checked_at' =>
                        $target['last_checked_at'] ?? null,
                ];
            }
        }

        usort(
            $aliases,
            static fn(array $a, array $b): int =>
                strnatcasecmp($a['name'], $b['name'])
        );

        $categories = [];

        if ($categoryError === null) {
            foreach (
                inventory_rows(
                    (array) $categoryResponse['value']
                ) as $row
            ) {
                if (!is_array($row)) {
                    continue;
                }

                $name = trim((string) ($row['name'] ?? ''));

                if ($name === '') {
                    continue;
                }

                $key = strtolower($name);
                $definition = $categoryDefinitions[$key] ?? null;
                $target = $categoryTargets[$id][$key] ?? null;
                $managed = $definition !== null;

                $categories[] = [
                    'uuid' => (string) (
                        $row['uuid'] ??
                        $row['id'] ??
                        ''
                    ),
                    'name' => $name,
                    'color' => (string) (
                        $row['color'] ??
                        ''
                    ),
                    'automatic' => inventory_bool(
                        $row['auto'] ??
                        $row['automatic'] ??
                        false
                    ),
                    'managed' => $managed,
                    'management_reason' => $managed
                        ? 'Name exists in opnCentral central definitions'
                        : 'Not present in opnCentral central definitions',
                    'last_status' => (string) (
                        $target['last_status'] ??
                        ($managed ? 'unknown' : 'unmanaged')
                    ),
                    'last_message' => (string) (
                        $target['last_message'] ??
                        ($managed
                            ? 'Not checked'
                            : 'Exists only on this OPNsense')
                    ),
                    'last_checked_at' =>
                        $target['last_checked_at'] ?? null,
                ];
            }
        }

        usort(
            $categories,
            static fn(array $a, array $b): int =>
                strnatcasecmp($a['name'], $b['name'])
        );

        $result[] = [
            'firewall' => [
                'id' => $id,
                'name' => (string) $firewall['name'],
                'base_url' => (string) $firewall['base_url'],
            ],
            'aliases_ok' => $aliasError === null,
            'aliases_error' => $aliasError,
            'aliases' => $aliases,
            'categories_ok' => $categoryError === null,
            'categories_error' => $categoryError,
            'categories' => $categories,
            'opncentral_category_uuid' =>
                $opnCentralCategoryUuid,
        ];
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode(
        [
            'ok' => true,
            'firewalls' => $result,
            'central_alias_count' => count($centralAliases),
            'central_category_count' => count($centralCategories),
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
        [
            'ok' => false,
            'error' => $exception->getMessage(),
        ],
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    );
}
