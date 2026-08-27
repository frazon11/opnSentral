<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/alias_central.php';
require_once __DIR__ . '/inc/managed_category.php';

require_login();
central_alias_init();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function deploy_alias_success(array $response): bool
{
    $validations = $response['validations'] ?? null;
    if (is_array($validations) && $validations !== []) {
        return false;
    }

    foreach (['result', 'status'] as $field) {
        if (!array_key_exists($field, $response)) {
            continue;
        }
        $value = $response[$field];
        if ($value === false || $value === 0 || $value === '0') {
            return false;
        }
        if (is_string($value)) {
            $normalized = strtolower(trim($value));
            if (in_array($normalized, ['failed', 'failure', 'error', 'invalid', 'rejected'], true)) {
                return false;
            }
        }
    }

    return true;
}

function deploy_alias_scalar(mixed $value): string
{
    if (is_array($value)) {
        foreach ($value as $key => $item) {
            if (is_bool($item) && $item) {
                return (string) $key;
            }
            if (is_scalar($item) && trim((string) $item) !== '') {
                return trim((string) $item);
            }
        }
        return '';
    }
    return trim((string) $value);
}

function deploy_alias_bool(mixed $value): int
{
    if (is_array($value)) {
        $value = deploy_alias_scalar($value);
    }
    return in_array(strtolower(trim((string) $value)), ['1', 'true', 'yes', 'on', 'enabled'], true) ? 1 : 0;
}

function deploy_alias_firewall(int $id): array
{
    $stmt = db()->prepare('SELECT * FROM firewalls WHERE id = ?');
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    if (!$row) {
        throw new RuntimeException('Firewall not found.');
    }
    return $row;
}

function deploy_alias_find(array $firewall, string $name): ?array
{
    $response = opn_raw_request(
        $firewall,
        'firewall/alias/search_item',
        'POST',
        [
            'current' => 1,
            'rowCount' => -1,
            'searchPhrase' => $name,
            'sort' => new stdClass(),
        ],
        25
    );

    foreach (($response['rows'] ?? []) as $row) {
        if (is_array($row) && strcasecmp(trim((string) ($row['name'] ?? '')), $name) === 0) {
            return $row;
        }
    }
    return null;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('POST required.');
    }
    require_csrf();
    require_configuration_unlocked();

    $name = trim((string) ($_POST['name'] ?? ''));
    $sourceId = (int) ($_POST['source_firewall_id'] ?? 0);
    $targetIds = array_values(array_unique(array_filter(
        array_map('intval', (array) ($_POST['target_firewall_ids'] ?? [])),
        static fn (int $id): bool => $id > 0
    )));

    if ($name === '' || !preg_match('/^[A-Za-z0-9_]+$/', $name)) {
        throw new RuntimeException('Invalid alias name.');
    }
    if ($sourceId <= 0) {
        throw new RuntimeException('Source firewall is required.');
    }
    $targetIds = array_values(array_filter($targetIds, static fn (int $id): bool => $id !== $sourceId));
    if ($targetIds === []) {
        throw new RuntimeException('There are no remaining firewalls to deploy this alias to.');
    }

    $source = deploy_alias_firewall($sourceId);
    $sourceMatch = deploy_alias_find($source, $name);
    if ($sourceMatch === null) {
        throw new RuntimeException('Alias "' . $name . '" was not found on source firewall ' . $source['name'] . '.');
    }

    $sourceUuid = trim((string) ($sourceMatch['uuid'] ?? $sourceMatch['id'] ?? ''));
    if ($sourceUuid === '') {
        throw new RuntimeException('Source alias has no UUID.');
    }

    $current = opn_raw_request(
        $source,
        'firewall/alias/get_item/' . rawurlencode($sourceUuid),
        'GET',
        null,
        25
    );
    $model = isset($current['alias']) && is_array($current['alias']) ? $current['alias'] : $current;

    $type = deploy_alias_scalar($model['type'] ?? $sourceMatch['type'] ?? '');
    $content = deploy_alias_scalar($model['content'] ?? $sourceMatch['content'] ?? '');
    $description = deploy_alias_scalar($model['description'] ?? $model['descr'] ?? $sourceMatch['description'] ?? '');
    $enabled = deploy_alias_bool($model['enabled'] ?? $sourceMatch['enabled'] ?? true);

    if ($type === '' || central_alias_lines($content) === []) {
        throw new RuntimeException('Source alias definition is incomplete and cannot be deployed safely.');
    }

    $aliasId = central_alias_save_definition($name, $type, $content, $description, $enabled);

    $marks = implode(',', array_fill(0, count($targetIds), '?'));
    $stmt = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $marks . ') ORDER BY name');
    $stmt->execute($targetIds);
    $targets = $stmt->fetchAll();

    if (count($targets) !== count($targetIds)) {
        throw new RuntimeException('One or more target firewalls no longer exist.');
    }

    $results = [];
    foreach ($targets as $firewall) {
        $entry = [
            'id' => (int) $firewall['id'],
            'name' => (string) $firewall['name'],
            'ok' => false,
            'message' => '',
        ];

        try {
            if (deploy_alias_find($firewall, $name) !== null) {
                $entry['ok'] = true;
                $entry['message'] = 'Already exists; left unchanged.';
                $results[] = $entry;
                continue;
            }

            $categoryUuid = central_alias_category_uuid($firewall);
            if ($categoryUuid === null) {
                throw new RuntimeException('Managed category "' . managed_category_name() . '" is missing.');
            }

            backup_before_change($firewall, 'alias-distribution');

            $response = opn_raw_request(
                $firewall,
                'firewall/alias/add_item',
                'POST',
                ['alias' => [
                    'enabled' => (string) $enabled,
                    'name' => $name,
                    'type' => $type,
                    'content' => $content,
                    'description' => $description,
                    'categories' => $categoryUuid,
                ]],
                30
            );
            if (!deploy_alias_success($response)) {
                throw new RuntimeException('OPNsense rejected alias creation: ' . json_encode($response));
            }

            $apply = opn_raw_request($firewall, 'firewall/alias/reconfigure', 'POST', [], 45);
            if (!deploy_alias_success($apply)) {
                throw new RuntimeException('Alias was created, but reconfigure failed: ' . json_encode($apply));
            }

            $verify = deploy_alias_find($firewall, $name);
            if ($verify === null) {
                throw new RuntimeException('Alias creation returned success but verification failed.');
            }

            central_alias_target_status($aliasId, (int) $firewall['id'], 'synchronized', 'Deployed from ' . $source['name'] . ' and verified.');
            $entry['ok'] = true;
            $entry['message'] = 'Deployed and verified.';
        } catch (Throwable $exception) {
            central_alias_target_status($aliasId, (int) $firewall['id'], 'error', $exception->getMessage());
            $entry['message'] = $exception->getMessage();
        }

        $results[] = $entry;
    }

    echo json_encode([
        'ok' => true,
        'source' => (string) $source['name'],
        'results' => $results,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
