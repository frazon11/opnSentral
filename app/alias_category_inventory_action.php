<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function inventory_action_success(array $response): bool
{
    if (($response['error'] ?? '') !== '') return false;
    foreach (['result','status'] as $key) {
        if (!array_key_exists($key, $response)) continue;
        return in_array(strtolower(trim((string)$response[$key])), ['1','true','ok','saved','success','done'], true);
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

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();
    require_configuration_unlocked();

    $type = strtolower(trim((string)($_POST['type'] ?? '')));
    if (!in_array($type, ['categories','aliases'], true)) throw new RuntimeException('Unsupported inventory type.');

    $oldName = trim((string)($_POST['old_name'] ?? ''));
    $newName = trim((string)($_POST['new_name'] ?? ''));
    if ($oldName === '' || $newName === '') throw new RuntimeException('Old and new names are required.');
    if ($oldName === $newName) throw new RuntimeException('The new name is unchanged.');

    $ids = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['firewall_ids'] ?? [])), static fn(int $id): bool => $id > 0)));
    $firewalls = inventory_action_firewalls($ids);
    $controller = $type === 'categories' ? 'category' : 'alias';
    $root = $type === 'categories' ? 'category' : 'alias';
    $results = [];

    foreach ($firewalls as $firewall) {
        $entry = ['id'=>(int)$firewall['id'], 'name'=>(string)$firewall['name'], 'ok'=>false, 'message'=>''];
        try {
            $search = opn_raw_request($firewall, 'firewall/' . $controller . '/search_item', 'POST', [
                'current'=>1, 'rowCount'=>-1, 'searchPhrase'=>$oldName, 'sort'=>new stdClass()
            ], 25);
            $rows = isset($search['rows']) && is_array($search['rows']) ? $search['rows'] : [];
            $match = null;
            foreach ($rows as $row) {
                if (is_array($row) && strcasecmp(trim((string)($row['name'] ?? '')), $oldName) === 0) { $match = $row; break; }
            }
            if ($match === null) throw new RuntimeException('Entry not found.');
            $uuid = trim((string)($match['uuid'] ?? $match['id'] ?? ''));
            if ($uuid === '') throw new RuntimeException('OPNsense did not return a UUID.');

            $current = opn_raw_request($firewall, 'firewall/' . $controller . '/get_item/' . rawurlencode($uuid), 'GET', null, 20);
            $model = isset($current[$root]) && is_array($current[$root]) ? $current[$root] : $current;
            $model['name'] = $newName;
            $response = opn_raw_request($firewall, 'firewall/' . $controller . '/set_item/' . rawurlencode($uuid), 'POST', [$root=>$model], 30);
            if (!inventory_action_success($response)) throw new RuntimeException('OPNsense rejected the rename: ' . json_encode($response));

            if ($type === 'aliases') {
                $apply = opn_raw_request($firewall, 'firewall/alias/reconfigure', 'POST', [], 45);
                if (!inventory_action_success($apply)) throw new RuntimeException('Alias renamed, but reconfigure failed: ' . json_encode($apply));
            }

            $entry['ok'] = true;
            $entry['message'] = $oldName . ' renamed to ' . $newName . '.';
        } catch (Throwable $e) {
            $entry['message'] = $e->getMessage();
        }
        $results[] = $entry;
    }

    echo json_encode(['ok'=>true,'results'=>$results], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$e->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
