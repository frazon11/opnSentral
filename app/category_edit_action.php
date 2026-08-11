<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_login();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function category_edit_success(array $response): bool
{
    if (($response['error'] ?? '') !== '') return false;
    foreach (['result','status'] as $key) {
        if (!array_key_exists($key, $response)) continue;
        return in_array(strtolower(trim((string)$response[$key])), ['1','true','ok','saved','success','done'], true);
    }
    return true;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();
    require_configuration_unlocked();

    $oldName = trim((string)($_POST['old_name'] ?? ''));
    $newName = trim((string)($_POST['new_name'] ?? ''));
    $color = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', (string)($_POST['color'] ?? '')) ?? '');
    $automatic = isset($_POST['automatic']) ? '1' : '0';
    $ids = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['firewall_ids'] ?? [])), static fn(int $id): bool => $id > 0)));

    if ($oldName === '' || $newName === '') throw new RuntimeException('Old and new category names are required.');
    if (mb_strlen($newName) > 255) throw new RuntimeException('Category name is too long.');
    if ($color !== '' && !preg_match('/^[0-9A-F]{6}$/', $color)) throw new RuntimeException('Color must contain exactly six hexadecimal digits.');
    if ($ids === []) throw new RuntimeException('No target firewall selected.');

    $marks = implode(',', array_fill(0, count($ids), '?'));
    $statement = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $marks . ') ORDER BY name');
    $statement->execute($ids);
    $firewalls = $statement->fetchAll();
    $results = [];

    foreach ($firewalls as $firewall) {
        $entry = ['id'=>(int)$firewall['id'], 'name'=>(string)$firewall['name'], 'ok'=>false, 'message'=>''];
        try {
            backup_before_change($firewall, 'category-edit');
            $search = opn_raw_request($firewall, 'firewall/category/search_item', 'POST', [
                'current'=>1,'rowCount'=>-1,'searchPhrase'=>$oldName,'sort'=>new stdClass()
            ], 25);
            $match = null;
            foreach (($search['rows'] ?? []) as $row) {
                if (is_array($row) && strcasecmp(trim((string)($row['name'] ?? '')), $oldName) === 0) {
                    $match = $row;
                    break;
                }
            }
            if ($match === null) throw new RuntimeException('Category not found.');
            $uuid = trim((string)($match['uuid'] ?? $match['id'] ?? ''));
            if ($uuid === '') throw new RuntimeException('OPNsense did not return a category UUID.');

            $current = opn_raw_request($firewall, 'firewall/category/get_item/' . rawurlencode($uuid), 'GET', null, 20);
            $model = isset($current['category']) && is_array($current['category']) ? $current['category'] : $current;
            $model['name'] = $newName;
            if ($color !== '') $model['color'] = $color;
            $model['auto'] = $automatic;
            if (array_key_exists('automatic', $model)) $model['automatic'] = $automatic;

            $response = opn_raw_request($firewall, 'firewall/category/set_item/' . rawurlencode($uuid), 'POST', ['category'=>$model], 30);
            if (!category_edit_success($response)) throw new RuntimeException('OPNsense rejected the category update: ' . json_encode($response));

            $entry['ok'] = true;
            $entry['message'] = 'Category saved.';
        } catch (Throwable $exception) {
            $entry['message'] = $exception->getMessage();
        }
        $results[] = $entry;
    }

    echo json_encode(['ok'=>true,'results'=>$results], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
