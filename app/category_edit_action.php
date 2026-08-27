<?php
declare(strict_types=1);
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/category_central.php';
require_login();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function category_edit_success(array $response): bool
{
    if (($response['error'] ?? '') !== '') return false;
    $validations=$response['validations']??null;
    if(is_array($validations)&&$validations!==[]) return false;
    foreach (['result','status'] as $key) {
        if (!array_key_exists($key, $response)) continue;
        $value=$response[$key];
        if($value===false||$value===0||$value==='0') return false;
        if(is_string($value)&&in_array(strtolower(trim($value)),['failed','failure','error','invalid','rejected'],true)) return false;
    }
    return true;
}

function category_edit_scalar(mixed $value): string
{
    if(!is_array($value)) return trim((string)$value);
    foreach($value as $key=>$item){
        if(is_array($item)&&!empty($item['selected'])) return is_string($key)?trim($key):trim((string)($item['value']??$item['name']??''));
    }
    foreach($value as $key=>$item){
        if(is_string($key)&&!is_array($item)&&in_array(strtolower(trim((string)$item)),['1','true','yes','on','selected'],true)) return trim($key);
    }
    foreach($value as $item){if(!is_array($item)&&trim((string)$item)!=='') return trim((string)$item);}
    return '';
}

function category_edit_bool(mixed $value): int
{
    return in_array(strtolower(category_edit_scalar($value)),['1','true','yes','on','enabled'],true)?1:0;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    require_csrf();
    require_configuration_unlocked();

    $oldName = trim((string)($_POST['old_name'] ?? ''));
    $newName = trim((string)($_POST['new_name'] ?? ''));
    $color = central_category_normalize_color((string)($_POST['color'] ?? ''));
    $automatic = isset($_POST['automatic']) ? 1 : 0;
    $ids = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['firewall_ids'] ?? [])), static fn(int $id): bool => $id > 0)));

    if ($oldName === '' || $newName === '') throw new RuntimeException('Old and new category names are required.');
    if (mb_strlen($newName) > 255) throw new RuntimeException('Category name is too long.');
    if ($ids === []) throw new RuntimeException('No target firewall selected.');

    $marks = implode(',', array_fill(0, count($ids), '?'));
    $statement = db()->prepare('SELECT * FROM firewalls WHERE id IN (' . $marks . ') ORDER BY name');
    $statement->execute($ids);
    $firewalls = $statement->fetchAll();
    $results = [];

    foreach ($firewalls as $firewall) {
        $entry = ['id'=>(int)$firewall['id'], 'name'=>(string)$firewall['name'], 'ok'=>false, 'message'=>''];
        try {
            $existing = central_category_search($firewall, $oldName);
            if ($existing === null) throw new RuntimeException('Category not found.');
            $uuid = trim((string)($existing['uuid'] ?? ''));
            if ($uuid === '') throw new RuntimeException('OPNsense did not return a category UUID.');

            backup_before_change($firewall, 'category-edit');

            $response = opn_raw_request(
                $firewall,
                'firewall/category/set_item/' . rawurlencode($uuid),
                'POST',
                ['category'=>[
                    'name'=>$newName,
                    'color'=>$color,
                    'auto'=>(string)$automatic,
                ]],
                30
            );
            if (!category_edit_success($response)) throw new RuntimeException('OPNsense rejected the category update: ' . json_encode($response, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));

            $reconfigure=opn_raw_request($firewall,'firewall/category/reconfigure','POST',[],45);
            if(!category_edit_success($reconfigure)) throw new RuntimeException('OPNsense rejected category reconfigure: '.json_encode($reconfigure,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));

            $verify=central_category_search($firewall,$newName);
            if($verify===null) throw new RuntimeException('Verification failed: category was not found after saving.');
            $verifyName=category_edit_scalar($verify['name']??'');
            $verifyColor=central_category_normalize_color(category_edit_scalar($verify['color']??''));
            $verifyAutomatic=category_edit_bool($verify['auto']??$verify['automatic']??0);
            if(strcasecmp($verifyName,$newName)!==0) throw new RuntimeException('Verification failed: category name does not match.');
            if(strcasecmp($verifyColor,$color)!==0) throw new RuntimeException('Verification failed: category color does not match.');
            if($verifyAutomatic!==$automatic) throw new RuntimeException('Verification failed: automatic state does not match.');

            $entry['ok'] = true;
            $entry['message'] = 'Updated and verified.';
        } catch (Throwable $exception) {
            $entry['message'] = $exception->getMessage();
        }
        $results[] = $entry;
    }

    $successful=array_filter($results,static fn(array $entry):bool=>($entry['ok']??false)===true);
    if($successful!==[]){
        central_category_save_definition($newName,$color,$automatic);
        if(strcasecmp($oldName,$newName)!==0){
            $delete=db()->prepare('DELETE FROM central_categories WHERE name = ? AND name <> ?');
            $delete->execute([$oldName,$newName]);
        }
    }

    echo json_encode(['ok'=>true,'results'=>$results], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
