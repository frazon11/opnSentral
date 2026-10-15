<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';

require_login();
require_csrf();
require_configuration_unlocked();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

function ids_action_bool(mixed $value): bool
{
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return $value !== 0;
    if (is_array($value)) {
        foreach ($value as $item) {
            if (is_array($item) && !empty($item['selected'])) return true;
        }
        foreach (['value','selected'] as $key) {
            if (isset($value[$key]) && !is_array($value[$key])) $value=$value[$key];
        }
    }
    return in_array(strtolower(trim((string)$value)), ['1','true','yes','on','enabled','selected'], true);
}

function ids_action_success(array $response): bool
{
    if (($response['error'] ?? '') !== '') return false;
    if (isset($response['validations']) && is_array($response['validations']) && $response['validations'] !== []) return false;
    foreach (['result','status'] as $key) {
        if (!array_key_exists($key,$response)) continue;
        $value=strtolower(trim((string)$response[$key]));
        if (in_array($value,['failed','failure','error','invalid','rejected'],true)) return false;
    }
    return true;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    if ((string)($_POST['action'] ?? '') !== 'set_enabled') throw new RuntimeException('Unsupported IDS action.');

    $firewallId=(int)($_POST['firewall_id'] ?? 0);
    if ($firewallId < 1) throw new RuntimeException('Invalid firewall.');
    $enabled=filter_var($_POST['enabled'] ?? false,FILTER_VALIDATE_BOOL);

    $firewall=firewall_by_id($firewallId);
    $before=opn_raw_request($firewall,'ids/settings/get','GET',null,20);
    $current=ids_action_bool($before['ids']['general']['enabled'] ?? false);

    if ($current !== $enabled) {
        backup_before_change($firewall,$enabled?'ids-enable':'ids-disable');

        $set=opn_raw_request(
            $firewall,
            'ids/settings/set',
            'POST',
            ['ids'=>['general'=>['enabled'=>$enabled?'1':'0']]],
            30
        );
        if (!ids_action_success($set)) {
            throw new RuntimeException('OPNsense rejected the IDS setting change: '.json_encode($set,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        }

        $apply=opn_raw_request($firewall,'ids/service/reconfigure','POST',[],90);
        if (!ids_action_success($apply)) {
            throw new RuntimeException('OPNsense rejected IDS reconfigure: '.json_encode($apply,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        }
    }

    $after=opn_raw_request($firewall,'ids/settings/get','GET',null,20);
    $verified=ids_action_bool($after['ids']['general']['enabled'] ?? false);
    if ($verified !== $enabled) throw new RuntimeException('Verification failed: OPNsense did not confirm the requested IDS state.');

    echo json_encode([
        'ok'=>true,
        'enabled'=>$verified,
        'message'=>'IDS/IPS '.($verified?'enabled':'disabled').' on '.$firewall['name'].'.',
    ],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
