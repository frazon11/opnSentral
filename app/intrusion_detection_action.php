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

function ids_action_scalar(mixed $value): string
{
    if ($value === null) return '';
    if (is_string($value) || is_int($value) || is_float($value)) return trim((string)$value);
    if (!is_array($value)) return '';
    foreach ($value as $key=>$item) {
        if (is_array($item) && ids_action_bool($item['selected'] ?? false) && is_string($key)) return $key;
    }
    foreach (['value','selected','name','id'] as $key) {
        if (isset($value[$key]) && !is_array($value[$key])) {
            $text=trim((string)$value[$key]);
            if ($text !== '') return $text;
        }
    }
    return '';
}

function ids_action_list(mixed $value): array
{
    if (!is_array($value)) {
        return array_values(array_filter(array_map('trim', preg_split('/[,\s]+/', (string)$value) ?: []), static fn(string $v): bool => $v !== ''));
    }
    $result=[];
    foreach ($value as $key=>$item) {
        if (is_array($item) && ids_action_bool($item['selected'] ?? false) && is_string($key)) $result[]=$key;
        elseif (!is_array($item) && trim((string)$item)!=='') $result[]=trim((string)$item);
    }
    return array_values(array_unique($result));
}

function ids_action_interface_keys(mixed $value): array
{
    if (!is_array($value)) return [];
    $keys=[];
    foreach ($value as $key=>$item) {
        if (is_string($key) && trim($key)!=='') $keys[]=$key;
    }
    return array_values(array_unique($keys));
}

function ids_action_normalize_homenet(string $value): string
{
    $parts=array_values(array_filter(array_map('trim', explode(',', $value)), static fn(string $v): bool => $v !== ''));
    foreach ($parts as $part) {
        if (preg_match('/^__[A-Za-z0-9_]+$/',$part)===1) continue;
        if (filter_var($part,FILTER_VALIDATE_IP)) continue;
        if (preg_match('/^([^\/]+)\/(\d{1,3})$/',$part,$match)!==1 || !filter_var($match[1],FILTER_VALIDATE_IP)) {
            throw new RuntimeException('Invalid Home network: '.$part);
        }
        $max=str_contains($match[1],':')?128:32;
        if ((int)$match[2] < 0 || (int)$match[2] > $max) throw new RuntimeException('Invalid Home network prefix: '.$part);
    }
    return implode(',', $parts);
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    $action=(string)($_POST['action'] ?? '');
    if (!in_array($action,['set_enabled','set_settings'],true)) throw new RuntimeException('Unsupported IDS action.');

    $firewallId=(int)($_POST['firewall_id'] ?? 0);
    if ($firewallId < 1) throw new RuntimeException('Invalid firewall.');

    $firewall=firewall_by_id($firewallId);
    $before=opn_raw_request($firewall,'ids/settings/get','GET',null,20);
    $general=is_array($before['ids']['general'] ?? null)?$before['ids']['general']:[];

    if ($action === 'set_enabled') {
        $enabled=filter_var($_POST['enabled'] ?? false,FILTER_VALIDATE_BOOL);
        $current=ids_action_bool($general['enabled'] ?? false);

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
        exit;
    }

    $mode=trim((string)($_POST['mode'] ?? ''));
    if (!in_array($mode,['pcap','netmap','divert'],true)) throw new RuntimeException('Invalid IDS mode.');

    $interfaces=array_values(array_unique(array_filter(array_map('trim',(array)($_POST['interfaces'] ?? [])),static fn(string $v):bool=>$v!=='')));
    if ($interfaces===[]) throw new RuntimeException('Select at least one IDS interface.');

    $availableNames=ids_action_interface_keys($general['interfaces'] ?? []);
    if ($availableNames===[]) throw new RuntimeException('OPNsense did not return logical IDS interface choices.');
    foreach ($interfaces as $interface) {
        if (!in_array($interface,$availableNames,true)) throw new RuntimeException('Unknown IDS interface: '.$interface);
    }

    $promisc=filter_var($_POST['promisc'] ?? false,FILTER_VALIDATE_BOOL);
    $homenet=ids_action_normalize_homenet(trim((string)($_POST['homenet'] ?? '')));
    if ($homenet==='') throw new RuntimeException('Home networks must not be empty.');

    $profile=trim((string)($_POST['detection_profile'] ?? ''));
    if (!in_array($profile,['','low','medium','high','custom'],true)) throw new RuntimeException('Invalid detection profile.');

    $payload=[
        'ids'=>[
            'general'=>[
                'mode'=>$mode,
                'interfaces'=>$interfaces,
                'promisc'=>$promisc?'1':'0',
                'homenet'=>$homenet,
                'detect'=>['Profile'=>$profile],
            ],
        ],
    ];

    backup_before_change($firewall,'ids-settings');
    $set=opn_raw_request($firewall,'ids/settings/set','POST',$payload,30);
    if (!ids_action_success($set)) {
        throw new RuntimeException('OPNsense rejected the IDS settings: '.json_encode($set,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
    }
    $apply=opn_raw_request($firewall,'ids/service/reconfigure','POST',[],90);
    if (!ids_action_success($apply)) {
        throw new RuntimeException('OPNsense rejected IDS reconfigure: '.json_encode($apply,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
    }

    $after=opn_raw_request($firewall,'ids/settings/get','GET',null,20);
    $verify=is_array($after['ids']['general'] ?? null)?$after['ids']['general']:[];
    $verifiedMode=ids_action_scalar($verify['mode'] ?? '');
    $verifiedInterfaces=ids_action_list($verify['interfaces'] ?? []);
    sort($verifiedInterfaces);
    $expectedInterfaces=$interfaces;
    sort($expectedInterfaces);
    $verifiedPromisc=ids_action_bool($verify['promisc'] ?? false);
    $verifiedHomenet=implode(',',ids_action_list($verify['homenet'] ?? ''));
    $verifiedProfile=ids_action_scalar($verify['detect']['Profile'] ?? '');

    if ($verifiedMode!==$mode ||
        $verifiedInterfaces!==$expectedInterfaces ||
        $verifiedPromisc!==$promisc ||
        str_replace(' ','',$verifiedHomenet)!==str_replace(' ','',$homenet) ||
        $verifiedProfile!==$profile) {
        throw new RuntimeException('Verification failed: OPNsense did not confirm the requested IDS settings.');
    }

    echo json_encode([
        'ok'=>true,
        'message'=>'IDS/IPS settings updated and verified on '.$firewall['name'].'.',
    ],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$exception->getMessage()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
