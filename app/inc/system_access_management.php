<?php

declare(strict_types=1);

require_once __DIR__ . '/opnsense.php';
require_once __DIR__ . '/system_access_inventory.php';

function access_management_state(array $firewall): array
{
    try {
        $value=opn_raw_request($firewall,'opnsentralagent/access/get','GET',null,20);
        return [
            'ok'=>true,
            'writable'=>true,
            'settings'=>is_array($value['settings']??null)?$value['settings']:[],
            'groups'=>is_array($value['groups']??null)?$value['groups']:[],
            'servers'=>is_array($value['servers']??null)?$value['servers']:[],
            'source'=>'opnSentral Access API',
            'error'=>'',
        ];
    } catch (Throwable $apiError) {
        try {
            $fleet=access_load_fleet_inventory([$firewall]);
            $entry=$fleet[(int)$firewall['id']]??null;
            if (is_array($entry) && ($entry['ok']??false)===true) {
                return [
                    'ok'=>true,
                    'writable'=>false,
                    'settings'=>is_array($entry['settings']??null)?$entry['settings']:[],
                    'groups'=>array_keys(is_array($entry['groups']??null)?$entry['groups']:[]),
                    'servers'=>is_array($entry['authservers']??null)?$entry['authservers']:[],
                    'source'=>'OPNsense backup API (read-only)',
                    'error'=>'System Access write API unavailable: '.$apiError->getMessage(),
                ];
            }
        } catch (Throwable $ignored) {
        }
        return [
            'ok'=>false,'writable'=>false,'settings'=>[],'groups'=>[],'servers'=>[],
            'source'=>'','error'=>$apiError->getMessage(),
        ];
    }
}

function access_management_server_names(array $servers): array
{
    $names=[];
    foreach ($servers as $server) {
        if (!is_array($server)) continue;
        $name=trim((string)($server['name']??''));
        if ($name!=='') $names[]=$name;
    }
    return array_values(array_unique($names));
}
