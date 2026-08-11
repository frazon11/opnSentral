<?php

declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('html_errors', '0');
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/wireguard_create.php';
require_login();
require_csrf();
require_configuration_unlocked();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function request_bool(string $name): bool
{
    return isset($_POST[$name]) && filter_var($_POST[$name], FILTER_VALIDATE_BOOL);
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new RuntimeException('POST required.');
    $aId=(int)($_POST['site_a_id']??0); $bId=(int)($_POST['site_b_id']??0);
    if($aId<1||$bId<1||$aId===$bId) throw new InvalidArgumentException('Select two different managed firewalls.');
    $a=firewall_by_id($aId); $b=firewall_by_id($bId);
    $aLan=wg_create_validate_network((string)($_POST['site_a_lan']??''));
    $bLan=wg_create_validate_network((string)($_POST['site_b_lan']??''));
    $aTunnel=wg_create_validate_network((string)($_POST['site_a_tunnel']??''));
    $bTunnel=wg_create_validate_network((string)($_POST['site_b_tunnel']??''));
    if($aLan===$bLan||$aTunnel===$bTunnel) throw new InvalidArgumentException('LAN and tunnel addresses must be distinct.');
    $aEndpoint=wg_create_validate_host((string)($_POST['site_a_endpoint']??''));
    $bEndpoint=wg_create_validate_host((string)($_POST['site_b_endpoint']??''));
    $aPort=(int)($_POST['site_a_port']??0); $bPort=(int)($_POST['site_b_port']??0); $keepalive=(int)($_POST['keepalive']??25);
    foreach([$aPort,$bPort] as $port) if($port<1||$port>65535) throw new InvalidArgumentException('WireGuard ports must be between 1 and 65535.');
    if($keepalive<0||$keepalive>65535) throw new InvalidArgumentException('Keepalive must be between 0 and 65535.');
    $aName=wg_create_validate_name((string)($_POST['site_a_name']??''));
    $bName=wg_create_validate_name((string)($_POST['site_b_name']??''));
    $aWan=wg_create_validate_name((string)($_POST['site_a_wan_interface']??'wan'));
    $bWan=wg_create_validate_name((string)($_POST['site_b_wan_interface']??'wan'));
    $aLanIf=wg_create_validate_name((string)($_POST['site_a_lan_interface']??'lan'));
    $bLanIf=wg_create_validate_name((string)($_POST['site_b_lan_interface']??'lan'));
    $wgIf=wg_create_validate_name((string)($_POST['wireguard_interface']??'wireguard'));
    $wanRules=request_bool('create_wan_rules'); $trafficRules=request_bool('create_traffic_rules');
    $tunnelId='WG-'.strtoupper(bin2hex(random_bytes(3))); $marker='managed by opnCentral ['.$tunnelId.']';

    backup_before_change($a,'wireguard-create-'.strtolower($tunnelId));
    backup_before_change($b,'wireguard-create-'.strtolower($tunnelId));

    $created=['a_server'=>null,'b_server'=>null,'a_client'=>null,'b_client'=>null,'a_rules'=>[],'b_rules'=>[]];
    try {
        $keysA=wg_create_keypair($a); $keysB=wg_create_keypair($b);
        $created['a_server']=wg_create_add_server($a,$aName,$keysA,$aPort,$aTunnel);
        $created['b_server']=wg_create_add_server($b,$bName,$keysB,$bPort,$bTunnel);
        $aTunnelHost=explode('/',$aTunnel,2)[0].'/32'; $bTunnelHost=explode('/',$bTunnel,2)[0].'/32';
        $created['a_client']=wg_create_add_client($a,$bName,$keysB['public'],$bTunnelHost,$bLan,$bEndpoint,$bPort,$keepalive);
        $created['b_client']=wg_create_add_client($b,$aName,$keysA['public'],$aTunnelHost,$aLan,$aEndpoint,$aPort,$keepalive);
        wg_create_attach_peer($a,$created['a_server'],$created['a_client']);
        wg_create_attach_peer($b,$created['b_server'],$created['b_client']);

        if($wanRules||$trafficRules){
            $catA=wg_create_category_uuid($a); $catB=wg_create_category_uuid($b);
            if($wanRules){
                $created['a_rules'][]=wg_create_filter_rule($a,$aWan,'UDP','any','wanip',(string)$aPort,$catA,'Allow WireGuard from '.$b['name'].' - '.$marker);
                $created['b_rules'][]=wg_create_filter_rule($b,$bWan,'UDP','any','wanip',(string)$bPort,$catB,'Allow WireGuard from '.$a['name'].' - '.$marker);
            }
            if($trafficRules){
                $created['a_rules'][]=wg_create_filter_rule($a,$aLanIf,'any',$aLan,$bLan,'',$catA,'Allow '.$a['name'].' LAN to '.$b['name'].' - '.$marker);
                $created['b_rules'][]=wg_create_filter_rule($b,$bLanIf,'any',$bLan,$aLan,'',$catB,'Allow '.$b['name'].' LAN to '.$a['name'].' - '.$marker);
                $created['a_rules'][]=wg_create_filter_rule($a,$wgIf,'any',$bLan,$aLan,'',$catA,'Allow '.$b['name'].' to '.$a['name'].' LAN - '.$marker);
                $created['b_rules'][]=wg_create_filter_rule($b,$wgIf,'any',$aLan,$bLan,'',$catB,'Allow '.$a['name'].' to '.$b['name'].' LAN - '.$marker);
            }
            wg_create_apply_rules($a); wg_create_apply_rules($b);
        }
        wg_create_enable_pair($a,$created['a_server'],$created['a_client']);
        wg_create_enable_pair($b,$created['b_server'],$created['b_client']);
        invalidate_wireguard_inventory_cache();
        echo json_encode(['ok'=>true,'tunnel_id'=>$tunnelId,'site_a'=>(string)$a['name'],'site_b'=>(string)$b['name'],'message'=>'Dedicated instances, reciprocal peers and requested firewall rules were created. Check handshake status in Managed WireGuard.'],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
    } catch(Throwable $e){
        foreach(array_reverse($created['a_rules']) as $uuid) wg_create_delete_rule($a,$uuid);
        foreach(array_reverse($created['b_rules']) as $uuid) wg_create_delete_rule($b,$uuid);
        try{if($created['a_rules'])wg_create_apply_rules($a);}catch(Throwable){}
        try{if($created['b_rules'])wg_create_apply_rules($b);}catch(Throwable){}
        wg_create_delete_pair($a,$created['a_client'],$created['a_server']);
        wg_create_delete_pair($b,$created['b_client'],$created['b_server']);
        invalidate_wireguard_inventory_cache();
        throw new RuntimeException('Tunnel creation failed and rollback was attempted: '.$e->getMessage());
    }
} catch(Throwable $e){
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>$e->getMessage()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
}
