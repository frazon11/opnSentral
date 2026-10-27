<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();
require_csrf();
require_configuration_unlocked(false);

try {
    $firewall=firewall_by_id((int)($_POST['firewall_id']??0));
    $action=(string)($_POST['action']??'');
    if($action==='delete'){
        $result=opn_raw_request($firewall,'opnsentralagent/access/delete_server','POST',['index'=>(int)($_POST['index']??-1)],30);
        if(($result['result']??'')!=='deleted') throw new RuntimeException('OPNsense did not confirm server deletion.');
        $_SESSION['system_access_message']=['ok'=>true,'text'=>'Authentication server deleted on '.(string)$firewall['name'].'.'];
    } elseif($action==='save') {
        $payload=[];
        foreach([
            'index','name','type','otpLength','timeWindow','graceperiod','passwordFirst',
            'host','ldap_port','ldap_urltype','ldap_protver','ldap_scope','ldap_basedn','ldap_authcn','ldap_extended_query','ldap_attr_user','ldap_binddn','ldap_bindpw','ldap_read_properties',
            'radius_auth_port','radius_acct_port','radius_secret','radius_timeout','radius_stationid'
        ] as $field) $payload[$field]=$_POST[$field]??'';
        $result=opn_raw_request($firewall,'opnsentralagent/access/server','POST',$payload,30);
        if(($result['result']??'')!=='saved') throw new RuntimeException('OPNsense did not confirm the authentication-server write.');
        $_SESSION['system_access_message']=['ok'=>true,'text'=>'Authentication server saved on '.(string)$firewall['name'].'.'];
    } else {
        throw new RuntimeException('Unsupported System Access server action.');
    }
} catch(Throwable $e) {
    $_SESSION['system_access_message']=['ok'=>false,'text'=>$e->getMessage()];
}
header('Location: /system_access_servers.php');
