<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/webssh.php';
require_login();
require_csrf();
require_configuration_unlocked(false);

try {
    $firewall=firewall_by_id((int)($_POST['firewall_id']??0));
    if (!webssh_credentials_configured($firewall)) {
        throw new RuntimeException('Stored WebSSH credentials are required. Configure Managed SSH Access for this firewall first.');
    }
    $forwardedProto=trim(explode(',',(string)($_SERVER['HTTP_X_FORWARDED_PROTO']??''))[0]??'');
    $scheme=$forwardedProto!==''?strtolower($forwardedProto):((((string)($_SERVER['HTTPS']??''))!==''&&($_SERVER['HTTPS']??'off')!=='off')?'https':'http');
    $forwardedHost=trim(explode(',',(string)($_SERVER['HTTP_X_FORWARDED_HOST']??''))[0]??'');
    $host=$forwardedHost!==''?$forwardedHost:trim((string)($_SERVER['HTTP_HOST']??''));
    $publicBase=$host!==''?$scheme.'://'.$host:'';
    if(!str_starts_with(strtolower($publicBase),'https://')) {
        throw new RuntimeException('Open opnSentral through its public HTTPS URL before installing System Access support.');
    }
    webssh_install_access_controller($firewall,$publicBase);

    $check=opn_raw_request($firewall,'opnsentralagent/access/get','GET',null,20);
    if(!isset($check['settings']) || !isset($check['servers'])) {
        throw new RuntimeException('Access API installation completed, but read-back verification failed.');
    }
    $_SESSION['system_access_message']=['ok'=>true,'text'=>'System Access editing support installed and verified on '.(string)$firewall['name'].'.'];
} catch(Throwable $e) {
    $_SESSION['system_access_message']=['ok'=>false,'text'=>$e->getMessage()];
}
$referer=(string)($_SERVER['HTTP_REFERER']??'');
$target=str_contains($referer,'system_access_servers.php')?'/system_access_servers.php':'/system_access_settings.php';
header('Location: '.$target);
