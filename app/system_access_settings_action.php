<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();
require_csrf();
require_configuration_unlocked(false);

try {
    $firewall=firewall_by_id((int)($_POST['firewall_id']??0));
    $payload=[
        'autologout'=>trim((string)($_POST['autologout']??'')),
        'authmode'=>array_values(array_filter(array_map('trim',(array)($_POST['authmode']??[])),static fn($v)=>$v!=='')),
        'sudo_allow_wheel'=>trim((string)($_POST['sudo_allow_wheel']??'')),
        'sudo_allow_group'=>trim((string)($_POST['sudo_allow_group']??'')),
        'user_allow_gen_token'=>array_values(array_filter(array_map('trim',(array)($_POST['user_allow_gen_token']??[])),static fn($v)=>$v!=='')),
    ];
    $result=opn_raw_request($firewall,'opnsentralagent/access/settings','POST',$payload,30);
    if (($result['result']??'')!=='saved') throw new RuntimeException('OPNsense did not confirm the settings write.');
    $_SESSION['system_access_message']=['ok'=>true,'text'=>'Saved System Access settings on '.(string)$firewall['name'].'.'];
} catch(Throwable $e) {
    $_SESSION['system_access_message']=['ok'=>false,'text'=>$e->getMessage()];
}
header('Location: /system_access_settings.php');
