<?php

declare(strict_types=1);

$root=dirname(__DIR__);

function access_check_read(string $path): string
{
    $content=file_get_contents($path);
    if(!is_string($content)){fwrite(STDERR,"System Access regression: cannot read {$path}\n");exit(1);}
    return $content;
}
function access_check_has(string $content,string $needle,string $message): void
{
    if(!str_contains($content,$needle)){fwrite(STDERR,"System Access regression: {$message}\n");exit(1);}
}
function access_check_not(string $content,string $needle,string $message): void
{
    if(str_contains($content,$needle)){fwrite(STDERR,"System Access regression: {$message}\n");exit(1);}
}

$settings=access_check_read($root.'/app/system_access_settings.php');
foreach(['Inactivity timeout','Authentication servers','Sudo','Additional sudo group','User OTP seed'] as $label){
    access_check_has($settings,$label,'settings page missing '.$label);
}
access_check_has($settings,'system_access_settings_action.php','settings page must post to narrow write endpoint');

$settingsAction=access_check_read($root.'/app/system_access_settings_action.php');
access_check_has($settingsAction,'require_csrf();','settings write must require CSRF');
access_check_has($settingsAction,'require_configuration_unlocked(false);','settings write must require configuration unlock');
access_check_has($settingsAction,"'opnsentralagent/access/settings'",'settings write must use narrow OPNsense Access API');

$servers=access_check_read($root.'/app/system_access_servers.php');
access_check_has($servers,'Add server','servers page must expose add server');
access_check_has($servers,'system_access_server_edit.php','servers page must expose edit server');
access_check_has($servers,'system_access_server_action.php','servers page must use narrow server action endpoint');

$serverAction=access_check_read($root.'/app/system_access_server_action.php');
access_check_has($serverAction,'require_csrf();','server writes must require CSRF');
access_check_has($serverAction,'require_configuration_unlocked(false);','server writes must require configuration unlock');
access_check_has($serverAction,"'opnsentralagent/access/server'",'server save must use narrow OPNsense Access API');
access_check_has($serverAction,"'opnsentralagent/access/delete_server'",'server delete must use narrow OPNsense Access API');

$editor=access_check_read($root.'/app/system_access_server_edit.php');
foreach(['Local + TOTP','LDAP + TOTP','RADIUS','StartTLS','Stored — leave blank to keep'] as $needle){
    access_check_has($editor,$needle,'server editor missing '.$needle);
}
access_check_not($editor,'value="<?= h((string)($s[\'ldap_bindpw\']','LDAP bind password must never be rendered');
access_check_not($editor,'value="<?= h((string)($s[\'radius_secret\']','RADIUS secret must never be rendered');

$helper=access_check_read($root.'/app/inc/system_access_management.php');
access_check_has($helper,"'opnsentralagent/access/get'",'management reads must prefer narrow OPNsense Access API');
access_check_has($helper,'OPNsense backup API (read-only)','management reads must retain safe backup fallback');
access_check_has($helper,"'writable'=>false",'backup fallback must remain read-only');

$inventory=access_check_read($root.'/app/inc/system_access_inventory.php');
access_check_has($inventory,'access_parse_settings','backup inventory must parse Access settings');
access_check_has($inventory,'access_parse_authservers','backup inventory must parse authentication servers');
access_check_has($inventory,"['ldap_bindpw','radius_secret']", 'backup parser must redact stored authentication secrets');

$controller=access_check_read($root.'/opnsense-plugin/opnsentral-agent/src/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php');
foreach([
    '$this->throwReadOnly()',
    "'autologout'",
    "'authmode'",
    "'sudo_allow_wheel'",
    "'sudo_allow_group'",
    "'user_allow_gen_token'",
    "['totp', 'ldap', 'ldap-totp', 'radius']",
    '$node->addChild(\'refid\'',
    "['ldap_bindpw', 'radius_secret']",
    "configdRun('service restart login')"
] as $needle){
    access_check_has($controller,$needle,'Access controller missing safety/contract marker: '.$needle);
}
access_check_has($controller,'$row[$key . \'_set\']', 'Access API must expose only secret-presence state');
access_check_has($controller,"if (in_array(\$key, ['ldap_bindpw', 'radius_secret'], true)) {",'Access API must branch on secret fields before generic serialization');
access_check_has($controller,'$row[$key . \'_set\'] = trim((string)$value) !== \'\';','Access API must expose only whether a stored secret exists');
access_check_has($controller,'continue;','secret handling must stop before generic field serialization');

$installer=access_check_read($root.'/app/agent/install-plugin.sh');
access_check_has($installer,'fetch_plugin_file access_controller','plugin installer must deploy Access controller');
access_check_has($installer,'php -l /usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php','plugin installer must lint Access controller');
access_check_has($installer,'System Access management API was not installed correctly','plugin installer must verify Access controller');

$header=access_check_read($root.'/app/inc/header.php');
access_check_has($header,'href="/system_access_settings.php"><span>Settings</span>','System Access settings must be in navigation');
access_check_has($header,'href="/system_access_servers.php"><span>Servers</span>','System Access servers must be in navigation');

echo "System Access management checks passed.\n";
