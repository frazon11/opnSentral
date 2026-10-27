<?php

declare(strict_types=1);

$root = dirname(__DIR__);

function sysacc_read(string $path): string
{
    $content = @file_get_contents($path);
    if (!is_string($content)) {
        fwrite(STDERR, "System Access regression: cannot read {$path}\n");
        exit(1);
    }
    return $content;
}

function sysacc_has(string $content, string $needle, string $message): void
{
    if (!str_contains($content, $needle)) {
        fwrite(STDERR, "System Access regression: {$message}\n");
        exit(1);
    }
}

function sysacc_not(string $content, string $needle, string $message): void
{
    if (str_contains($content, $needle)) {
        fwrite(STDERR, "System Access regression: {$message}\n");
        exit(1);
    }
}

$controller = sysacc_read($root . '/opnsense-plugin/opnsentral-agent/src/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php');
foreach ([
    'class AccessController extends ApiControllerBase',
    'public function snapshotAction()',
    'public function setAdministrationAction()',
    'public function setServerAction($index)',
    'Config::getInstance()->lock();',
    '$this->throwReadOnly();',
    'Config::getInstance()->save();',
    "'autologout'",
    "'authmode'",
    "'sudo_allow_wheel'",
    "'sudo_allow_group'",
    "'user_allow_gen_token'",
    "'otpLength'",
    "'timeWindow'",
    "'graceperiod'",
    "'passwordFirst'",
    "'ldap-totp'",
    "'radius'",
    "'has_ldap_bindpw'",
    "'has_radius_secret'",
    "configdRun('service restart login')",
] as $needle) {
    sysacc_has($controller, $needle, 'bridge controller missing ' . $needle);
}
sysacc_not($controller, "'ldap_bindpw' =>", 'bridge snapshot must not expose LDAP bind passwords');
sysacc_not($controller, "'radius_secret' =>", 'bridge snapshot must not expose RADIUS shared secrets');

$action = sysacc_read($root . '/app/system_access_settings_action.php');
foreach ([
    'require_csrf();',
    'require_configuration_unlocked();',
    'backup_before_change(',
    "'opnsentralagent/access/setAdministration'",
    "'opnsentralagent/access/setServer/'",
    'Read-back verification failed',
    'access_action_expect_scalar',
    'access_action_expect_bool',
    'access_action_expect_csv',
    'has_ldap_bindpw',
    'has_radius_secret',
] as $needle) {
    sysacc_has($action, $needle, 'write handler missing ' . $needle);
}
sysacc_not($action, 'INSERT INTO agent_jobs', 'System Access writes must not use agent jobs');

$servers = sysacc_read($root . '/app/system_access_servers.php');
foreach ([
    'System → Access → Servers',
    "'core/backup/download/this'",
    "'opnsentralagent/access/snapshot'",
    'Write bridge available',
    'Local + Timebased One Time Password',
    'LDAP + Timebased One Time Password',
    'RADIUS',
    'Stored — leave blank to keep',
] as $needle) {
    sysacc_has($servers, $needle, 'Servers page missing ' . $needle);
}
sysacc_not($servers, 'agent_jobs', 'Servers page must not depend on agent jobs');

$admin = sysacc_read($root . '/app/system_administration.php');
foreach ([
    'Inactivity timeout',
    'name="authmode[]"',
    'name="sudo_allow_wheel"',
    'name="sudo_allow_group"',
    'name="user_allow_gen_token[]"',
    '/system_access_servers.php?firewall_id=',
    "'opnsentralagent/access/snapshot'",
] as $needle) {
    sysacc_has($admin, $needle, 'Administration page missing ' . $needle);
}

$header = sysacc_read($root . '/app/inc/header.php');
sysacc_has($header, 'href="/system_access_servers.php"><span>Servers</span></a>', 'System → Access → Servers navigation missing');
sysacc_has($header, 'href="/system_administration.php"><span>Administration</span></a>', 'Administration navigation must open the per-firewall editor');

$pluginFiles = sysacc_read($root . '/app/agent/plugin_file.php');
sysacc_has($pluginFiles, "'access_controller'", 'plugin file endpoint must serve the System Access controller');

$bridgeInstaller = sysacc_read($root . '/app/system-access-bridge-install.sh');
foreach ([
    'access_controller',
    '/usr/local/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/AccessController.php',
    '/api/opnsentralagent/access/snapshot',
] as $needle) {
    sysacc_has($bridgeInstaller, $needle, 'standalone bridge installer missing ' . $needle);
}
sysacc_not($bridgeInstaller, 'opnsentral_agent start', 'standalone bridge installer must not start the agent worker');
sysacc_not($bridgeInstaller, 'register', 'standalone bridge installer must not register an agent');

fwrite(STDOUT, "System Access settings checks passed.\n");
