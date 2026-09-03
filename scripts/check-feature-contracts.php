<?php

declare(strict_types=1);

$root = dirname(__DIR__);

function read_required(string $path): string
{
    if (!is_file($path)) {
        fwrite(STDERR, "Missing required file: {$path}\n");
        exit(1);
    }
    $content = file_get_contents($path);
    if (!is_string($content)) {
        fwrite(STDERR, "Could not read: {$path}\n");
        exit(1);
    }
    return $content;
}

function require_contains(string $content, string $needle, string $message): void
{
    if (!str_contains($content, $needle)) {
        fwrite(STDERR, "Feature contract failed: {$message}\n");
        exit(1);
    }
}

function require_not_contains(string $content, string $needle, string $message): void
{
    if (str_contains($content, $needle)) {
        fwrite(STDERR, "Feature contract failed: {$message}\n");
        exit(1);
    }
}

$fleet = read_required($root . '/app/fleet_settings_action.php');
require_contains($fleet, 'http_response_code(503)', 'unsupported General/Advanced fleet writes must fail closed');
require_not_contains($fleet, 'INSERT INTO agent_jobs', 'fleet settings endpoint must not queue jobs while agent writes are disabled');
require_not_contains($fleet, 'backup_before_change', 'disabled fleet settings endpoint must not create misleading backups');

$ssh = read_required($root . '/app/ssh_access_action.php');
require_contains($ssh, 'temporarily disabled because agent 0.1.16 does not implement', 'Managed SSH repair must fail closed until the agent implements the job');
require_not_contains($ssh, 'ssh_access_ensure_objects(', 'Managed SSH repair must not change firewall objects before a supported agent job exists');
require_not_contains($ssh, "'ensure_ssh_access'", 'Managed SSH repair must not queue unsupported ensure_ssh_access jobs');
require_not_contains($ssh, "'ssh_access_status'", 'legacy SSH status must not queue unsupported ssh_access_status jobs');

$ids = read_required($root . '/app/intrusion_detection_action.php');
require_contains($ids, 'http_response_code(503)', 'unverified IDS writes must remain fail-closed');
require_not_contains($ids, 'opn_raw_request(', 'disabled IDS action endpoint must not call OPNsense write APIs');

$firmware = read_required($root . '/app/firewall_action.php');
require_contains(
    $firmware,
    '$statusValue = opn_request($firewall, \'core/firmware/status\', \'POST\', [], 120);',
    'firmware update/upgrade must run a fresh OPNsense probe immediately before the write'
);

$agent = read_required($root . '/app/agent/opnsentral-agent');
require_contains(
    $agent,
    "in_array(\$type,['set_administration_settings','set_general_settings','set_firewall_advanced_settings'],true)",
    'agent safety block for risky fleet writes must remain present'
);

$notificationHelper = read_required($root . '/app/inc/firewall_notifications.php');
require_contains($notificationHelper, 'notifications_enabled INTEGER NOT NULL DEFAULT 1', 'per-firewall notifications must default to enabled for existing and new managed firewalls');
require_contains($notificationHelper, "DELETE FROM alert_states WHERE state_key = ? OR state_key LIKE ?", 'toggling firewall notifications must reset stale alert runtime state');

$alerts = read_required($root . '/app/inc/alerts.php');
require_contains($alerts, "if ((int)(\$firewall['notifications_enabled'] ?? 1) !== 1)", 'alert worker must skip firewalls with notifications disabled');

$notificationAction = read_required($root . '/app/firewall_notifications_action.php');
require_contains($notificationAction, 'require_csrf();', 'per-firewall notification changes must require CSRF protection');
require_contains($notificationAction, 'firewall_notifications_set_enabled($id, $enabled);', 'per-firewall notification API must use the centralized state helper');

$cardActions = read_required($root . '/app/assets/firewall-card-actions.js');
require_contains($cardActions, "details.textContent='Manage'", 'Dashboard Details action must be relabeled Manage');
require_contains($cardActions, "edit.textContent='Connection settings'", 'Dashboard Edit action must be relabeled Connection settings');
require_contains($cardActions, "remove.textContent='Remove from opnSentral'", 'ambiguous Delete entry label must be removed');
require_contains($cardActions, "Notifications: ", 'Dashboard must expose per-firewall notification state');
require_contains($cardActions, '/ssh_lockout.php?firewall_id=', 'per-firewall Manage page must expose SSH/WebGUI lockout management');

$installer = read_required($root . '/app/agent/install-plugin.sh');
require_contains($installer, 'fetch_plugin_file syshook', 'agent installer must deploy the OPNsense startup recovery hook');
require_contains($installer, '/usr/local/etc/rc.syshook.d/start/50-opnsentral-agent', 'agent installer must verify the startup recovery hook');
require_not_contains($installer, 'fetch_plugin_file hardware_controller', 'agent installer must not deploy a custom hardware API controller');
require_not_contains($installer, '/api/opnsentralagent/hardware/get', 'agent installer must not advertise a custom hardware API endpoint');
require_contains($installer, 'fetch_plugin_file lockout_script', 'agent installer must deploy the narrow sshlockout helper');
require_contains($installer, 'fetch_plugin_file lockout_controller', 'agent installer must deploy the narrow sshlockout API');
require_contains($installer, 'fetch_plugin_file actions', 'agent installer must deploy sshlockout configd actions');
require_contains($installer, 'service configd restart', 'installer must reload configd after installing new action definitions');
require_contains($installer, 'opnsentralagent sshlockout.status', 'installer must verify sshlockout configd registration');

$pluginFiles = read_required($root . '/app/agent/plugin_file.php');
require_not_contains($pluginFiles, "'hardware_controller'", 'plugin file server must not ship a custom hardware API controller');
require_contains($pluginFiles, "'lockout_script'", 'plugin file server must ship the sshlockout helper');
require_contains($pluginFiles, "'lockout_controller'", 'plugin file server must ship the sshlockout controller');
require_contains($pluginFiles, "'actions'", 'plugin file server must ship sshlockout configd actions');

$syshook = read_required($root . '/opnsense-plugin/opnsentral-agent/src/etc/rc.syshook.d/start/50-opnsentral-agent');
require_contains($syshook, '$SERVICE opnsentral_agent', 'startup recovery hook must manage the opnSentral agent service');
require_contains($syshook, 'onestatus', 'startup recovery hook must avoid duplicate agent processes');
require_contains($syshook, 'sshlockout.php', 'startup recovery hook must reapply trusted lockout hosts');
require_contains($syshook, 'sync', 'startup recovery hook must synchronize trusted lockout hosts');

$lockoutHelper = read_required($root . '/opnsense-plugin/opnsentral-agent/src/opnsense/scripts/OPNsense/OpnSentralAgent/sshlockout.php');
require_contains($lockoutHelper, "const TABLE_NAME = 'sshlockout'", 'trusted-host helper must only operate on the OPNsense sshlockout table');
require_contains($lockoutHelper, "const TRUST_FILE = TRUST_DIR . '/ssh-trusted.txt'", 'trusted hosts must have persistent local state under /conf');
require_contains($lockoutHelper, 'FILTER_VALIDATE_IP', 'trusted hosts must be validated as IP addresses');
require_contains($lockoutHelper, "str_contains(\$value, '/')", 'trusted hosts must reject CIDR/network entries');
require_contains($lockoutHelper, "'-T', 'add', '!' . \$ip", 'trusted hosts must use exact negated PF table entries');
require_contains($lockoutHelper, "'-T', 'delete', \$ip", 'trusting a host must be able to remove its positive lockout entry');
require_contains($lockoutHelper, "trusted_file_write(\$before)", 'trusted-host writes must roll persistent state back on verification failure');
require_contains($lockoutHelper, 'trusted_active', 'trusted-host writes must use read-back verification');
require_not_contains($lockoutHelper, 'shell_exec(', 'sshlockout helper must not build shell command strings');

$lockoutController = read_required($root . '/opnsense-plugin/opnsentral-agent/src/opnsense/mvc/app/controllers/OPNsense/OpnSentralAgent/Api/LockoutController.php');
require_contains($lockoutController, 'configdpRun', 'trusted-host writes must cross the OPNsense configd privilege boundary');
require_contains($lockoutController, '$this->throwReadOnly()', 'trusted-host API writes must respect OPNsense read-only API credentials');
require_contains($lockoutController, 'FILTER_VALIDATE_IP', 'trusted-host API must independently validate IP addresses');

$lockoutPage = read_required($root . '/app/ssh_lockout.php');
require_contains($lockoutPage, 'firewall/alias_util/list/sshlockout', 'blocked-IP view must use the standard OPNsense alias table API');
require_contains($lockoutPage, 'firewall/alias_util/delete/sshlockout', 'blocked-IP removal must use the standard OPNsense alias table API');
require_contains($lockoutPage, 'opnsentralagent/lockout/trust', 'persistent whitelist must use the narrow opnSentral trusted-host API');
require_contains($lockoutPage, 'opnsentralagent/lockout/untrust', 'persistent whitelist removal must use the narrow opnSentral trusted-host API');
require_contains($lockoutPage, 'Read-back verification', 'runtime lockout changes must be verified');
require_contains($lockoutPage, 'require_csrf();', 'lockout writes must require CSRF protection');

$hardwareEndpoint = read_required($root . '/app/firewall_hardware.php');
require_contains($hardwareEndpoint, "dmidecode/service/get", 'DMI inventory must use the official os-dmidecode API');
require_contains($hardwareEndpoint, "diagnostics/cpu_usage/getcputype", 'CPU inventory must use the OPNsense core CPU API');
require_contains($hardwareEndpoint, "diagnostics/system/system_resources", 'RAM inventory must use the OPNsense core resources API');
require_contains($hardwareEndpoint, "smart/service/list/details", 'physical disk inventory must use the official os-smart API');
require_not_contains($hardwareEndpoint, "opnsentralagent/hardware/get", 'hardware endpoint must not call a custom opnSentral DMI API');
require_not_contains($hardwareEndpoint, "diagnostics/system/system_disk", 'filesystem inventory must never be presented as physical disk hardware');

$hardwareCard = read_required($root . '/app/assets/firewall-hardware-card.js');
foreach (['Hardware','CPU','RAM','Storage'] as $label) {
    require_contains($hardwareCard, $label, 'Dashboard hardware card must show ' . $label);
}
require_contains($hardwareCard, 'Install os-dmidecode', 'Dashboard must clearly identify a missing os-dmidecode dependency');
require_contains($hardwareCard, 'Install os-smart', 'Dashboard must clearly identify a missing os-smart dependency for physical disks');

$dashboardStatus = read_required($root . '/app/firewall_status.php');
require_contains($dashboardStatus, 'diagnostics/system/system_information', 'Dashboard must retrieve the running OPNsense version independently of firmware probe success');
require_contains($dashboardStatus, "array_key_exists('raw', \$value)", 'Dashboard status must reject non-JSON/HTML API responses instead of treating them as online');
require_contains($dashboardStatus, "\$value['version'] = \$version", 'Dashboard system payload must carry the independently detected OPNsense version');

$statusIndicator = read_required($root . '/app/assets/system-status-indicator.js');
require_contains($statusIndicator, "return 'unavailable'", 'empty or unknown OPNsense health status must never be displayed green');
require_contains($statusIndicator, 'dashboardCardIsOffline', 'system-health LED must respect the Dashboard connectivity state');
require_contains($statusIndicator, "if(value==='NOTICE'||value==='YELLOW'||value==='1') return 'notice'", 'NOTICE must remain visually distinct from WARNING');
require_contains($statusIndicator, 'metadata.system.status is OPNsense\'s authoritative aggregate state', 'system-health severity must use OPNsense aggregate status instead of a first-subsystem override');

fwrite(STDOUT, "Feature contract checks passed.\n");
