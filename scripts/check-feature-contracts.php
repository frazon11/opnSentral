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

$installer = read_required($root . '/app/agent/install-plugin.sh');
require_contains($installer, 'fetch_plugin_file syshook', 'agent installer must deploy the OPNsense startup recovery hook');
require_contains($installer, '/usr/local/etc/rc.syshook.d/start/50-opnsentral-agent', 'agent installer must verify the startup recovery hook');
require_not_contains($installer, 'fetch_plugin_file hardware_controller', 'agent installer must not deploy a custom hardware API controller');
require_not_contains($installer, '/api/opnsentralagent/hardware/get', 'agent installer must not advertise a custom hardware API endpoint');
$pluginFiles = read_required($root . '/app/agent/plugin_file.php');
require_not_contains($pluginFiles, "'hardware_controller'", 'plugin file server must not ship a custom hardware API controller');

$syshook = read_required($root . '/opnsense-plugin/opnsentral-agent/src/etc/rc.syshook.d/start/50-opnsentral-agent');
require_contains($syshook, '$SERVICE opnsentral_agent', 'startup recovery hook must manage the opnSentral agent service');
require_contains($syshook, 'onestatus', 'startup recovery hook must avoid duplicate agent processes');

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

fwrite(STDOUT, "Feature contract checks passed.\n");
