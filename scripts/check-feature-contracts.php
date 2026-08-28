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
    "$statusValue = opn_request($firewall, 'core/firmware/status', 'POST', [], 120);",
    'firmware update/upgrade must run a fresh OPNsense probe immediately before the write'
);

$agent = read_required($root . '/app/agent/opnsentral-agent');
require_contains($agent, "in_array($type,['set_administration_settings','set_general_settings','set_firewall_advanced_settings'],true)", 'agent safety block for risky fleet writes must remain present');

fwrite(STDOUT, "Feature contract checks passed.\n");
