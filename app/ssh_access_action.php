<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/ssh_access.php';

require_login();
require_csrf();

$firewallId = (int) ($_POST['firewall_id'] ?? 0);
$action = trim((string) ($_POST['action'] ?? ''));

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('POST required.');
    }
    if ($firewallId <= 0) {
        throw new RuntimeException('Select an OPNsense firewall.');
    }
    if (!in_array($action, ['check', 'ensure'], true)) {
        throw new RuntimeException('Invalid SSH access action.');
    }

    $firewall = firewall_by_id($firewallId);
    $agent = ssh_access_agent($firewallId);
    if ($agent === null) {
        throw new RuntimeException('No enabled opnSentral agent is associated with this firewall.');
    }
    $agentVersion = trim((string) ($agent['last_version'] ?? ''));
    if (!ssh_access_agent_ready($agent)) {
        throw new RuntimeException(
            'Agent ' . SSH_ACCESS_AGENT_MIN_VERSION . ' or newer is required for SSH management; current: ' .
            ($agentVersion !== '' ? $agentVersion : 'unknown') . '.'
        );
    }

    $source = ssh_access_public_source();
    if ($action === 'ensure') {
        require_configuration_unlocked(false);
        backup_before_change($firewall, 'managed-ssh-access');
        $objects = ssh_access_ensure_objects($firewall, $source);
        if (($objects['ok'] ?? false) !== true) {
            throw new RuntimeException('Managed SSH alias/rule verification failed.');
        }
        $jobId = ssh_access_queue_job($agent, 'ensure_ssh_access', [
            'port' => 22,
            'sudo_mode' => '1',
            'sudo_group' => 'admins',
        ]);
        $_SESSION['ssh_access_result'] = [
            'ok' => true,
            'message' => 'Managed alias and firewall rule verified. SSH service repair job #' . $jobId . ' queued.',
        ];
    } else {
        $objects = ssh_access_objects_status($firewall, $source);
        $jobId = ssh_access_queue_job($agent, 'ssh_access_status');
        $_SESSION['ssh_access_result'] = [
            'ok' => true,
            'message' => 'Object status checked. Remote SSH status job #' . $jobId . ' queued.',
            'objects' => $objects,
        ];
    }
} catch (Throwable $exception) {
    $_SESSION['ssh_access_result'] = [
        'ok' => false,
        'message' => $exception->getMessage(),
    ];
}

header('Location: /ssh_access.php?firewall_id=' . $firewallId);
exit;
