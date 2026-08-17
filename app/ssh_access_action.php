<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/ssh_access.php';

require_login();
require_csrf();

$action = trim((string) ($_POST['action'] ?? ''));

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('POST required.');
    }
    if (!in_array($action, ['check', 'ensure'], true)) {
        throw new RuntimeException('Invalid SSH access action.');
    }

    $firewallIds = [];
    if (isset($_POST['firewall_ids']) && is_array($_POST['firewall_ids'])) {
        foreach ($_POST['firewall_ids'] as $value) {
            $id = (int) $value;
            if ($id > 0) $firewallIds[$id] = $id;
        }
    }
    $legacyId = (int) ($_POST['firewall_id'] ?? 0);
    if ($legacyId > 0) $firewallIds[$legacyId] = $legacyId;
    $firewallIds = array_values($firewallIds);

    if ($firewallIds === []) {
        throw new RuntimeException('Select at least one OPNsense firewall.');
    }
    if ($action === 'check' && count($firewallIds) !== 1) {
        throw new RuntimeException('Status checks are available for one firewall at a time.');
    }

    $source = ssh_access_public_source();
    $results = [];
    $success = 0;
    $failed = 0;

    foreach ($firewallIds as $firewallId) {
        $firewallName = 'Firewall #' . $firewallId;
        try {
            $firewall = firewall_by_id($firewallId);
            $firewallName = (string) $firewall['name'];
            $agent = ssh_access_agent($firewallId);
            if ($agent === null) {
                throw new RuntimeException('No enabled opnSentral agent is associated with this firewall.');
            }
            $agentVersion = trim((string) ($agent['last_version'] ?? ''));
            if (!ssh_access_agent_ready($agent)) {
                throw new RuntimeException(
                    'Agent ' . SSH_ACCESS_AGENT_MIN_VERSION . ' or newer is required; current: ' .
                    ($agentVersion !== '' ? $agentVersion : 'unknown') . '.'
                );
            }

            if ($action === 'ensure') {
                require_configuration_unlocked(false);
                $backup = backup_before_change($firewall, 'managed-ssh-access');
                $objects = ssh_access_ensure_objects($firewall, $source);
                if (($objects['ok'] ?? false) !== true) {
                    throw new RuntimeException('Managed SSH alias/rule verification failed.');
                }
                $jobId = ssh_access_queue_job($agent, 'ensure_ssh_access', [
                    'port' => 22,
                    'sudo_mode' => '1',
                    'sudo_group' => 'admins',
                ]);
                $results[] = [
                    'ok' => true,
                    'firewall' => $firewallName,
                    'message' => 'Backup #' . (int) ($backup['id'] ?? 0) . ' created; management rule verified; SSH repair job #' . $jobId . ' queued.',
                ];
            } else {
                $objects = ssh_access_objects_status($firewall, $source);
                $jobId = ssh_access_queue_job($agent, 'ssh_access_status');
                $results[] = [
                    'ok' => true,
                    'firewall' => $firewallName,
                    'message' => 'Object status checked; remote SSH status job #' . $jobId . ' queued.',
                    'objects' => $objects,
                ];
            }
            $success++;
        } catch (Throwable $exception) {
            $failed++;
            $results[] = [
                'ok' => false,
                'firewall' => $firewallName,
                'message' => $exception->getMessage(),
            ];
        }
    }

    $_SESSION['ssh_access_result'] = [
        'ok' => $failed === 0,
        'message' => $action === 'ensure'
            ? $success . ' firewall' . ($success === 1 ? '' : 's') . ' queued for SSH enable/repair' . ($failed ? '; ' . $failed . ' failed.' : '.')
            : 'SSH status check queued.',
        'results' => $results,
    ];
} catch (Throwable $exception) {
    $_SESSION['ssh_access_result'] = [
        'ok' => false,
        'message' => $exception->getMessage(),
        'results' => [],
    ];
}

header('Location: /ssh_access.php');
exit;
