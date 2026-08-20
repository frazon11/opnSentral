<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/opnsense.php';
require_once __DIR__ . '/inc/backups.php';
require_once __DIR__ . '/inc/system_administration_matrix.php';
require_login();
require_csrf();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('POST required.');
    }

    $changes = json_decode((string) ($_POST['changes'] ?? ''), true);
    if (!is_array($changes) || $changes === []) {
        throw new RuntimeException('No Administration changes supplied.');
    }
    if (count($changes) > 500) {
        throw new RuntimeException('Too many changes in one deployment.');
    }

    $definitions = administration_matrix_settings();
    $byFirewall = [];
    foreach ($changes as $change) {
        if (!is_array($change)) continue;
        $firewallId = (int) ($change['firewall_id'] ?? 0);
        $setting = trim((string) ($change['setting'] ?? ''));
        $enabled = filter_var($change['enabled'] ?? false, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        if ($firewallId <= 0 || !isset($definitions[$setting]) || $enabled === null) {
            throw new RuntimeException('Invalid Administration change payload.');
        }
        $byFirewall[$firewallId][$setting] = $enabled;
    }

    if ($byFirewall === []) {
        throw new RuntimeException('No valid Administration changes supplied.');
    }

    $pdo = db();
    $jobs = [];
    $failures = [];

    foreach ($byFirewall as $firewallId => $settings) {
        $firewallName = 'Firewall #' . $firewallId;
        try {
            $firewall = firewall_by_id((int) $firewallId);
            $firewallName = (string) $firewall['name'];

            $agentStatement = $pdo->prepare(
                'SELECT * FROM agents
                 WHERE firewall_id = ? AND enabled = 1
                 ORDER BY id DESC LIMIT 1'
            );
            $agentStatement->execute([(int) $firewallId]);
            $agent = $agentStatement->fetch();
            if (!$agent) {
                throw new RuntimeException('No enabled opnSentral agent is associated with this firewall.');
            }

            $agentVersion = trim((string) ($agent['last_version'] ?? ''));
            if ($agentVersion === '' || version_compare($agentVersion, '0.1.7', '<')) {
                throw new RuntimeException('Agent 0.1.7 or newer is required for Administration writes. Update the agent first.');
            }

            backup_before_change($firewall, 'system-administration-fleet');

            $payload = json_encode(
                ['settings' => $settings],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
            );
            $statement = $pdo->prepare(
                'INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at)
                 VALUES(?, ?, ?, ?, ?)'
            );
            $statement->execute([
                (int) $agent['id'],
                'set_administration_settings',
                $payload,
                'queued',
                gmdate('c'),
            ]);

            $jobs[] = [
                'job_id' => (int) $pdo->lastInsertId(),
                'firewall_id' => (int) $firewallId,
                'firewall_name' => $firewallName,
                'settings' => array_keys($settings),
            ];
        } catch (Throwable $exception) {
            $failures[] = [
                'firewall_id' => (int) $firewallId,
                'firewall_name' => $firewallName,
                'error' => $exception->getMessage(),
            ];
        }
    }

    echo json_encode([
        'ok' => true,
        'jobs' => $jobs,
        'failures' => $failures,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => $exception->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
