<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/agent_deployment.php';
require_login();
require_csrf();

$action = (string) ($_POST['action'] ?? '');
$pdo = db();

if ($action === 'create_registration') {
    $firewallId = (int) ($_POST['firewall_id'] ?? 0);
    $label = trim((string) ($_POST['name'] ?? ''));
    $ttl = (int) ($_POST['ttl_minutes'] ?? 15);
    if (!in_array($ttl, [5, 10, 15, 30, 60], true)) $ttl = 15;

    if ($firewallId > 0) {
        $check = $pdo->prepare('SELECT id FROM firewalls WHERE id = ?');
        $check->execute([$firewallId]);
        if (!$check->fetchColumn()) $firewallId = 0;
    }

    if ($firewallId > 0) {
        $registration = agent_create_registration_token($firewallId, $label, $ttl);
        $_SESSION['new_agent_registration'] = [
            'token' => (string) $registration['token'],
            'expires_at' => (string) $registration['expires_at'],
            'firewall_id' => $firewallId,
            'label' => $label,
        ];
    } else {
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $createdAt = gmdate('c');
        $expiresAt = gmdate('c', time() + ($ttl * 60));
        $cleanup = $pdo->prepare('DELETE FROM agent_registration_tokens WHERE used_at IS NOT NULL OR expires_at < ?');
        $cleanup->execute([gmdate('c', time() - 86400)]);
        $statement = $pdo->prepare(
            'INSERT INTO agent_registration_tokens(
                firewall_id, token_hash, token_prefix, label, created_at, expires_at
             ) VALUES(NULL, ?, ?, ?, ?, ?)'
        );
        $statement->execute([
            hash('sha256', $token),
            substr($token, 0, 8),
            substr($label, 0, 255),
            $createdAt,
            $expiresAt,
        ]);
        $_SESSION['new_agent_registration'] = [
            'token' => $token,
            'expires_at' => $expiresAt,
            'firewall_id' => 0,
            'label' => $label,
        ];
    }
} elseif ($action === 'associate') {
    $agentId = (int) ($_POST['id'] ?? 0);
    $firewallId = (int) ($_POST['firewall_id'] ?? 0);

    $agentStatement = $pdo->prepare('SELECT id, name, last_hostname, agent_id, firewall_id FROM agents WHERE id = ?');
    $agentStatement->execute([$agentId]);
    $agent = $agentStatement->fetch();
    if (!$agent) {
        http_response_code(404);
        exit('Agent not found.');
    }

    $agentLabel = (string) ($agent['name'] ?: $agent['last_hostname'] ?: $agent['agent_id']);

    if ($firewallId === 0) {
        $pdo->prepare('UPDATE agents SET firewall_id = NULL WHERE id = ?')->execute([$agentId]);
        $_SESSION['agent_association_result'] = [
            'ok' => true,
            'message' => 'Agent ' . $agentLabel . ' is now unassigned.',
        ];
    } else {
        $firewallStatement = $pdo->prepare('SELECT id, name FROM firewalls WHERE id = ?');
        $firewallStatement->execute([$firewallId]);
        $firewall = $firewallStatement->fetch();
        if (!$firewall) {
            http_response_code(404);
            exit('Managed firewall not found.');
        }

        $conflictStatement = $pdo->prepare('SELECT id, name, last_hostname, agent_id FROM agents WHERE firewall_id = ? AND id <> ? LIMIT 1');
        $conflictStatement->execute([$firewallId, $agentId]);
        $conflict = $conflictStatement->fetch();
        if ($conflict) {
            $conflictLabel = (string) ($conflict['name'] ?: $conflict['last_hostname'] ?: $conflict['agent_id']);
            $_SESSION['agent_association_result'] = [
                'ok' => false,
                'message' => 'Firewall ' . (string) $firewall['name'] . ' is already associated with agent ' . $conflictLabel . '. Unassign or delete that agent first.',
            ];
        } else {
            $pdo->prepare('UPDATE agents SET firewall_id = ? WHERE id = ?')->execute([$firewallId, $agentId]);
            $_SESSION['agent_association_result'] = [
                'ok' => true,
                'message' => 'Agent ' . $agentLabel . ' associated with firewall ' . (string) $firewall['name'] . '.',
            ];
        }
    }
} elseif ($action === 'queue_job') {
    $agentId = (int) ($_POST['id'] ?? 0);
    $jobType = (string) ($_POST['job_type'] ?? '');
    if (!in_array($jobType, ['inventory', 'system_status'], true)) {
        http_response_code(400);
        exit('Unsupported agent job.');
    }
    $check = $pdo->prepare('SELECT id FROM agents WHERE id = ? AND enabled = 1');
    $check->execute([$agentId]);
    if (!$check->fetchColumn()) {
        http_response_code(404);
        exit('Agent not found or disabled.');
    }
    $statement = $pdo->prepare(
        'INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at)
         VALUES(?, ?, ?, ?, ?)'
    );
    $statement->execute([$agentId, $jobType, '{}', 'queued', gmdate('c')]);
} elseif ($action === 'self_update') {
    require_configuration_unlocked(false);
    $id = (int) ($_POST['id'] ?? 0);
    $statement = $pdo->prepare('SELECT * FROM agents WHERE id = ?');
    $statement->execute([$id]);
    $agent = $statement->fetch();
    if (!$agent) {
        http_response_code(404);
        exit('Agent not found.');
    }
    $current = trim((string) ($agent['last_version'] ?? ''));
    if ($current === '' || version_compare($current, '0.1.2', '<')) {
        http_response_code(400);
        exit('Agent 0.1.2 or newer is required for outbound self-update.');
    }
    $jobId = agent_queue_self_update($agent);
    $_SESSION['agent_update_result'] = 'Self-update job #' . $jobId . ' queued for ' . ((string) ($agent['name'] ?: $agent['last_hostname'] ?: $agent['agent_id'])) . '.';
} elseif ($action === 'self_update_all') {
    require_configuration_unlocked(false);
    $targetVersion = agent_current_version();
    if ($targetVersion === 'unknown') {
        http_response_code(500);
        exit('Current agent version is unavailable.');
    }

    $agents = $pdo->query('SELECT * FROM agents ORDER BY id')->fetchAll();
    $queued = 0;
    $skippedCurrent = 0;
    $skippedDisabled = 0;
    $skippedOld = 0;
    $skippedPending = 0;

    $pendingStatement = $pdo->prepare(
        'SELECT COUNT(*) FROM agent_jobs
         WHERE agent_id = ? AND job_type = "self_update" AND status IN ("queued", "running")'
    );

    foreach ($agents as $agent) {
        if ((int) ($agent['enabled'] ?? 0) !== 1) {
            $skippedDisabled++;
            continue;
        }

        $current = trim((string) ($agent['last_version'] ?? ''));
        if ($current === '' || version_compare($current, '0.1.2', '<')) {
            $skippedOld++;
            continue;
        }
        if (version_compare($current, $targetVersion, '>=')) {
            $skippedCurrent++;
            continue;
        }

        $pendingStatement->execute([(int) $agent['id']]);
        if ((int) $pendingStatement->fetchColumn() > 0) {
            $skippedPending++;
            continue;
        }

        agent_queue_self_update($agent);
        $queued++;
    }

    $_SESSION['agent_update_result'] = sprintf(
        'Update all agents → target v%s: %d queued, %d already current, %d disabled, %d too old/unknown for self-update, %d already queued/running.',
        $targetVersion,
        $queued,
        $skippedCurrent,
        $skippedDisabled,
        $skippedOld,
        $skippedPending
    );
} elseif ($action === 'delete') {
    $id = (int) ($_POST['id'] ?? 0);
    $agent = $pdo->prepare('SELECT agent_id FROM agents WHERE id = ?');
    $agent->execute([$id]);
    $agentExternalId = (string) ($agent->fetchColumn() ?: '');
    $pdo->prepare('DELETE FROM agent_jobs WHERE agent_id = ?')->execute([$id]);
    if ($agentExternalId !== '') {
        $pdo->prepare('DELETE FROM agent_nonces WHERE agent_id = ?')->execute([$agentExternalId]);
    }
    $pdo->prepare('DELETE FROM agents WHERE id = ?')->execute([$id]);
} elseif ($action === 'toggle') {
    $statement = $pdo->prepare(
        'UPDATE agents SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id = ?'
    );
    $statement->execute([(int) ($_POST['id'] ?? 0)]);
}

header('Location: /agents.php');
