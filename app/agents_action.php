<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/agent_deployment.php';
require_once __DIR__ . '/inc/opnsense.php';
require_login();
require_csrf();

$action = (string) ($_POST['action'] ?? '');
$pdo = db();

function agent_action_is_fresh(array $agent): bool
{
    $lastSeen = !empty($agent['last_seen_at']) ? (strtotime((string) $agent['last_seen_at']) ?: 0) : 0;
    return $lastSeen > 0 && (time() - $lastSeen) < 300;
}

function agent_action_recover_service(PDO $pdo, array $agent): string
{
    $firewallId = (int) ($agent['firewall_id'] ?? 0);
    if ($firewallId <= 0) {
        throw new RuntimeException('The stale agent is not associated with a managed firewall.');
    }

    $statement = $pdo->prepare('SELECT * FROM firewalls WHERE id = ?');
    $statement->execute([$firewallId]);
    $firewall = $statement->fetch();
    if (!$firewall) {
        throw new RuntimeException('The associated managed firewall no longer exists.');
    }

    $response = opn_raw_request(
        $firewall,
        'core/service/start/opnsentral_agent',
        'POST',
        [],
        20
    );
    $responseText = strtolower(json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '');
    foreach (['unknown service', 'could not find', 'not found', 'failed', 'error'] as $failure) {
        if ($responseText !== '' && str_contains($responseText, $failure)) {
            throw new RuntimeException('OPNsense did not accept the opnSentral agent service start request.');
        }
    }

    return (string) ($firewall['name'] ?? ('Firewall #' . $firewallId));
}

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
    try {
        $recoveredFirewall = null;
        if (!agent_action_is_fresh($agent)) {
            $recoveredFirewall = agent_action_recover_service($pdo, $agent);
            sleep(3);
            $statement->execute([$id]);
            $agent = $statement->fetch() ?: $agent;
            if (!agent_action_is_fresh($agent)) {
                throw new RuntimeException(
                    'Agent service start was requested on ' . $recoveredFirewall .
                    ', but no heartbeat arrived yet. Refresh this page in a minute. '
                    . 'If it remains stale, this older installation predates the recoverable-service registration and needs one full agent installer repair.'
                );
            }
        }
        $jobId = agent_queue_self_update($agent);
        $_SESSION['agent_update_result'] = ($recoveredFirewall !== null ? 'Recovered agent service on ' . $recoveredFirewall . '. ' : '')
            . 'Self-update job #' . $jobId . ' queued for ' . ((string) ($agent['name'] ?: $agent['last_hostname'] ?: $agent['agent_id'])) . '.';
    } catch (Throwable $exception) {
        $_SESSION['agent_update_result'] = 'Could not recover/update agent: ' . $exception->getMessage();
    }
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
    $recoveryRequested = 0;
    $queueFailed = 0;
    $queueErrors = [];

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

        if (!agent_action_is_fresh($agent)) {
            try {
                agent_action_recover_service($pdo, $agent);
                $recoveryRequested++;
            } catch (Throwable $exception) {
                $queueFailed++;
                $label = (string) ($agent['name'] ?: $agent['last_hostname'] ?: $agent['agent_id']);
                $queueErrors[] = $label . ': recovery failed: ' . $exception->getMessage();
            }
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

        try {
            agent_queue_self_update($agent);
            $queued++;
        } catch (Throwable $exception) {
            $queueFailed++;
            $label = (string) ($agent['name'] ?: $agent['last_hostname'] ?: $agent['agent_id']);
            $queueErrors[] = $label . ': ' . $exception->getMessage();
        }
    }

    $message = sprintf(
        'Update all agents → target v%s: %d queued, %d recovery requests sent, %d already current, %d disabled, %d too old/unknown for self-update, %d already queued/running, %d failures.',
        $targetVersion,
        $queued,
        $recoveryRequested,
        $skippedCurrent,
        $skippedDisabled,
        $skippedOld,
        $skippedPending,
        $queueFailed
    );
    if ($recoveryRequested > 0) {
        $message .= ' Refresh in about a minute; recovered agents can then receive updates.';
    }
    if ($queueErrors !== []) {
        $message .= ' ' . implode(' | ', array_slice($queueErrors, 0, 5));
    }
    $_SESSION['agent_update_result'] = $message;
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
