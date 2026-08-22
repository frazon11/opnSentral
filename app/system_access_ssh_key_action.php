<?php

declare(strict_types=1);

require_once __DIR__ . '/inc/config.php';
require_login();
require_csrf();
require_configuration_unlocked(false);

$firewallId = (int)($_POST['firewall_id'] ?? 0);
$userName = trim((string)($_POST['user'] ?? ''));
$key = trim(str_replace(["\r\n", "\r"], "\n", (string)($_POST['authorized_key'] ?? '')));
$result = ['error' => null, 'job_id' => null, 'firewall_name' => '', 'user' => $userName];

try {
    if ($firewallId <= 0) throw new RuntimeException('Invalid firewall target.');
    if ($userName === '' || !preg_match('/^[^\x00-\x1F\x7F]{1,128}$/u', $userName)) throw new RuntimeException('User name is invalid.');
    if ($key === '' || str_contains($key, "\n")) throw new RuntimeException('Enter exactly one OpenSSH public key.');
    if (strlen($key) > 8192 || preg_match('/[\x00-\x1F\x7F]/', $key)) throw new RuntimeException('SSH key contains invalid characters.');
    $parts = preg_split('/\s+/', $key, 3) ?: [];
    $allowed = ['ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521','sk-ssh-ed25519@openssh.com','sk-ecdsa-sha2-nistp256@openssh.com'];
    $type = (string)($parts[0] ?? '');
    $blob = (string)($parts[1] ?? '');
    if (!in_array($type, $allowed, true) || $blob === '' || base64_decode($blob, true) === false) throw new RuntimeException('Unsupported or invalid OpenSSH public key.');

    $firewallStmt = db()->prepare('SELECT * FROM firewalls WHERE id = ?');
    $firewallStmt->execute([$firewallId]);
    $firewall = $firewallStmt->fetch();
    if (!is_array($firewall)) throw new RuntimeException('Firewall not found.');
    $result['firewall_name'] = (string)$firewall['name'];

    $agentStmt = db()->prepare('SELECT * FROM agents WHERE firewall_id = ? ORDER BY id DESC LIMIT 1');
    $agentStmt->execute([$firewallId]);
    $agent = $agentStmt->fetch();
    if (!is_array($agent) || (int)($agent['enabled'] ?? 0) !== 1) throw new RuntimeException('No enabled agent is associated with this firewall.');
    $version = trim((string)($agent['last_version'] ?? ''));
    if ($version === '' || version_compare($version, '0.1.15', '<')) throw new RuntimeException('Agent 0.1.15 is required.');
    $lastSeen = !empty($agent['last_seen_at']) ? (strtotime((string)$agent['last_seen_at']) ?: 0) : 0;
    if ($lastSeen <= 0 || (time() - $lastSeen) >= 300) throw new RuntimeException('The selected firewall agent is offline or stale.');

    $pending = db()->prepare("SELECT COUNT(*) FROM agent_jobs WHERE agent_id = ? AND job_type = 'add_access_user_authorized_key' AND status IN ('queued','running')");
    $pending->execute([(int)$agent['id']]);
    if ((int)$pending->fetchColumn() > 0) throw new RuntimeException('An SSH-key job is already queued or running for this firewall.');

    $payload = json_encode(['user' => $userName, 'authorized_key' => $key], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $insert = db()->prepare('INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at) VALUES(?,?,?,?,?)');
    $insert->execute([(int)$agent['id'], 'add_access_user_authorized_key', $payload, 'queued', gmdate('c')]);
    $result['job_id'] = (int)db()->lastInsertId();
} catch (Throwable $exception) {
    $result['error'] = $exception->getMessage();
}

$_SESSION['ssh_key_deploy_result'] = $result;
header('Location: /system_access_ssh_key.php?firewall_id=' . $firewallId . '&user=' . rawurlencode($userName));
