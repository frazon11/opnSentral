<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/inc/config.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function registration_fail(int $status, string $message): never
{
    http_response_code($status);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    registration_fail(405, 'POST required.');
}

$body = file_get_contents('php://input');
if ($body === false || strlen($body) > 32768) {
    registration_fail(413, 'Invalid or oversized registration payload.');
}

$payload = json_decode($body, true);
if (!is_array($payload)) {
    registration_fail(400, 'Invalid JSON payload.');
}

$token = trim((string) ($payload['token'] ?? ''));
$hostname = trim((string) ($payload['hostname'] ?? ''));
$opnsenseVersion = trim((string) ($payload['opnsense_version'] ?? ''));
$architecture = trim((string) ($payload['architecture'] ?? ''));
$agentVersion = trim((string) ($payload['agent_version'] ?? ''));

if (!preg_match('/^[A-Za-z0-9_-]{40,128}$/', $token)) {
    registration_fail(400, 'Invalid registration token.');
}
if ($hostname === '' || strlen($hostname) > 255) {
    registration_fail(400, 'A valid hostname is required.');
}

$tokenHash = hash('sha256', $token);
$now = gmdate('c');
$pdo = db();

try {
    $pdo->beginTransaction();

    $statement = $pdo->prepare(
        'SELECT * FROM agent_registration_tokens
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?'
    );
    $statement->execute([$tokenHash, $now]);
    $registration = $statement->fetch();
    if (!$registration) {
        $pdo->rollBack();
        registration_fail(401, 'Registration token is invalid, expired, or already used.');
    }

    $claim = $pdo->prepare(
        'UPDATE agent_registration_tokens SET used_at = ?
         WHERE id = ? AND used_at IS NULL'
    );
    $claim->execute([$now, (int) $registration['id']]);
    if ($claim->rowCount() !== 1) {
        $pdo->rollBack();
        registration_fail(409, 'Registration token was already claimed.');
    }

    $agentId = bin2hex(random_bytes(16));
    $secret = bin2hex(random_bytes(32));
    $firewallId = (int) ($registration['firewall_id'] ?? 0);
    $label = trim((string) ($registration['label'] ?? ''));
    $agentName = $label !== '' ? $label : $hostname;

    $insert = $pdo->prepare(
        'INSERT INTO agents(
            firewall_id, agent_id, secret_enc, name, enabled, created_at,
            last_seen_at, last_version, last_hostname, last_opnsense_version,
            last_payload
         ) VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)'
    );
    $initialPayload = json_encode([
        'hostname' => $hostname,
        'agent_version' => substr($agentVersion, 0, 64),
        'opnsense_version' => substr($opnsenseVersion, 0, 128),
        'architecture' => substr($architecture, 0, 64),
        'registered_at' => $now,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    $insert->execute([
        $firewallId > 0 ? $firewallId : null,
        $agentId,
        encrypt_value($secret),
        substr($agentName, 0, 255),
        $now,
        $now,
        substr($agentVersion, 0, 64),
        substr($hostname, 0, 255),
        substr($opnsenseVersion, 0, 128),
        $initialPayload,
    ]);

    $pdo->commit();

    echo json_encode([
        'ok' => true,
        'agent_id' => $agentId,
        'agent_secret' => $secret,
        'report_url' => '/api/agent_report.php',
        'jobs_url' => '/api/agent_jobs.php',
        'job_result_url' => '/api/agent_job_result.php',
        'poll_interval' => 60,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    registration_fail(500, 'Registration failed.');
}
