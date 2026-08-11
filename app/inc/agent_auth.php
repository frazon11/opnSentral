<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function agent_fail(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_SLASHES);
    exit;
}

function agent_header(string $newName, string $legacyName): string
{
    $value = trim((string) ($_SERVER[$newName] ?? ''));
    if ($value !== '') {
        return $value;
    }
    return trim((string) ($_SERVER[$legacyName] ?? ''));
}

function authenticate_agent_request(int $maxBodyBytes = 262144): array
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        agent_fail(405, 'POST required.');
    }

    $agentId = agent_header('HTTP_X_OPNSENTRAL_AGENT_ID', 'HTTP_X_OPNCENTRAL_AGENT_ID');
    $timestamp = agent_header('HTTP_X_OPNSENTRAL_TIMESTAMP', 'HTTP_X_OPNCENTRAL_TIMESTAMP');
    $nonce = agent_header('HTTP_X_OPNSENTRAL_NONCE', 'HTTP_X_OPNCENTRAL_NONCE');
    $signature = strtolower(agent_header('HTTP_X_OPNSENTRAL_SIGNATURE', 'HTTP_X_OPNCENTRAL_SIGNATURE'));

    if (
        !preg_match('/^[a-f0-9-]{20,80}$/i', $agentId)
        || !ctype_digit($timestamp)
        || !preg_match('/^[a-f0-9]{24,128}$/i', $nonce)
        || !preg_match('/^[a-f0-9]{64}$/', $signature)
    ) {
        agent_fail(400, 'Invalid authentication headers.');
    }

    $now = time();
    $sentAt = (int) $timestamp;
    if (abs($now - $sentAt) > 300) {
        agent_fail(401, 'Timestamp outside allowed window.');
    }

    $body = file_get_contents('php://input');
    if ($body === false || strlen($body) > $maxBodyBytes) {
        agent_fail(413, 'Invalid or oversized payload.');
    }

    $payload = json_decode($body, true);
    if (!is_array($payload)) {
        agent_fail(400, 'Invalid JSON payload.');
    }

    $statement = db()->prepare('SELECT * FROM agents WHERE agent_id = ? AND enabled = 1');
    $statement->execute([$agentId]);
    $agent = $statement->fetch();
    if (!$agent) {
        agent_fail(401, 'Unknown or disabled agent.');
    }

    $secret = decrypt_value((string) $agent['secret_enc']);
    $canonical = $timestamp . "\n" . $nonce . "\n" . hash('sha256', $body);
    $expected = hash_hmac('sha256', $canonical, $secret);
    if (!hash_equals($expected, $signature)) {
        agent_fail(401, 'Invalid signature.');
    }

    db()->exec('DELETE FROM agent_nonces WHERE seen_at < ' . ($now - 900));
    try {
        $nonceStatement = db()->prepare(
            'INSERT INTO agent_nonces(agent_id, nonce, seen_at) VALUES(?, ?, ?)'
        );
        $nonceStatement->execute([$agentId, $nonce, $now]);
    } catch (PDOException $exception) {
        agent_fail(409, 'Nonce already used.');
    }

    return [
        'agent' => $agent,
        'payload' => $payload,
        'body' => $body,
        'now' => $now,
    ];
}
