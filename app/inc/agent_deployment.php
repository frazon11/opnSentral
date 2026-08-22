<?php

declare(strict_types=1);

function agent_current_version(): string
{
    $path = __DIR__ . '/../agent/opnsentral-agent';
    $content = is_file($path) ? (string) file_get_contents($path) : '';
    if (preg_match("/const AGENT_VERSION = '([^']+)'/", $content, $match)) {
        return (string) $match[1];
    }
    return 'unknown';
}

function agent_current_sha256(): string
{
    $path = __DIR__ . '/../agent/opnsentral-agent';
    $hash = is_file($path) ? hash_file('sha256', $path) : false;
    if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/', $hash)) {
        throw new RuntimeException('Could not calculate the current agent SHA-256.');
    }
    return $hash;
}

function agent_public_base_url(): string
{
    $forwardedProto = trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0] ?? '');
    $scheme = $forwardedProto !== ''
        ? strtolower($forwardedProto)
        : ((((string) ($_SERVER['HTTPS'] ?? '')) !== '' && ($_SERVER['HTTPS'] ?? 'off') !== 'off') ? 'https' : 'http');
    $forwardedHost = trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? ''))[0] ?? '');
    $host = $forwardedHost !== '' ? $forwardedHost : trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
    return $host !== '' ? $scheme . '://' . $host : '';
}

function agent_sqlite_busy(Throwable $exception): bool
{
    return $exception instanceof PDOException
        && str_contains(strtolower($exception->getMessage()), 'database is locked');
}

function agent_execute_with_retry(PDOStatement $statement, array $params, int $attempts = 5): void
{
    $attempts = max(1, $attempts);
    for ($attempt = 1; $attempt <= $attempts; $attempt++) {
        try {
            $statement->execute($params);
            return;
        } catch (Throwable $exception) {
            if (!agent_sqlite_busy($exception) || $attempt === $attempts) {
                throw $exception;
            }
            usleep(150000 * $attempt);
        }
    }
}

function agent_create_registration_token(int $firewallId, string $label = '', int $ttlMinutes = 15): array
{
    if ($firewallId <= 0) throw new RuntimeException('A managed firewall is required for agent bootstrap.');
    if (!in_array($ttlMinutes, [5, 10, 15, 30, 60], true)) $ttlMinutes = 15;

    $pdo = db();
    $check = $pdo->prepare('SELECT id,name FROM firewalls WHERE id = ?');
    $check->execute([$firewallId]);
    $firewall = $check->fetch();
    if (!$firewall) throw new RuntimeException('Firewall not found.');

    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $createdAt = gmdate('c');
    $expiresAt = gmdate('c', time() + ($ttlMinutes * 60));

    $cleanup = $pdo->prepare(
        'DELETE FROM agent_registration_tokens WHERE used_at IS NOT NULL OR expires_at < ?'
    );
    $cleanup->execute([gmdate('c', time() - 86400)]);

    $statement = $pdo->prepare(
        'INSERT INTO agent_registration_tokens(
            firewall_id, token_hash, token_prefix, label, created_at, expires_at
         ) VALUES(?, ?, ?, ?, ?, ?)'
    );
    $statement->execute([
        $firewallId,
        hash('sha256', $token),
        substr($token, 0, 8),
        substr(trim($label), 0, 255),
        $createdAt,
        $expiresAt,
    ]);

    return [
        'token' => $token,
        'expires_at' => $expiresAt,
        'firewall_name' => (string) $firewall['name'],
    ];
}

function agent_queue_self_update(array $agent): int
{
    if ((int) ($agent['enabled'] ?? 0) !== 1) {
        throw new RuntimeException('Agent is disabled.');
    }

    $lastSeen = !empty($agent['last_seen_at']) ? (strtotime((string) $agent['last_seen_at']) ?: 0) : 0;
    if ($lastSeen <= 0 || (time() - $lastSeen) >= 300) {
        throw new RuntimeException('Agent is stale/offline. Self-update cannot be queued until it is reporting again.');
    }

    $pdo = db();
    $pending = $pdo->prepare(
        'SELECT COUNT(*) FROM agent_jobs
         WHERE agent_id = ? AND job_type = ? AND status IN (?, ?)'
    );
    $pending->execute([(int) $agent['id'], 'self_update', 'queued', 'running']);
    if ((int) $pending->fetchColumn() > 0) {
        throw new RuntimeException('A self-update job is already queued or running for this agent.');
    }

    $payload = json_encode([
        'sha256' => agent_current_sha256(),
        'target_version' => agent_current_version(),
    ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $statement = $pdo->prepare(
        'INSERT INTO agent_jobs(agent_id, job_type, payload_json, status, created_at)
         VALUES(?, ?, ?, ?, ?)'
    );
    agent_execute_with_retry($statement, [
        (int) $agent['id'],
        'self_update',
        $payload,
        'queued',
        gmdate('c'),
    ]);
    return (int) $pdo->lastInsertId();
}
