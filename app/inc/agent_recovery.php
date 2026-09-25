<?php

declare(strict_types=1);

require_once __DIR__ . '/opnsense.php';

const AGENT_RECOVERY_STALE_SECONDS = 300;
const AGENT_RECOVERY_LOOP_SECONDS = 60;

function agent_recovery_state_path(): string
{
    return DATA_DIR . '/agent-recovery-state.json';
}

function agent_recovery_state_load(): array
{
    $path = agent_recovery_state_path();
    if (!is_file($path)) return [];
    $decoded = json_decode((string) @file_get_contents($path), true);
    return is_array($decoded) ? $decoded : [];
}

function agent_recovery_state_save(array $state): void
{
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0770, true) && !is_dir(DATA_DIR)) {
        throw new RuntimeException('Could not create the data directory.');
    }
    $path = agent_recovery_state_path();
    $tmp = $path . '.tmp-' . bin2hex(random_bytes(4));
    $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    if (file_put_contents($tmp, $json, LOCK_EX) === false) {
        throw new RuntimeException('Could not write agent recovery state.');
    }
    chmod($tmp, 0660);
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('Could not replace agent recovery state.');
    }
}

function agent_recovery_last_seen(array $agent): int
{
    return !empty($agent['last_seen_at']) ? (strtotime((string) $agent['last_seen_at']) ?: 0) : 0;
}

function agent_recovery_is_fresh(array $agent): bool
{
    $lastSeen = agent_recovery_last_seen($agent);
    return $lastSeen > 0 && (time() - $lastSeen) < AGENT_RECOVERY_STALE_SECONDS;
}

function agent_recovery_backoff_seconds(int $attempts): int
{
    return match (true) {
        $attempts <= 0 => 0,
        $attempts === 1 => 300,
        $attempts === 2 => 900,
        $attempts === 3 => 3600,
        default => 21600,
    };
}

function agent_recovery_due(array $state): bool
{
    $attempts = max(0, (int) ($state['attempts'] ?? 0));
    $lastAttempt = trim((string) ($state['last_attempt'] ?? ''));
    if ($lastAttempt === '') return true;
    $timestamp = strtotime($lastAttempt);
    if ($timestamp === false) return true;
    return (time() - $timestamp) >= agent_recovery_backoff_seconds($attempts);
}

function agent_recovery_response_failed(array $response): bool
{
    $text = strtolower(json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '');
    foreach (['unknown service', 'could not find', 'not found', 'failed', 'error'] as $failure) {
        if ($text !== '' && str_contains($text, $failure)) return true;
    }
    return false;
}

function agent_recovery_firewall(PDO $pdo, array $agent): array
{
    $firewallId = (int) ($agent['firewall_id'] ?? 0);
    if ($firewallId <= 0) {
        throw new RuntimeException('The stale agent is not associated with a managed firewall.');
    }
    $statement = $pdo->prepare('SELECT * FROM firewalls WHERE id = ?');
    $statement->execute([$firewallId]);
    $firewall = $statement->fetch();
    if (!is_array($firewall)) {
        throw new RuntimeException('The associated managed firewall no longer exists.');
    }
    return $firewall;
}

function agent_recovery_request_service(PDO $pdo, array $agent, string $action = 'start'): string
{
    if (!in_array($action, ['start', 'restart'], true)) {
        throw new InvalidArgumentException('Unsupported agent recovery action.');
    }
    $firewall = agent_recovery_firewall($pdo, $agent);
    $response = opn_raw_request(
        $firewall,
        'core/service/' . $action . '/opnsentral_agent',
        'POST',
        [],
        20
    );
    if (agent_recovery_response_failed($response)) {
        throw new RuntimeException('OPNsense did not accept the opnSentral agent service ' . $action . ' request.');
    }
    return (string) ($firewall['name'] ?? ('Firewall #' . (int) $firewall['id']));
}

function agent_recovery_repair_command(string $publicBase): string
{
    $publicBase = rtrim(trim($publicBase), '/');
    if (!str_starts_with(strtolower($publicBase), 'https://')) return '';
    return 'fetch -o - ' . escapeshellarg($publicBase . '/agent/install-plugin.sh')
        . ' | sh -s -- ' . escapeshellarg($publicBase);
}
