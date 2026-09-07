<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function agent_state_ensure_schema(): void
{
    db()->exec(
        'CREATE TABLE IF NOT EXISTS agent_state (
            agent_id INTEGER PRIMARY KEY,
            firewall_id INTEGER,
            revision INTEGER NOT NULL DEFAULT 0,
            schema_version INTEGER NOT NULL DEFAULT 1,
            state_json TEXT NOT NULL DEFAULT "{}",
            hashes_json TEXT NOT NULL DEFAULT "{}",
            reported_at TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        )'
    );
    db()->exec('CREATE INDEX IF NOT EXISTS idx_agent_state_firewall ON agent_state(firewall_id)');
}

function agent_state_normalize(mixed $value): mixed
{
    if (!is_array($value)) {
        return $value;
    }

    if (array_is_list($value)) {
        return array_map('agent_state_normalize', $value);
    }

    ksort($value, SORT_STRING);
    foreach ($value as $key => $item) {
        $value[$key] = agent_state_normalize($item);
    }
    return $value;
}

function agent_state_hash(mixed $value): string
{
    return hash(
        'sha256',
        json_encode(
            agent_state_normalize($value),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        )
    );
}

function agent_state_get_by_agent(int $agentId): ?array
{
    agent_state_ensure_schema();
    $statement = db()->prepare('SELECT * FROM agent_state WHERE agent_id = ?');
    $statement->execute([$agentId]);
    $row = $statement->fetch();
    if (!is_array($row)) {
        return null;
    }

    $row['state'] = json_decode((string)$row['state_json'], true) ?: [];
    $row['hashes'] = json_decode((string)$row['hashes_json'], true) ?: [];
    return $row;
}

function agent_state_get_by_firewall(int $firewallId): ?array
{
    agent_state_ensure_schema();
    $statement = db()->prepare(
        'SELECT s.*
         FROM agent_state s
         INNER JOIN agents a ON a.id = s.agent_id
         WHERE s.firewall_id = ? AND a.enabled = 1
         ORDER BY a.last_seen_at DESC, a.id DESC
         LIMIT 1'
    );
    $statement->execute([$firewallId]);
    $row = $statement->fetch();
    if (!is_array($row)) {
        return null;
    }

    $row['state'] = json_decode((string)$row['state_json'], true) ?: [];
    $row['hashes'] = json_decode((string)$row['hashes_json'], true) ?: [];
    return $row;
}

function agent_state_merge_report(array $agent, array $payload): array
{
    agent_state_ensure_schema();

    $existing = agent_state_get_by_agent((int)$agent['id']);
    $current = is_array($existing['state'] ?? null) ? $existing['state'] : [];
    $currentRevision = (int)($existing['revision'] ?? 0);

    $sync = is_array($payload['sync'] ?? null) ? $payload['sync'] : [];
    $mode = strtolower(trim((string)($sync['mode'] ?? 'full')));
    if (!in_array($mode, ['full', 'delta', 'heartbeat'], true)) {
        $mode = 'full';
    }

    $incomingRevision = max(0, (int)($sync['revision'] ?? ($currentRevision + 1)));
    $baseRevision = max(0, (int)($sync['base_revision'] ?? $currentRevision));
    $schemaVersion = max(1, (int)($sync['schema_version'] ?? 1));

    $sections = is_array($payload['sections'] ?? null) ? $payload['sections'] : [];
    if ($sections === [] && $mode !== 'heartbeat') {
        // Backward compatibility: legacy reports become named sections while
        // transport/control fields stay out of the durable state document.
        $sections = $payload;
        foreach (['sync', 'reported_at'] as $reserved) {
            unset($sections[$reserved]);
        }
    }

    $resyncRequired = false;
    if ($mode === 'delta' && $existing !== null && $baseRevision !== $currentRevision) {
        $resyncRequired = true;
    } elseif ($mode === 'full') {
        $current = [];
    }

    $changed = [];
    if (!$resyncRequired && $mode !== 'heartbeat') {
        foreach ($sections as $name => $value) {
            $name = trim((string)$name);
            if ($name === '' || strlen($name) > 64) {
                continue;
            }
            $newHash = agent_state_hash($value);
            $oldHash = isset($current[$name]) ? agent_state_hash($current[$name]) : '';
            if (!hash_equals($oldHash, $newHash)) {
                $current[$name] = $value;
                $changed[] = $name;
            }
        }
    }

    $hashes = [];
    foreach ($current as $name => $value) {
        $hashes[(string)$name] = agent_state_hash($value);
    }
    ksort($hashes, SORT_STRING);

    $revision = $resyncRequired ? $currentRevision : max($currentRevision, $incomingRevision);
    $now = gmdate('c');
    $statement = db()->prepare(
        'INSERT INTO agent_state
            (agent_id, firewall_id, revision, schema_version, state_json, hashes_json, reported_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(agent_id) DO UPDATE SET
            firewall_id = excluded.firewall_id,
            revision = excluded.revision,
            schema_version = excluded.schema_version,
            state_json = excluded.state_json,
            hashes_json = excluded.hashes_json,
            reported_at = excluded.reported_at,
            updated_at = excluded.updated_at'
    );
    $statement->execute([
        (int)$agent['id'],
        isset($agent['firewall_id']) ? (int)$agent['firewall_id'] : null,
        $revision,
        $schemaVersion,
        json_encode($current, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
        json_encode($hashes, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
        trim((string)($payload['reported_at'] ?? '')) ?: $now,
        $now,
    ]);

    return [
        'revision' => $revision,
        'changed_sections' => $changed,
        'resync_required' => $resyncRequired,
        'hashes' => $hashes,
    ];
}
