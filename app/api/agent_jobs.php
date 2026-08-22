<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/inc/agent_auth.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$request = authenticate_agent_request(32768);
$agent = $request['agent'];
$agentDbId = (int)$agent['id'];
$now = gmdate('c');
$pdo = db();

try {
    $pdo->beginTransaction();

    // Safety barrier: legacy broad writes must never be delivered. They can
    // change authentication or management settings and are intentionally
    // disabled while the dedicated narrow actions are used instead.
    $blocked = $pdo->prepare(
        "UPDATE agent_jobs
         SET status='failed', error=?, finished_at=?
         WHERE agent_id=? AND status IN ('queued','running')
           AND job_type IN ('set_access_user','set_administration_settings','set_general_settings','set_firewall_advanced_settings')"
    );
    $blocked->execute([
        'Blocked by opnSentral safety policy. Use a dedicated narrow action instead.',
        $now,
        $agentDbId,
    ]);

    $requeue = $pdo->prepare(
        'UPDATE agent_jobs
         SET status = ?, picked_at = NULL
         WHERE agent_id = ? AND status = ? AND picked_at < ?'
    );
    $requeue->execute(['queued', $agentDbId, 'running', gmdate('c', time() - 300)]);

    // If several self-update clicks accumulated while an agent was stale,
    // only the newest queued update is meaningful. Mark older queued copies
    // failed before selecting work so a recovered agent cannot restart through
    // several obsolete update jobs in sequence.
    $latestSelfUpdate = $pdo->prepare(
        "SELECT MAX(id) FROM agent_jobs
         WHERE agent_id = ? AND job_type = 'self_update' AND status = 'queued'"
    );
    $latestSelfUpdate->execute([$agentDbId]);
    $latestSelfUpdateId = (int)($latestSelfUpdate->fetchColumn() ?: 0);
    if ($latestSelfUpdateId > 0) {
        $supersede = $pdo->prepare(
            "UPDATE agent_jobs
             SET status='failed', error=?, finished_at=?
             WHERE agent_id=? AND job_type='self_update' AND status='queued' AND id<>?"
        );
        $supersede->execute([
            'Superseded by newer queued self-update job #'.$latestSelfUpdateId.'.',
            $now,
            $agentDbId,
            $latestSelfUpdateId,
        ]);
    }

    $statement = $pdo->prepare(
        'SELECT id, job_type, payload_json, created_at
         FROM agent_jobs
         WHERE agent_id = ? AND status = ?
         ORDER BY id
         LIMIT 1'
    );
    $statement->execute([$agentDbId, 'queued']);
    $job = $statement->fetch();

    if (!$job) {
        $pdo->commit();
        echo json_encode(['ok' => true, 'job' => null], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $claim = $pdo->prepare(
        'UPDATE agent_jobs
         SET status = ?, picked_at = ?
         WHERE id = ? AND status = ?'
    );
    $claim->execute(['running', $now, (int)$job['id'], 'queued']);

    if ($claim->rowCount() !== 1) {
        $pdo->rollBack();
        echo json_encode(['ok' => true, 'job' => null], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $pdo->commit();

    $payload = json_decode((string)$job['payload_json'], true);
    if (!is_array($payload)) $payload = [];

    echo json_encode([
        'ok' => true,
        'job' => [
            'id' => (int)$job['id'],
            'type' => (string)$job['job_type'],
            'payload' => $payload,
            'created_at' => (string)$job['created_at'],
        ],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    agent_fail(500, 'Could not fetch agent job.');
}
